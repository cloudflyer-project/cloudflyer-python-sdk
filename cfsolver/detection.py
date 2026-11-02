"""Cloudflare challenge detection.

Cloudflare does not always serve challenges with 403/503: managed and
Turnstile interstitials are frequently returned with 200. Detection therefore
looks at the response itself, not only at the status code.

Decision order (first match wins):

1. ``cf-mitigated: challenge`` header -> challenge (set by Cloudflare itself).
2. A Cloudflare hard block page (``error code: 1020`` and friends) -> block.
   These are not solvable, so the caller must leave the response alone.
3. Strong page markers -> challenge, for any status code.
4. User-supplied markers -> challenge, for any status code.
5. Weak markers, only on 403/429/503: a weak marker means a challenge when
   ``Server: cloudflare`` is present or a second weak marker matches, and
   "suspicious" otherwise. Suspicious responses are reported but not solved,
   so a near miss is visible instead of silently passing through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

CHALLENGE_STATUS_CODES = (403, 429, 503)

CHALLENGE = "challenge"
SUSPICIOUS = "suspicious"
BLOCK = "block"
NONE = "none"

# Interstitial pages are a few KiB. Anything larger cannot be one, and skipping
# it avoids decoding every asset that flows through the proxy.
MAX_CHALLENGE_BYTES = 256 * 1024

# Only present on a Cloudflare interstitial. A normal page that embeds a
# Turnstile widget does not contain any of these.
_STRONG_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cf_chl_opt", re.compile(r"window\._cf_chl_opt\s*=")),
    (
        "orchestrate",
        re.compile(
            r"/cdn-cgi/challenge-platform/[^\s'\"]{1,200}/orchestrate/"
            r"(?:chl_page|jsch|managed)/"
        ),
    ),
    ("challenge_form", re.compile(r"<form[^>]+id=['\"]challenge-form['\"]", re.I)),
    ("browser_verification", re.compile(r"cf-browser-verification|jschl_vc", re.I)),
)

# Also appear on ordinary pages, so they only count on a challenge status code
# and only together with a corroborating signal.
_WEAK_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("just_a_moment", re.compile(r"just a moment", re.I)),
    ("cf_turnstile", re.compile(r"cf-turnstile", re.I)),
    (
        "cf_challenge",
        re.compile(r"cf-challenge|cf_challenge_response|cloudflare-challenge", re.I),
    ),
    ("cf_chl_prog", re.compile(r"cf_chl_prog", re.I)),
    (
        "checking_browser",
        re.compile(r"cf-under-attack|cf-checking-browser|checking your browser", re.I),
    ),
    (
        "noindex_nofollow",
        re.compile(
            r"<meta[^>]+name=['\"]robots['\"][^>]+content=['\"][^'\"]*"
            r"\bnoindex\b[^'\"]*\bnofollow\b",
            re.I,
        ),
    ),
    (
        "noscript_js_cookies",
        re.compile(
            r"<noscript[^>]*>[^<]*?(?:enable|please\s+enable)[^<]*javascript"
            r"[^<]*cookies",
            re.I | re.S,
        ),
    ),
)

# Cloudflare error pages that are hard blocks: no challenge to solve.
_BLOCK_RULE = re.compile(r"error code:?\s*(10[01]\d|1020)\b", re.I)


@dataclass(frozen=True)
class Detection:
    """Outcome of inspecting one response."""

    kind: str
    reason: str = ""
    strong: bool = False
    markers: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.kind == CHALLENGE

    @property
    def is_challenge(self) -> bool:
        return self.kind == CHALLENGE

    @property
    def is_block(self) -> bool:
        return self.kind == BLOCK

    @property
    def is_suspicious(self) -> bool:
        return self.kind == SUSPICIOUS


NONE_DETECTION = Detection(NONE)


def _content_length(response: Any) -> int:
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return len(content)
    return -1


def _body_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", "ignore")
    text = getattr(response, "text", None)
    return text if isinstance(text, str) else ""


def _get_header(response: Any, name: str) -> str:
    headers = getattr(response, "headers", None)
    if not headers:
        return ""
    try:
        items = headers.items()
    except AttributeError:
        return ""
    for key, value in items:
        if isinstance(key, str) and key.lower() == name.lower():
            return value if isinstance(value, str) else ""
    return ""


def _looks_like_html(response: Any) -> bool:
    content_type = _get_header(response, "Content-Type").lower()
    if not content_type:
        return True
    return "html" in content_type or "text/" in content_type


def detect(
    response: Any,
    *,
    overrides: Iterable[str] = (),
    weak_markers: Iterable[str] = (),
) -> Detection:
    """Classify ``response`` as a challenge, a block, suspicious or neither.

    Args:
        response: Object with ``status_code``, ``headers`` and ``content``
            (or ``text``), e.g. a curl_cffi or mitmproxy response.
        overrides: Case-insensitive body substrings that force a challenge,
            for site-specific pages that carry none of the standard markers.
        weak_markers: Extra weak substrings, trusted only like the built-in
            weak rules (challenge status code plus corroboration).
    """
    if "challenge" in _get_header(response, "cf-mitigated").lower():
        return Detection(CHALLENGE, "header:cf-mitigated", strong=True)

    length = _content_length(response)
    if length == 0:
        return NONE_DETECTION

    status = getattr(response, "status_code", 0) or 0
    has_challenge_status = status in CHALLENGE_STATUS_CODES
    if not has_challenge_status:
        if length > MAX_CHALLENGE_BYTES:
            return NONE_DETECTION
        # Non-HTML bodies are only worth scanning when the caller declared a
        # marker, e.g. a JSON error page that signals a challenge.
        if not _looks_like_html(response) and not (overrides or weak_markers):
            return NONE_DETECTION

    text = _body_text(response)
    if not text:
        return NONE_DETECTION

    if has_challenge_status:
        blocked = _BLOCK_RULE.search(text)
        if blocked:
            return Detection(BLOCK, f"error:{blocked.group(1)}")

    strong_hits = tuple(name for name, rule in _STRONG_RULES if rule.search(text))
    if strong_hits:
        return Detection(CHALLENGE, strong_hits[0], strong=True, markers=strong_hits)

    lowered = text.lower()
    user_hits = tuple(m for m in overrides if m and m.lower() in lowered)
    if user_hits:
        return Detection(
            CHALLENGE, f"override:{user_hits[0]}", strong=True, markers=user_hits
        )

    if not has_challenge_status:
        return NONE_DETECTION

    hits = tuple(name for name, rule in _WEAK_RULES if rule.search(text))
    hits += tuple(m for m in weak_markers if m and m.lower() in lowered)
    if not hits:
        return NONE_DETECTION

    if len(hits) >= 2 or "cloudflare" in _get_header(response, "Server").lower():
        return Detection(CHALLENGE, hits[0], strong=False, markers=hits)

    return Detection(SUSPICIOUS, hits[0], strong=False, markers=hits)


def is_challenge_response(
    response: Any,
    *,
    overrides: Iterable[str] = (),
    weak_markers: Iterable[str] = (),
) -> bool:
    """Return True if ``response`` is a Cloudflare challenge page."""
    return detect(response, overrides=overrides, weak_markers=weak_markers).is_challenge

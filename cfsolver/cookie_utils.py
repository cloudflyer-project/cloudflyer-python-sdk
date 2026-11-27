"""Cookie selection without cross-origin or path-scope fallbacks."""

from typing import Optional
from urllib.parse import urlparse


def find_cookie_value(cookies, name: str, url: str) -> Optional[str]:
    """Select the most specific applicable cookie, retaining hostless support."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    jar = getattr(cookies, "jar", cookies)
    candidates = []
    for cookie in jar:
        if cookie.name != name or not cookie.value or cookie.is_expired():
            continue
        domain = (cookie.domain or "").lstrip(".").lower()
        if domain:
            if domain != host and not (
                cookie.domain_specified and host.endswith("." + domain)
            ):
                continue
        if cookie.secure and parsed.scheme.lower() != "https":
            continue
        cookie_path = cookie.path or "/"
        if path != cookie_path and not (
            path.startswith(cookie_path)
            and (cookie_path.endswith("/") or path[len(cookie_path) :].startswith("/"))
        ):
            continue
        candidates.append(
            (
                (bool(domain), len(cookie_path), domain == host, len(domain)),
                cookie.value,
            )
        )
    return (
        max(candidates, key=lambda candidate: candidate[0])[1] if candidates else None
    )

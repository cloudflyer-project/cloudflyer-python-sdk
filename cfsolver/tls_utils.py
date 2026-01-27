from __future__ import annotations

import re
from typing import Optional


_CIPHER_NOT_FOUND_RE = re.compile(r"Cipher\s+0x([0-9a-fA-F]+)\s+is\s+not\s+found")
_EXTENSION_TOGGLE_RE = re.compile(
    r"extension\((\d+)\)\s+can\s+not\s+be\s+toggled",
    re.IGNORECASE,
)


DEFAULT_BLOCKED_CIPHER_IDS: set[int] = {
    52394,  # 0xCCAA
}


DEFAULT_BLOCKED_EXTENSION_IDS: set[int] = {
    22,
}


def _is_grease_value(value: int) -> bool:
    """Return True if the value looks like a TLS GREASE placeholder."""
    low = value & 0xFF
    return (value >> 8) == low and (low & 0x0F) == 0x0A


def is_cipher_not_found_error(error: BaseException) -> bool:
    """Return True if the error indicates an unknown cipher by hex id."""
    return _CIPHER_NOT_FOUND_RE.search(str(error)) is not None


def is_extension_toggle_error(error: BaseException) -> bool:
    """Return True if the error indicates an unsupported TLS extension toggle."""
    return _EXTENSION_TOGGLE_RE.search(str(error)) is not None


def is_fingerprint_incompatibility_error(error: BaseException) -> bool:
    """Return True for known non-fatal TLS fingerprint incompatibilities."""
    return is_cipher_not_found_error(error) or is_extension_toggle_error(error)


def extract_missing_cipher_id(error: BaseException) -> Optional[int]:
    """Extract the missing cipher id (decimal) from an error message."""
    m = _CIPHER_NOT_FOUND_RE.search(str(error))
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def remove_cipher_from_ja3(ja3: Optional[str], cipher_id: int) -> Optional[str]:
    """Remove a cipher id from the JA3 cipher list (2nd field) if present."""
    if not ja3 or "," not in ja3:
        return ja3

    parts = ja3.split(",")
    if len(parts) != 5:
        return ja3

    ciphers = parts[1]
    if not ciphers:
        return ja3

    kept: list[str] = []
    for token in ciphers.split("-"):
        if not token:
            continue
        try:
            num = int(token)
        except ValueError:
            kept.append(token)
            continue
        if num == cipher_id:
            continue
        kept.append(str(num))

    parts[1] = "-".join(kept)
    return ",".join(parts)


def remove_extension_from_ja3(ja3: Optional[str], extension_id: int) -> Optional[str]:
    """Remove an extension id from the JA3 extension list (3rd field) if present."""
    if not ja3 or "," not in ja3:
        return ja3

    parts = ja3.split(",")
    if len(parts) != 5:
        return ja3

    exts = parts[2]
    if not exts:
        return ja3

    kept: list[str] = []
    for token in exts.split("-"):
        if not token:
            continue
        try:
            num = int(token)
        except ValueError:
            kept.append(token)
            continue
        if num == extension_id:
            continue
        kept.append(str(num))

    parts[2] = "-".join(kept)
    return ",".join(parts)


def sanitize_ja3(
    ja3: Optional[str],
    *,
    blocked_cipher_ids: Optional[set[int]] = None,
    blocked_extension_ids: Optional[set[int]] = None,
) -> Optional[str]:
    """Remove GREASE placeholders from a JA3 string.

    Some JA3 sources include GREASE cipher suites (e.g. 52394 / 0xCCAA) and
    extensions which may not be accepted by the underlying TLS stack.
    """

    if not ja3 or "," not in ja3:
        return ja3

    parts = ja3.split(",")
    if len(parts) != 5:
        return ja3

    blocked_ciphers = (
        DEFAULT_BLOCKED_CIPHER_IDS if blocked_cipher_ids is None else blocked_cipher_ids
    )
    blocked_exts = (
        DEFAULT_BLOCKED_EXTENSION_IDS
        if blocked_extension_ids is None
        else blocked_extension_ids
    )

    def _filter_list(
        text: str,
        *,
        drop_blocked: bool = False,
        blocked: Optional[set[int]] = None,
    ) -> str:
        if not text:
            return text

        kept: list[str] = []
        for token in text.split("-"):
            if not token:
                continue
            try:
                num = int(token)
            except ValueError:
                kept.append(token)
                continue
            if _is_grease_value(num):
                continue
            if drop_blocked and blocked is not None and num in blocked:
                continue
            kept.append(str(num))
        return "-".join(kept)

    version = parts[0]
    ciphers = _filter_list(parts[1], drop_blocked=True, blocked=blocked_ciphers)
    extensions = _filter_list(parts[2], drop_blocked=True, blocked=blocked_exts)
    curves = _filter_list(parts[3])
    point_formats = _filter_list(parts[4])
    return ",".join([version, ciphers, extensions, curves, point_formats])

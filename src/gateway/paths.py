"""Path normalization and prefix matching.

The allowlist check, the route match and the forwarded URL must all agree on what path was
requested, or a tenant could slip past the allowlist with a path the gateway reads one way and
the upstream reads another. So the raw path is decoded exactly once, anything ambiguous is
rejected (not "fixed"), and the one resulting string is used everywhere.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from gateway.errors import GatewayError

MAX_PATH_LENGTH = 2048

# Encoded characters that change how a path is split or decoded:
# `.` (%2e) and `/` (%2f) and `\` (%5c) can hide traversal, `%` (%25) enables double-decoding,
# NUL (%00) truncates strings in some upstreams.
_FORBIDDEN_ENCODINGS = re.compile(r"%(?:2e|2f|5c|25|00)", re.IGNORECASE)


class InvalidPath(GatewayError):
    def __init__(self, reason: str) -> None:
        super().__init__(400, "invalid_path", f"Request path rejected: {reason}.")


def normalize_path(raw_path: bytes) -> str:
    """Decode a raw request path once and reject anything ambiguous.

    `raw_path` is the path exactly as received on the wire (no query string).
    Returns the decoded path, e.g. b"/orders/caf%C3%A9" -> "/orders/café".
    """
    raw_path = raw_path.split(b"?", 1)[0]
    try:
        text = raw_path.decode("ascii")
    except UnicodeDecodeError:
        raise InvalidPath("non-ASCII bytes must be percent-encoded") from None
    if not text.startswith("/"):
        raise InvalidPath("must start with '/'")
    if len(text) > MAX_PATH_LENGTH:
        raise InvalidPath(f"longer than {MAX_PATH_LENGTH} characters")
    if _FORBIDDEN_ENCODINGS.search(text):
        raise InvalidPath("encoded '.', '/', '\\', '%' or NUL is not allowed")

    try:
        path = unquote(text, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise InvalidPath("percent-encoding is not valid UTF-8") from None

    if "%" in path:
        raise InvalidPath("malformed percent-encoding")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise InvalidPath("control characters are not allowed")
    if "\\" in path:
        raise InvalidPath("backslashes are not allowed")
    if "//" in path:
        raise InvalidPath("empty path segments ('//') are not allowed")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise InvalidPath("'.' and '..' segments are not allowed")
    return path


def normalize_prefix(prefix: str) -> str:
    """Validate a configured prefix (route or allowlist) and strip any trailing slash."""
    try:
        normalized = normalize_path(prefix.encode("utf-8", errors="strict"))
    except InvalidPath as err:
        raise ValueError(f"prefix {prefix!r}: {err.message}") from None
    if normalized != prefix:
        raise ValueError(f"prefix {prefix!r} must be a plain, already-decoded path")
    return normalized.rstrip("/") or "/"


def has_prefix(path: str, prefix: str) -> bool:
    """Segment-boundary prefix match: `/orders` matches `/orders` and `/orders/42`, not `/ordersX`.

    Both arguments must already be normalized (see `normalize_path`/`normalize_prefix`).
    """
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")

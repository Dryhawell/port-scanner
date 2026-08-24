"""Passive banner capture for open TCP ports.

Only data the server sends first is read. This module does not send HTTP,
SMTP, or other application probes. Many services (HTTP, TLS) send nothing
until the client speaks, so a missing banner is normal.
"""

from __future__ import annotations

import select
import socket

from scanner.constants import (
    DEFAULT_BANNER_TIMEOUT,
    MAX_BANNER_BYTES,
    MAX_BANNER_CHARS,
)


def grab_banner(sock: socket.socket, timeout: float) -> str | None:
    """Read a short banner if the peer sends data within the wait window."""
    wait = min(timeout, DEFAULT_BANNER_TIMEOUT)
    readable, _writable, _errors = select.select([sock], [], [], wait)
    if not readable:
        return None
    try:
        raw = sock.recv(MAX_BANNER_BYTES)
    except OSError:
        return None
    return sanitize_banner(raw)


def sanitize_banner(raw: bytes) -> str | None:
    """Decode and trim banner bytes into a single printable line."""
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = " ".join(part.strip() for part in text.split("\n") if part.strip())
    text = "".join(char if char.isprintable() else " " for char in text)
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > MAX_BANNER_CHARS:
        return text[:MAX_BANNER_CHARS].rstrip() + "..."
    return text

"""Map well-known port numbers to service names.

A name from the local services table (IANA / OS) is a hint, not proof that
that application is actually running on the open port.
"""

from __future__ import annotations

import socket

from scanner.constants import PROTOCOL_TCP


def lookup_service(port: int, protocol: str = PROTOCOL_TCP) -> str | None:
    """Return the usual service name for a port, or None if unknown.

    Uses socket.getservbyport(), which reads the operating system's service
    database (for example C:\\Windows\\System32\\drivers\\etc\\services).
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return None

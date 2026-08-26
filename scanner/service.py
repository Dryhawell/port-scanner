"""Map well-known port numbers to service names.

A name from the local services table (IANA / OS) is a hint, not proof that
that application is actually running on the open port. A small fallback map
covers common ports that some OS tables omit (Redis, MongoDB, PostgreSQL, …).
"""

from __future__ import annotations

import socket

from scanner.constants import PROTOCOL_TCP

# Used only when getservbyport raises. Conventional names, not a vuln list.
_FALLBACK_SERVICES: dict[tuple[int, str], str] = {
    (1883, "tcp"): "mqtt",
    (2375, "tcp"): "docker",
    (3389, "tcp"): "ms-wbt-server",
    (5432, "tcp"): "postgresql",
    (5672, "tcp"): "amqp",
    (5900, "tcp"): "vnc",
    (5985, "tcp"): "wsman",
    (6379, "tcp"): "redis",
    (6443, "tcp"): "kubernetes-api",
    (8080, "tcp"): "http-alt",
    (8443, "tcp"): "https-alt",
    (9200, "tcp"): "elasticsearch",
    (11211, "tcp"): "memcached",
    (27017, "tcp"): "mongodb",
    (1900, "udp"): "ssdp",
    (5353, "udp"): "mdns",
}


def lookup_service(port: int, protocol: str = PROTOCOL_TCP) -> str | None:
    """Return the usual service name for a port, or None if unknown.

    Tries socket.getservbyport() first (the OS services database, for example
    C:\\Windows\\System32\\drivers\\etc\\services). If that table has no row,
    uses a small built-in fallback. A table name always wins.
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return _FALLBACK_SERVICES.get((port, protocol))

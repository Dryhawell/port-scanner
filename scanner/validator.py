"""Validate user-supplied scan targets, ports, and related values.

This module does not open sockets and does not start a scan. It only answers:
"Can we even try to scan this input?"
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final

from scanner.constants import MAX_PORT, MAX_WORKERS, MIN_PORT, SCAN_PROFILES

# Four decimal groups, e.g. 127.0.0.1 or 999.1.1.1 (shape only, not validity).
_IPV4_SHAPE: Final[re.Pattern[str]] = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# One DNS label: starts and ends with alphanumeric; hyphen allowed in between.
_HOSTNAME_LABEL: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

_MAX_HOSTNAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63


class ValidationError(ValueError):
    """Raised when user input cannot be used for a scan."""


def validate_target(target: str) -> str:
    """Return a stripped IPv4 address or hostname if the target is usable.

    A value that *looks* like IPv4 (four dotted numbers) is validated only as
    IPv4, so 999.1.1.1 is rejected instead of being treated as a hostname.
    Hostname checks are syntactic; DNS resolution happens later, during scan.
    """
    if not isinstance(target, str):
        raise ValidationError("Invalid target.")

    cleaned = target.strip()
    if not cleaned:
        raise ValidationError("Invalid target.")

    if "://" in cleaned or "/" in cleaned or " " in cleaned:
        raise ValidationError("Invalid target.")

    if ":" in cleaned:
        raise ValidationError("IPv6 is not supported yet.")

    if _IPV4_SHAPE.fullmatch(cleaned):
        return _validate_ipv4(cleaned)

    return _validate_hostname(cleaned)


def validate_port(port: int | str) -> int:
    """Return a port number in the inclusive range 1-65535."""
    parsed = _parse_port_number(port)
    if parsed < MIN_PORT or parsed > MAX_PORT:
        raise ValidationError("Port must be between 1 and 65535.")
    return parsed


def validate_port_range(start: int | str, end: int | str) -> tuple[int, int]:
    """Return (start, end) if both ports are valid and start <= end."""
    start_port = validate_port(start)
    end_port = validate_port(end)
    if start_port > end_port:
        raise ValidationError("Invalid port range.")
    return start_port, end_port


def parse_port_range(value: str) -> tuple[int, int]:
    """Parse a single port or a range.

    Examples:
        "80"      -> (80, 80)
        "1-1000"  -> (1, 1000)
    """
    if not isinstance(value, str):
        raise ValidationError("Invalid port range.")

    cleaned = value.strip()
    if not cleaned:
        raise ValidationError("Invalid port range.")

    if "-" in cleaned:
        parts = cleaned.split("-")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValidationError("Invalid port range.")
        return validate_port_range(parts[0], parts[1])

    port = validate_port(cleaned)
    return port, port


def parse_ports(value: str) -> list[int]:
    """Parse ports as a single value, a range, or a comma-separated mix.

    Examples:
        "80"           -> [80]
        "1-1000"       -> [1, 2, ..., 1000]
        "22,80,443"    -> [22, 80, 443]
        "22,80-82,443" -> [22, 80, 81, 82, 443]
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Invalid port range.")

    ports: list[int] = []
    for chunk in value.split(","):
        start, end = parse_port_range(chunk)
        ports.extend(range(start, end + 1))
    return sorted(set(ports))


def resolve_scan_profile(name: str) -> list[int]:
    """Return the port list for a named profile (quick or common)."""
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("Unknown scan profile. Use quick or common.")
    key = name.strip().lower()
    profile = SCAN_PROFILES.get(key)
    if profile is None:
        raise ValidationError("Unknown scan profile. Use quick or common.")
    return list(profile)


def validate_timeout(timeout: float | int | str) -> float:
    """Return a positive timeout in seconds."""
    if isinstance(timeout, bool) or timeout is None:
        raise ValidationError("Timeout must be a positive number.")

    if isinstance(timeout, str):
        cleaned = timeout.strip()
        try:
            value = float(cleaned)
        except ValueError as exc:
            raise ValidationError("Timeout must be a positive number.") from exc
    elif isinstance(timeout, (int, float)):
        value = float(timeout)
    else:
        raise ValidationError("Timeout must be a positive number.")

    if value != value or value in (float("inf"), float("-inf")) or value <= 0:
        raise ValidationError("Timeout must be a positive number.")

    return value


def validate_threads(workers: int | str) -> int:
    """Return a thread count in the inclusive range 1-MAX_WORKERS."""
    if isinstance(workers, bool) or workers is None:
        raise ValidationError(f"Thread count must be between 1 and {MAX_WORKERS}.")

    if isinstance(workers, str):
        cleaned = workers.strip()
        if not cleaned.isdigit():
            raise ValidationError(f"Thread count must be between 1 and {MAX_WORKERS}.")
        parsed = int(cleaned)
    elif isinstance(workers, int):
        parsed = workers
    else:
        raise ValidationError(f"Thread count must be between 1 and {MAX_WORKERS}.")

    if parsed < 1 or parsed > MAX_WORKERS:
        raise ValidationError(f"Thread count must be between 1 and {MAX_WORKERS}.")
    return parsed


def _validate_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValidationError("Invalid IP address.") from exc
    return str(address)


def _validate_hostname(value: str) -> str:
    hostname = value.rstrip(".")
    if not hostname or len(hostname) > _MAX_HOSTNAME_LENGTH:
        raise ValidationError("Invalid hostname.")

    labels = hostname.split(".")
    if any(not label or len(label) > _MAX_LABEL_LENGTH for label in labels):
        raise ValidationError("Invalid hostname.")
    if any(_HOSTNAME_LABEL.fullmatch(label) is None for label in labels):
        raise ValidationError("Invalid hostname.")

    return hostname


def _parse_port_number(port: int | str) -> int:
    if isinstance(port, bool) or port is None:
        raise ValidationError("Port must be between 1 and 65535.")

    if isinstance(port, str):
        cleaned = port.strip()
        if not cleaned.isdigit():
            raise ValidationError("Port must be between 1 and 65535.")
        return int(cleaned)

    if isinstance(port, float):
        if not port.is_integer():
            raise ValidationError("Port must be between 1 and 65535.")
        return int(port)

    if isinstance(port, int):
        return port

    raise ValidationError("Port must be between 1 and 65535.")

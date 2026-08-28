"""Validate user-supplied scan targets, ports, and related values.

This module does not open sockets and does not start a scan. It only answers:
"Can we even try to scan this input?"
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from scanner.constants import (
    ABSOLUTE_MAX_PORTS,
    MAX_DISCOVERY_HOSTS,
    MAX_INTERVAL,
    MAX_PORT,
    MAX_RUNS,
    MAX_TARGET_FILE_HOSTS,
    MAX_TIMEOUT,
    MAX_WORKERS,
    MIN_DISCOVERY_PREFIX,
    MIN_INTERVAL,
    MIN_PORT,
    MIN_TIMEOUT,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    SCAN_PROFILES,
    UDP_SCAN_PROFILES,
)

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
    """Return a stripped IPv4/IPv6 address or hostname if the target is usable.

    A value that *looks* like IPv4 (four dotted numbers) is validated only as
    IPv4, so 999.1.1.1 is rejected instead of being treated as a hostname.
    Values with a colon are treated as IPv6 (including bracketed [::1]).
    Hostname checks are syntactic; DNS resolution happens later, during scan.
    """
    if not isinstance(target, str):
        raise ValidationError("Invalid target.")

    cleaned = target.strip()
    if not cleaned:
        raise ValidationError("Invalid target.")

    if "://" in cleaned or "/" in cleaned or " " in cleaned:
        raise ValidationError("Invalid target.")

    cleaned = _unwrap_ipv6_brackets(cleaned)

    if _IPV4_SHAPE.fullmatch(cleaned):
        return _validate_ipv4(cleaned)

    if ":" in cleaned:
        return _validate_ipv6(cleaned)

    return _validate_hostname(cleaned)


def parse_discovery_targets(value: str) -> tuple[str, list[str]]:
    """Return (spec, hosts) for TCP ping discovery.

    A single IPv4/IPv6/hostname is one host. An IPv4 CIDR such as
    192.168.1.0/24 expands to its usable hosts. Networks larger than /24
    are rejected. Port scans still use validate_target() and do not accept CIDR.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Invalid target.")
    cleaned = value.strip()
    if "://" in cleaned or " " in cleaned:
        raise ValidationError("Invalid target.")
    if "/" in cleaned:
        network, hosts = _expand_ipv4_network(cleaned)
        return str(network), hosts
    single = validate_target(cleaned)
    return single, [single]


def parse_target_file(path: str | Path, *, discover: bool = False) -> list[str]:
    """Return unique hosts from a UTF-8 list file (comments and blanks skipped).

    Each line is one --target value. With discover=True a line may be an IPv4
    CIDR. The cap matches discovery (256). This is a lab inventory, not a
    parallel sweep of the internet.
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except FileNotFoundError as extra:
        raise ValidationError(f"Target file not found: {file_path}") from extra
    except OSError as extra:
        raise ValidationError(f"Could not read target file: {extra}") from extra
    except UnicodeDecodeError as extra:
        raise ValidationError("Target file must be UTF-8 text.") from extra

    lines: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            stripped = stripped.split("#", 1)[0].strip()
        if not stripped:
            continue
        try:
            if discover:
                spec, _hosts = parse_discovery_targets(stripped)
                lines.append(spec)
            else:
                lines.append(validate_target(stripped))
        except ValidationError as extra:
            raise ValidationError(f"Target file line {lineno}: {extra}") from extra

    unique = list(dict.fromkeys(lines))
    if not unique:
        raise ValidationError("Target file has no hosts.")
    if len(unique) > MAX_TARGET_FILE_HOSTS:
        raise ValidationError(
            f"Target file has at most {MAX_TARGET_FILE_HOSTS} hosts."
        )
    return unique


def _expand_ipv4_network(value: str) -> tuple[ipaddress.IPv4Network, list[str]]:
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ipaddress.NetmaskValueError as exc:
        raise ValidationError("Invalid IP network.") from exc
    except ipaddress.AddressValueError as exc:
        if ":" in value:
            raise ValidationError("IPv6 networks are not supported.") from exc
        raise ValidationError("Invalid IP network.") from exc

    if network.prefixlen < MIN_DISCOVERY_PREFIX or network.num_addresses > MAX_DISCOVERY_HOSTS:
        raise ValidationError(
            f"Network too large. Use /{MIN_DISCOVERY_PREFIX} or smaller "
            f"(max {MAX_DISCOVERY_HOSTS} addresses)."
        )
    if network.prefixlen == 32:
        hosts = [str(network.network_address)]
    else:
        hosts = [str(item) for item in network.hosts()]
    if not hosts:
        raise ValidationError("Invalid IP network.")
    return network, hosts


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


def exclude_ports(ports: Sequence[int], spec: str | None) -> list[int]:
    """Return ports with --exclude values removed. Keep the original order.

    spec uses the same syntax as parse_ports (80, 22,80,443, or 1-1023).
    A blank spec is a no-op. Ports listed in spec but absent from ports are
    ignored. An empty remainder is an error: there is nothing left to scan.
    """
    remaining = list(ports)
    if spec is None or not str(spec).strip():
        return remaining
    blocked = set(parse_ports(spec))
    remaining = [port for port in remaining if port not in blocked]
    if not remaining:
        raise ValidationError("No ports left after exclude.")
    return remaining


def validate_max_ports(value: int | str) -> int:
    """Return how many ports one scan may probe (1–ABSOLUTE_MAX_PORTS)."""
    if isinstance(value, bool) or value is None:
        raise ValidationError(
            f"Max ports must be between 1 and {ABSOLUTE_MAX_PORTS}."
        )
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned.isdigit():
            raise ValidationError(
                f"Max ports must be between 1 and {ABSOLUTE_MAX_PORTS}."
            )
        parsed = int(cleaned)
    elif isinstance(value, int):
        parsed = value
    else:
        raise ValidationError(
            f"Max ports must be between 1 and {ABSOLUTE_MAX_PORTS}."
        )
    if parsed < 1 or parsed > ABSOLUTE_MAX_PORTS:
        raise ValidationError(
            f"Max ports must be between 1 and {ABSOLUTE_MAX_PORTS}."
        )
    return parsed


def limit_port_count(ports: Sequence[int], max_ports: int) -> list[int]:
    """Return ports unchanged, or reject if the list exceeds max_ports."""
    remaining = list(ports)
    if len(remaining) > max_ports:
        raise ValidationError(
            f"Port list has {len(remaining)} ports; maximum is {max_ports} "
            f"(raise with --max-ports, up to {ABSOLUTE_MAX_PORTS})."
        )
    return remaining


def resolve_scan_profile(name: str, protocol: str = PROTOCOL_TCP) -> list[int]:
    """Return the port list for a named profile (quick or common)."""
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("Unknown scan profile. Use quick or common.")
    key = name.strip().lower()
    table = UDP_SCAN_PROFILES if protocol == PROTOCOL_UDP else SCAN_PROFILES
    profile = table.get(key)
    if profile is None:
        raise ValidationError("Unknown scan profile. Use quick or common.")
    return list(profile)


def validate_protocol(value: str) -> str:
    """Return tcp or udp."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Protocol must be tcp or udp.")
    cleaned = value.strip().lower()
    if cleaned not in {PROTOCOL_TCP, PROTOCOL_UDP}:
        raise ValidationError("Protocol must be tcp or udp.")
    return cleaned


def _positive_seconds(value: float | int | str, *, label: str = "Timeout") -> float:
    """Parse a finite positive duration in seconds (no min/max policy)."""
    if isinstance(value, bool) or value is None:
        raise ValidationError(f"{label} must be a positive number.")

    if isinstance(value, str):
        cleaned = value.strip()
        try:
            parsed = float(cleaned)
        except ValueError as exc:
            raise ValidationError(f"{label} must be a positive number.") from exc
    elif isinstance(value, (int, float)):
        parsed = float(value)
    else:
        raise ValidationError(f"{label} must be a positive number.")

    if parsed != parsed or parsed in (float("inf"), float("-inf")) or parsed <= 0:
        raise ValidationError(f"{label} must be a positive number.")
    return parsed


def validate_timeout(timeout: float | int | str) -> float:
    """Return a per-port connect/UDP wait in seconds (MIN_TIMEOUT–MAX_TIMEOUT)."""
    value = _positive_seconds(timeout, label="Timeout")
    if value < MIN_TIMEOUT or value > MAX_TIMEOUT:
        raise ValidationError(
            f"Timeout must be between {MIN_TIMEOUT:g} and {MAX_TIMEOUT:g} seconds."
        )
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


def validate_interval(value: float | int | str) -> float:
    """Return a wait between scheduled runs, in seconds."""
    seconds = _positive_seconds(value, label="Interval")
    if seconds < MIN_INTERVAL or seconds > MAX_INTERVAL:
        raise ValidationError(
            f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds."
        )
    return seconds


def validate_runs(value: int | str) -> int:
    """Return how many authorized scans to run, 1-MAX_RUNS."""
    if isinstance(value, bool) or value is None:
        raise ValidationError(f"Run count must be between 1 and {MAX_RUNS}.")

    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned.isdigit():
            raise ValidationError(f"Run count must be between 1 and {MAX_RUNS}.")
        parsed = int(cleaned)
    elif isinstance(value, int):
        parsed = value
    else:
        raise ValidationError(f"Run count must be between 1 and {MAX_RUNS}.")

    if parsed < 1 or parsed > MAX_RUNS:
        raise ValidationError(f"Run count must be between 1 and {MAX_RUNS}.")
    return parsed


def _unwrap_ipv6_brackets(value: str) -> str:
    """Accept RFC 3986 [::1]; reject mixed forms such as [::1]:80."""
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner or ":" not in inner:
            raise ValidationError("Invalid IP address.")
        return inner
    if "[" in value or "]" in value:
        raise ValidationError("Invalid IP address.")
    return value


def _validate_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValidationError("Invalid IP address.") from exc
    return str(address)


def _validate_ipv6(value: str) -> str:
    if "%" in value:
        raise ValidationError("IPv6 zone identifiers are not supported.")
    try:
        address = ipaddress.IPv6Address(value)
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

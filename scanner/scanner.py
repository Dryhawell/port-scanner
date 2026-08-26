"""Concurrent TCP connect scanner.

This module performs a TCP connect scan or a UDP probe per port.
It does not evade firewalls, spoof packets, or scan without authorization.
"""

from __future__ import annotations

import errno
import ipaddress
import select
import socket
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from datetime import datetime, timezone

from scanner.banner import grab_banner, parse_banner, sanitize_banner
from scanner.constants import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_TIMEOUT,
    MAX_BANNER_BYTES,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    UDP_PROBE_PAYLOAD,
)
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.service import lookup_service
from scanner.validator import (
    ValidationError,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_target,
    validate_threads,
    validate_timeout,
)
from utils.logger import get_logger

logger = get_logger()

ProgressCallback = Callable[[int, int, PortScanResult], None]


class ScannerError(Exception):
    """Raised when a scan cannot start (for example DNS failure)."""


def _errno_set(*names: str) -> frozenset[int]:
    """Collect errno constants that exist on this platform."""
    codes: set[int] = set()
    for name in names:
        value = getattr(errno, name, None)
        if isinstance(value, int):
            codes.add(value)
    return frozenset(codes)


_REFUSED_CODES = _errno_set("ECONNREFUSED", "WSAECONNREFUSED")
_RESET_CODES = _errno_set("ECONNRESET", "WSAECONNRESET")
_UDP_CLOSED_CODES = _REFUSED_CODES | _RESET_CODES
_TIMEOUT_CODES = _errno_set("ETIMEDOUT", "WSAETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH")
_IN_PROGRESS_CODES = _errno_set(
    "EINPROGRESS",
    "EWOULDBLOCK",
    "EAGAIN",
    "WSAEWOULDBLOCK",
    "WSAEINPROGRESS",
)
# Windows often returns WSAEWOULDBLOCK (10035) before the handshake finishes.


def resolve_host(target: str, *, prefer_ipv6: bool = False) -> tuple[str, int]:
    """Resolve a validated target to (ip, address family).

    IPv4 and IPv6 literals skip DNS. Hostnames use getaddrinfo. Dual-stack
    names prefer A/IPv4 unless prefer_ipv6 is True (then AAAA/IPv6 only).
    """
    cleaned = validate_target(target)
    literal_version = _literal_ip_version(cleaned)
    if literal_version == 4:
        return cleaned, socket.AF_INET
    if literal_version == 6:
        return cleaned, socket.AF_INET6

    family = socket.AF_INET6 if prefer_ipv6 else socket.AF_UNSPEC
    try:
        infos = socket.getaddrinfo(
            cleaned,
            None,
            family=family,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        kind = "IPv6" if prefer_ipv6 else "hostname"
        logger.error("Could not resolve %s: %s", kind, cleaned)
        raise ScannerError(f"Could not resolve hostname: {cleaned}") from exc

    if not infos:
        raise ScannerError(f"Could not resolve hostname: {cleaned}")

    chosen_family, ip = _pick_addrinfo(infos, prefer_ipv6=prefer_ipv6)
    return ip, chosen_family


def resolve_ipv4(target: str) -> str:
    """Resolve a validated hostname or IPv4 literal to an IPv4 address."""
    ip, family = resolve_host(target, prefer_ipv6=False)
    if family != socket.AF_INET:
        cleaned = validate_target(target)
        raise ScannerError(f"Could not resolve hostname to IPv4: {cleaned}")
    return ip


def _literal_ip_version(value: str) -> int | None:
    try:
        ipaddress.IPv4Address(value)
        return 4
    except ipaddress.AddressValueError:
        pass
    try:
        ipaddress.IPv6Address(value)
        return 6
    except ipaddress.AddressValueError:
        return None


def _pick_addrinfo(
    infos: Sequence[tuple[object, ...]],
    *,
    prefer_ipv6: bool,
) -> tuple[int, str]:
    preferred = socket.AF_INET6 if prefer_ipv6 else socket.AF_INET
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family == preferred and sockaddr:
            return int(family), str(sockaddr[0])
    family, _socktype, _proto, _canon, sockaddr = infos[0]
    return int(family), str(sockaddr[0])


def probe_tcp_port(
    host: str,
    port: int,
    timeout: float,
    family: int = socket.AF_INET,
) -> PortScanResult:
    """Try one TCP connect and map the outcome to OPEN / CLOSED / TIMEOUT.

    connect_ex returns 0 on success (the port accepted the handshake).
    Any other value is an operating-system error code, not an exception.

    The socket is non-blocking so Windows does not stack settimeout() plus
    select() into a double wait. The user timeout is enforced by select().
    response_time is the probe duration in seconds (perf_counter).
    IPv6 uses AF_INET6 and a 4-tuple address (host, port, flowinfo, scopeid).
    """
    logger.debug("Scanning port %s.", port)
    started = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        error_code = sock.connect_ex(_connect_address(host, port, family))
        if error_code in _IN_PROGRESS_CODES:
            error_code = _wait_for_connect(sock, timeout)
        state = _state_from_connect_code(error_code)
        banner = grab_banner(sock, timeout) if state is PortState.OPEN else None
        hint = parse_banner(banner)
        result = PortScanResult(
            port=port,
            state=state,
            error_code=error_code,
            response_time=time.perf_counter() - started,
            banner=banner,
            banner_kind=hint.kind,
            banner_product=hint.product,
            banner_version=hint.version,
        )
    except socket.timeout:
        result = _timed_result(port, PortState.TIMEOUT, None, started)
    except OSError as exc:
        code = exc.errno
        state = PortState.CLOSED if code in _REFUSED_CODES else PortState.TIMEOUT
        result = _timed_result(port, state, code, started)
    finally:
        sock.close()
    _log_probe_result(result)
    return result


def _connect_address(host: str, port: int, family: int) -> tuple[object, ...]:
    if family == socket.AF_INET6:
        return (host, port, 0, 0)
    return (host, port)


def probe_udp_port(
    host: str,
    port: int,
    timeout: float,
    family: int = socket.AF_INET,
) -> PortScanResult:
    """Send one UDP datagram and classify OPEN / CLOSED / TIMEOUT.

    UDP has no handshake. A reply is OPEN. ICMP port-unreachable (surfaced
    as ECONNREFUSED / WSAECONNRESET on a connected datagram socket) is
    CLOSED. Silence is TIMEOUT — nmap would call that open|filtered.
    The payload is a single null byte, not a protocol-specific probe.
    """
    logger.debug("UDP scanning port %s.", port)
    started = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        sock.connect(_connect_address(host, port, family))
        sock.send(UDP_PROBE_PAYLOAD)
        state, error_code, banner = _udp_wait(sock, timeout)
        result = PortScanResult(
            port=port,
            state=state,
            protocol=PROTOCOL_UDP,
            error_code=error_code,
            response_time=time.perf_counter() - started,
            banner=banner,
        )
    except OSError as exc:
        code = exc.errno
        state = PortState.CLOSED if code in _UDP_CLOSED_CODES else PortState.TIMEOUT
        result = _timed_result(port, state, code, started, protocol=PROTOCOL_UDP)
    finally:
        sock.close()
    _log_probe_result(result)
    return result


def _udp_wait(
    sock: socket.socket,
    timeout: float,
) -> tuple[PortState, int | None, str | None]:
    readable, _writable, errored = select.select([sock], [], [sock], timeout)
    if readable or errored:
        return _udp_recv(sock)
    return _udp_recv(sock, allow_empty=True)


def _udp_recv(
    sock: socket.socket,
    *,
    allow_empty: bool = False,
) -> tuple[PortState, int | None, str | None]:
    try:
        data = sock.recv(MAX_BANNER_BYTES)
    except OSError as exc:
        code = exc.errno
        if code in _UDP_CLOSED_CODES:
            return PortState.CLOSED, code, None
        return PortState.TIMEOUT, code, None
    if data:
        return PortState.OPEN, 0, sanitize_banner(data)
    if allow_empty:
        return PortState.TIMEOUT, None, None
    return PortState.OPEN, 0, None


def _timed_result(
    port: int,
    state: PortState,
    error_code: int | None,
    started: float,
    protocol: str = PROTOCOL_TCP,
) -> PortScanResult:
    return PortScanResult(
        port=port,
        state=state,
        protocol=protocol,
        error_code=error_code,
        response_time=time.perf_counter() - started,
    )


def _wait_for_connect(sock: socket.socket, timeout: float) -> int:
    """Wait until a non-blocking connect finishes or the timeout expires."""
    _readable, writable, _errors = select.select([], [sock], [sock], timeout)
    if not writable:
        return getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT)
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)


def _state_from_connect_code(error_code: int) -> PortState:
    if error_code == 0:
        return PortState.OPEN
    if error_code in _REFUSED_CODES:
        return PortState.CLOSED
    if error_code in _TIMEOUT_CODES:
        return PortState.TIMEOUT
    return PortState.TIMEOUT


class TcpConnectScanner:
    """Scan a port range on one IPv4 or IPv6 host using a bounded thread pool."""

    def scan(
        self,
        target: str,
        start_port: int | str | None = None,
        end_port: int | str | None = None,
        timeout: float | int | str = DEFAULT_TIMEOUT,
        max_workers: int | str = DEFAULT_MAX_WORKERS,
        on_progress: ProgressCallback | None = None,
        ports: Sequence[int] | None = None,
        prefer_ipv6: bool = False,
        protocol: str = PROTOCOL_TCP,
    ) -> ScanReport:
        """Validate input, resolve DNS, then probe ports concurrently."""
        cleaned_target = validate_target(target)
        port_list = _resolve_port_list(start_port, end_port, ports)
        timeout_seconds = validate_timeout(timeout)
        requested_workers = validate_threads(max_workers)
        scan_protocol = validate_protocol(protocol)
        resolved_ip, family = resolve_host(cleaned_target, prefer_ipv6=prefer_ipv6)
        ip_version = 6 if family == socket.AF_INET6 else 4

        port_count = len(port_list)
        workers = min(requested_workers, port_count)
        start = port_list[0]
        end = port_list[-1]
        logger.info(
            "Scan started. target=%s resolved_ip=%s ip_version=%s protocol=%s ports=%s-%s count=%s timeout=%s threads=%s",
            cleaned_target,
            resolved_ip,
            ip_version,
            scan_protocol,
            start,
            end,
            port_count,
            timeout_seconds,
            workers,
        )
        started_at = datetime.now(timezone.utc)
        started = time.perf_counter()
        results = _scan_ports_concurrently(
            resolved_ip,
            port_list,
            timeout_seconds,
            workers,
            on_progress,
            family,
            scan_protocol,
        )
        duration = time.perf_counter() - started
        results.sort(key=lambda item: item.port)

        report = ScanReport(
            target=cleaned_target,
            resolved_ip=resolved_ip,
            start_port=start,
            end_port=end,
            timeout=timeout_seconds,
            results=results,
            max_workers=workers,
            duration=duration,
            started_at=started_at,
            ip_version=ip_version,
            protocol=scan_protocol,
        )
        open_count = report.count(PortState.OPEN)
        closed_count = report.count(PortState.CLOSED)
        timeout_count = report.count(PortState.TIMEOUT)
        logger.info(
            "Scan finished. open=%s closed=%s timeout=%s duration=%.2fs",
            open_count,
            closed_count,
            timeout_count,
            duration,
        )
        if timeout_count:
            if scan_protocol == PROTOCOL_UDP:
                logger.warning(
                    "No UDP reply on %s port(s) (open|filtered, drop, or ICMP rate-limit).",
                    timeout_count,
                )
            else:
                logger.warning("Connection timeout on %s port(s).", timeout_count)
        return report


def _resolve_port_list(
    start_port: int | str | None,
    end_port: int | str | None,
    ports: Sequence[int] | None,
) -> list[int]:
    if ports is not None:
        unique = sorted({validate_port(port) for port in ports})
        if not unique:
            raise ValidationError("Invalid port range.")
        return unique
    if start_port is None or end_port is None:
        raise ValidationError("Invalid port range.")
    start, end = validate_port_range(start_port, end_port)
    return list(range(start, end + 1))


def _scan_ports_concurrently(
    host: str,
    ports: Sequence[int],
    timeout: float,
    workers: int,
    on_progress: ProgressCallback | None = None,
    family: int = socket.AF_INET,
    protocol: str = PROTOCOL_TCP,
) -> list[PortScanResult]:
    """Submit one probe per port and collect results as they finish."""
    results: list[PortScanResult] = []
    total = len(ports)
    probe_fn = probe_udp_port if protocol == PROTOCOL_UDP else probe_tcp_port
    probe = partial(probe_fn, family=family)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(probe, host, port, timeout)
            for port in ports
        ]
        for completed, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            _apply_service_hint(result)
            results.append(result)
            if on_progress is not None:
                on_progress(completed, total, result)
    return results


def _apply_service_hint(result: PortScanResult) -> None:
    """Fill the IANA/OS service name on open ports only.

    If the services table has no name, reuse the banner kind (ssh, ftp, …).
    A table name is never overwritten: a mismatch with the banner is useful.
    """
    if result.state is not PortState.OPEN:
        return
    result.service = lookup_service(result.port, result.protocol)
    if result.service is None and result.banner_kind:
        result.service = result.banner_kind


def _log_probe_result(result: PortScanResult) -> None:
    logger.debug("Port %s %s.", result.port, result.state.value)
    if result.state is PortState.TIMEOUT:
        logger.debug("Connection timeout on port %s.", result.port)

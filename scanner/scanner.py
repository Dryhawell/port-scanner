"""Concurrent TCP connect scanner.

This module performs a full TCP handshake attempt per port (connect scan).
It does not evade firewalls, spoof packets, or scan without authorization.
"""

from __future__ import annotations

import errno
import select
import socket
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from scanner.banner import grab_banner
from scanner.constants import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.service import lookup_service
from scanner.validator import (
    ValidationError,
    validate_port,
    validate_port_range,
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
_TIMEOUT_CODES = _errno_set("ETIMEDOUT", "WSAETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH")
_IN_PROGRESS_CODES = _errno_set(
    "EINPROGRESS",
    "EWOULDBLOCK",
    "EAGAIN",
    "WSAEWOULDBLOCK",
    "WSAEINPROGRESS",
)
# Windows often returns WSAEWOULDBLOCK (10035) before the handshake finishes.


def resolve_ipv4(target: str) -> str:
    """Resolve a validated hostname or IPv4 literal to an IPv4 address."""
    cleaned = validate_target(target)
    try:
        infos = socket.getaddrinfo(
            cleaned,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        logger.error("Could not resolve hostname: %s", cleaned)
        raise ScannerError(f"Could not resolve hostname: {cleaned}") from exc

    if not infos:
        raise ScannerError(f"Could not resolve hostname: {cleaned}")

    ipv4 = infos[0][4][0]
    return ipv4


def probe_tcp_port(host: str, port: int, timeout: float) -> PortScanResult:
    """Try one TCP connect and map the outcome to OPEN / CLOSED / TIMEOUT.

    connect_ex returns 0 on success (the port accepted the handshake).
    Any other value is an operating-system error code, not an exception.

    The socket is non-blocking so Windows does not stack settimeout() plus
    select() into a double wait. The user timeout is enforced by select().
    response_time is the probe duration in seconds (perf_counter).
    """
    logger.debug("Scanning port %s.", port)
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        error_code = sock.connect_ex((host, port))
        if error_code in _IN_PROGRESS_CODES:
            error_code = _wait_for_connect(sock, timeout)
        state = _state_from_connect_code(error_code)
        banner = grab_banner(sock, timeout) if state is PortState.OPEN else None
        result = PortScanResult(
            port=port,
            state=state,
            error_code=error_code,
            response_time=time.perf_counter() - started,
            banner=banner,
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


def _timed_result(
    port: int,
    state: PortState,
    error_code: int | None,
    started: float,
) -> PortScanResult:
    return PortScanResult(
        port=port,
        state=state,
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
    """Scan a port range on one IPv4 host using a bounded thread pool."""

    def scan(
        self,
        target: str,
        start_port: int | str | None = None,
        end_port: int | str | None = None,
        timeout: float | int | str = DEFAULT_TIMEOUT,
        max_workers: int | str = DEFAULT_MAX_WORKERS,
        on_progress: ProgressCallback | None = None,
        ports: Sequence[int] | None = None,
    ) -> ScanReport:
        """Validate input, resolve DNS, then probe ports concurrently."""
        cleaned_target = validate_target(target)
        port_list = _resolve_port_list(start_port, end_port, ports)
        timeout_seconds = validate_timeout(timeout)
        requested_workers = validate_threads(max_workers)
        resolved_ip = resolve_ipv4(cleaned_target)

        port_count = len(port_list)
        workers = min(requested_workers, port_count)
        start = port_list[0]
        end = port_list[-1]
        logger.info(
            "Scan started. target=%s resolved_ip=%s ports=%s-%s count=%s timeout=%s threads=%s",
            cleaned_target,
            resolved_ip,
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
) -> list[PortScanResult]:
    """Submit one probe per port and collect results as they finish."""
    results: list[PortScanResult] = []
    total = len(ports)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(probe_tcp_port, host, port, timeout)
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
    """Fill the IANA/OS service name on open ports only."""
    if result.state is PortState.OPEN:
        result.service = lookup_service(result.port, result.protocol)


def _log_probe_result(result: PortScanResult) -> None:
    logger.debug("Port %s %s.", result.port, result.state.value)
    if result.state is PortState.TIMEOUT:
        logger.debug("Connection timeout on port %s.", result.port)

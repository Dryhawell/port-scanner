"""Concurrent TCP connect scanner.

This module performs a full TCP handshake attempt per port (connect scan).
It does not evade firewalls, spoof packets, or scan without authorization.
"""

from __future__ import annotations

import errno
import select
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.banner import grab_banner
from scanner.constants import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.service import lookup_service
from scanner.validator import (
    validate_port_range,
    validate_target,
    validate_threads,
    validate_timeout,
)


class ScannerError(Exception):
    """Raised when a scan cannot start (for example DNS failure)."""


def _connection_refused_codes() -> frozenset[int]:
    codes = {errno.ECONNREFUSED}
    if hasattr(errno, "WSAECONNREFUSED"):
        codes.add(errno.WSAECONNREFUSED)
    return frozenset(codes)


def _timeout_codes() -> frozenset[int]:
    codes = {errno.ETIMEDOUT}
    for name in ("WSAETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH"):
        value = getattr(errno, name, None)
        if isinstance(value, int):
            codes.add(value)
    return frozenset(codes)


def _in_progress_codes() -> frozenset[int]:
    """connect_ex can return these before the handshake has finished.

    On Windows, settimeout() makes the socket non-blocking internally, so
    connect_ex often returns WSAEWOULDBLOCK (10035) immediately. That is not
    a final CLOSED/TIMEOUT verdict; we wait with select() and read SO_ERROR.
    """
    codes = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN}
    for name in ("WSAEWOULDBLOCK", "WSAEINPROGRESS"):
        value = getattr(errno, name, None)
        if isinstance(value, int):
            codes.add(value)
    return frozenset(codes)


_REFUSED_CODES = _connection_refused_codes()
_TIMEOUT_CODES = _timeout_codes()
_IN_PROGRESS_CODES = _in_progress_codes()


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
    started = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        error_code = sock.connect_ex((host, port))
        if error_code in _IN_PROGRESS_CODES:
            error_code = _wait_for_connect(sock, timeout)
        state = _state_from_connect_code(error_code)
        elapsed = time.perf_counter() - started
        banner = grab_banner(sock, timeout) if state is PortState.OPEN else None
        return PortScanResult(
            port=port,
            state=state,
            error_code=error_code,
            response_time=elapsed,
            banner=banner,
        )
    except socket.timeout:
        return _timed_result(port, PortState.TIMEOUT, None, started)
    except OSError as exc:
        code = exc.errno
        state = PortState.CLOSED if code in _REFUSED_CODES else PortState.TIMEOUT
        return _timed_result(port, state, code, started)
    finally:
        sock.close()


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
    """Finish a handshake that connect_ex started but did not complete."""
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
        start_port: int | str,
        end_port: int | str,
        timeout: float | int | str = DEFAULT_TIMEOUT,
        max_workers: int | str = DEFAULT_MAX_WORKERS,
    ) -> ScanReport:
        """Validate input, resolve DNS, then probe ports concurrently."""
        cleaned_target = validate_target(target)
        start, end = validate_port_range(start_port, end_port)
        timeout_seconds = validate_timeout(timeout)
        requested_workers = validate_threads(max_workers)
        resolved_ip = resolve_ipv4(cleaned_target)

        port_count = end - start + 1
        workers = min(requested_workers, port_count)
        started = time.perf_counter()
        results = _scan_ports_concurrently(
            resolved_ip,
            start,
            end,
            timeout_seconds,
            workers,
        )
        duration = time.perf_counter() - started
        results.sort(key=lambda item: item.port)
        _attach_service_names(results)

        return ScanReport(
            target=cleaned_target,
            resolved_ip=resolved_ip,
            start_port=start,
            end_port=end,
            timeout=timeout_seconds,
            results=results,
            max_workers=workers,
            duration=duration,
        )


def _scan_ports_concurrently(
    host: str,
    start: int,
    end: int,
    timeout: float,
    workers: int,
) -> list[PortScanResult]:
    """Submit one probe per port and collect results as they finish."""
    results: list[PortScanResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(probe_tcp_port, host, port, timeout)
            for port in range(start, end + 1)
        ]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def _attach_service_names(results: list[PortScanResult]) -> None:
    """Fill the IANA/OS service hint on open ports only."""
    for result in results:
        if result.state is PortState.OPEN:
            result.service = lookup_service(result.port, result.protocol)

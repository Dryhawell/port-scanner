"""TCP ping host discovery.

A host is UP if any discovery port returns OPEN or CLOSED (the stack answered).
All TIMEOUT means DOWN for this tool — the host may still be up behind a filter.
This is not ICMP ping, not ARP, and not a stealth scan.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import partial

from scanner.constants import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_TIMEOUT,
    DISCOVERY_PORTS,
)
from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState
from scanner.port import PortState
from scanner.scanner import probe_tcp_port, resolve_host
from scanner.validator import (
    parse_discovery_targets,
    validate_threads,
    validate_timeout,
)
from utils.logger import get_logger

logger = get_logger()

DiscoveryCallback = Callable[[int, int, HostDiscoveryResult], None]


def probe_host(
    ip: str,
    timeout: float,
    family: int = socket.AF_INET,
    ports: Sequence[int] = DISCOVERY_PORTS,
) -> HostDiscoveryResult:
    """TCP-ping one address. Stop at the first OPEN or CLOSED port."""
    started = time.perf_counter()
    for port in ports:
        result = probe_tcp_port(
            ip,
            port,
            timeout,
            family=family,
            with_banner=False,
        )
        if result.state in {PortState.OPEN, PortState.CLOSED}:
            return HostDiscoveryResult(
                ip=ip,
                state=HostState.UP,
                evidence=f"tcp/{port} {result.state.value}",
                response_time=time.perf_counter() - started,
            )
    return HostDiscoveryResult(
        ip=ip,
        state=HostState.DOWN,
        response_time=time.perf_counter() - started,
    )


def discover_hosts(
    target: str,
    timeout: float | int | str = DEFAULT_TIMEOUT,
    max_workers: int | str = DEFAULT_MAX_WORKERS,
    on_progress: DiscoveryCallback | None = None,
    prefer_ipv6: bool = False,
) -> DiscoveryReport:
    """Discover which addresses in a host or IPv4 CIDR answer a TCP ping."""
    spec, items = parse_discovery_targets(target)
    timeout_seconds = validate_timeout(timeout)
    requested_workers = validate_threads(max_workers)

    if "/" in spec:
        ips = items
        family = socket.AF_INET
        ip_version = 4
    else:
        resolved, family = resolve_host(items[0], prefer_ipv6=prefer_ipv6)
        ips = [resolved]
        ip_version = 6 if family == socket.AF_INET6 else 4

    workers = min(requested_workers, len(ips))
    logger.info(
        "Discovery started. spec=%s hosts=%s timeout=%s threads=%s",
        spec,
        len(ips),
        timeout_seconds,
        workers,
    )
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    ping = partial(probe_host, timeout=timeout_seconds, family=family)
    results: list[HostDiscoveryResult] = []
    total = len(ips)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(ping, ip) for ip in ips]
        for completed, future in enumerate(as_completed(futures), start=1):
            item = future.result()
            results.append(item)
            if on_progress is not None:
                on_progress(completed, total, item)
    results.sort(key=lambda item: _ip_sort_key(item.ip))
    duration = time.perf_counter() - started
    report = DiscoveryReport(
        spec=spec,
        results=results,
        timeout=timeout_seconds,
        max_workers=workers,
        duration=duration,
        started_at=started_at,
        ip_version=ip_version,
    )
    logger.info(
        "Discovery finished. up=%s down=%s duration=%.2fs",
        report.count(HostState.UP),
        report.count(HostState.DOWN),
        duration,
    )
    return report


def _ip_sort_key(value: str) -> tuple[int, ...]:
    try:
        packed = socket.inet_pton(socket.AF_INET, value)
        return (4, *packed)
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, value)
            return (6, *packed)
        except OSError:
            return (0, 0)

"""Compare consecutive authorized scans. This is a diff, not alerting or C2."""

from __future__ import annotations

from scanner.models import DiscoveryReport, HostState, ScanReport
from scanner.port import PortState


def open_port_delta(
    previous: ScanReport,
    current: ScanReport,
) -> tuple[list[int], list[int]]:
    """Return (newly open ports, ports no longer open)."""
    before = {item.port for item in previous.results if item.state is PortState.OPEN}
    after = {item.port for item in current.results if item.state is PortState.OPEN}
    appeared = sorted(after - before)
    disappeared = sorted(before - after)
    return appeared, disappeared


def live_host_delta(
    previous: DiscoveryReport,
    current: DiscoveryReport,
) -> tuple[list[str], list[str]]:
    """Return (newly up hosts, hosts no longer up)."""
    before = {item.ip for item in previous.results if item.state is HostState.UP}
    after = {item.ip for item in current.results if item.state is HostState.UP}
    appeared = sorted(after - before)
    disappeared = sorted(before - after)
    return appeared, disappeared

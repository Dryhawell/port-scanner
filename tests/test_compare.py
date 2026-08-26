"""Consecutive-scan diff tests. No network I/O."""

from __future__ import annotations

from scanner.compare import live_host_delta, open_port_delta
from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState, PortScanResult, ScanReport
from scanner.port import PortState


def _scan(*ports: tuple[int, PortState]) -> ScanReport:
    return ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=80,
        end_port=443,
        timeout=0.5,
        results=[PortScanResult(port=port, state=state) for port, state in ports],
    )


def test_open_port_delta_appeared_and_gone() -> None:
    previous = _scan((80, PortState.OPEN), (443, PortState.CLOSED))
    current = _scan((80, PortState.CLOSED), (443, PortState.OPEN))
    appeared, disappeared = open_port_delta(previous, current)
    assert appeared == [443]
    assert disappeared == [80]


def test_open_port_delta_no_change() -> None:
    report = _scan((22, PortState.OPEN), (80, PortState.TIMEOUT))
    appeared, disappeared = open_port_delta(report, report)
    assert appeared == []
    assert disappeared == []


def test_open_port_delta_only_shared_ignores_unprobed() -> None:
    previous = _scan((22, PortState.OPEN), (80, PortState.OPEN))
    current = _scan((80, PortState.OPEN), (443, PortState.OPEN))
    appeared, disappeared = open_port_delta(previous, current, only_shared=True)
    assert appeared == []
    assert disappeared == []
    appeared, disappeared = open_port_delta(previous, current)
    assert appeared == [443]
    assert disappeared == [22]


def test_live_host_delta() -> None:
    previous = DiscoveryReport(
        spec="192.168.1.0/30",
        results=[
            HostDiscoveryResult(ip="192.168.1.1", state=HostState.UP),
            HostDiscoveryResult(ip="192.168.1.2", state=HostState.DOWN),
        ],
        timeout=0.5,
    )
    current = DiscoveryReport(
        spec="192.168.1.0/30",
        results=[
            HostDiscoveryResult(ip="192.168.1.1", state=HostState.DOWN),
            HostDiscoveryResult(ip="192.168.1.2", state=HostState.UP),
        ],
        timeout=0.5,
    )
    appeared, disappeared = live_host_delta(previous, current)
    assert appeared == ["192.168.1.2"]
    assert disappeared == ["192.168.1.1"]

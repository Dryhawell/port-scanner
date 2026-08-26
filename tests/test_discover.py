"""Host discovery tests using mocks. No real remote hosts are contacted."""

from __future__ import annotations

import socket

import pytest

from scanner.discover import discover_hosts, probe_host
from scanner.models import HostDiscoveryResult, HostState, PortScanResult
from scanner.port import PortState


def test_probe_host_up_on_closed_port(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, bool]] = []

    def fake_probe(
        _host: str,
        port: int,
        _timeout: float,
        family: int = socket.AF_INET,
        with_banner: bool = True,
    ) -> PortScanResult:
        calls.append((port, with_banner))
        if port == 80:
            return PortScanResult(port=port, state=PortState.TIMEOUT)
        if port == 443:
            return PortScanResult(port=port, state=PortState.CLOSED)
        return PortScanResult(port=port, state=PortState.TIMEOUT)

    monkeypatch.setattr("scanner.discover.probe_tcp_port", fake_probe)
    result = probe_host("192.168.1.10", 0.5)

    assert result.state is HostState.UP
    assert result.evidence == "tcp/443 CLOSED"
    assert result.response_time is not None
    assert calls == [(80, False), (443, False)]


def test_probe_host_down_when_all_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(
        _host: str,
        port: int,
        _timeout: float,
        **_kwargs: object,
    ) -> PortScanResult:
        return PortScanResult(port=port, state=PortState.TIMEOUT)

    monkeypatch.setattr("scanner.discover.probe_tcp_port", fake_probe)
    result = probe_host("192.168.1.20", 0.5)

    assert result.state is HostState.DOWN
    assert result.evidence is None


def test_discover_hosts_cidr_sorts_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_probe(
        ip: str,
        timeout: float,
        family: int = socket.AF_INET,
        ports: object = None,
    ) -> HostDiscoveryResult:
        if ip.endswith(".1"):
            return HostDiscoveryResult(ip=ip, state=HostState.UP, evidence="tcp/80 OPEN")
        return HostDiscoveryResult(ip=ip, state=HostState.DOWN)

    monkeypatch.setattr("scanner.discover.probe_host", fake_probe)
    seen: list[int] = []

    def on_progress(completed: int, total: int, _result: HostDiscoveryResult) -> None:
        seen.append(total)

    report = discover_hosts(
        "192.168.1.0/30",
        timeout=0.5,
        max_workers=2,
        on_progress=on_progress,
    )

    assert report.spec == "192.168.1.0/30"
    assert [item.ip for item in report.results] == ["192.168.1.1", "192.168.1.2"]
    assert report.count(HostState.UP) == 1
    assert report.count(HostState.DOWN) == 1
    assert report.up_results[0].ip == "192.168.1.1"
    assert seen == [2, 2]


def test_discover_hosts_resolves_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scanner.discover.resolve_host",
        lambda _target, prefer_ipv6=False: ("127.0.0.1", socket.AF_INET),
    )
    monkeypatch.setattr(
        "scanner.discover.probe_host",
        lambda ip, timeout, family=socket.AF_INET, ports=(): HostDiscoveryResult(
            ip=ip,
            state=HostState.UP,
            evidence="tcp/80 CLOSED",
        ),
    )
    report = discover_hosts("localhost", timeout=0.5, max_workers=1)
    assert report.spec == "localhost"
    assert report.results[0].ip == "127.0.0.1"
    assert report.ip_version == 4

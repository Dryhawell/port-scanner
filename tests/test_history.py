"""Local sqlite history tests. No network I/O."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState, PortScanResult, ScanReport
from scanner.port import PortState
from utils.history import HistoryError, ScanHistory


def _scan() -> ScanReport:
    return ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=22,
        end_port=80,
        timeout=0.5,
        results=[
            PortScanResult(
                port=22,
                state=PortState.OPEN,
                service="ssh",
                banner="SSH-2.0-test",
                banner_kind="ssh",
                banner_product="OpenSSH",
                banner_version="9.2",
                response_time=0.012,
            ),
            PortScanResult(port=80, state=PortState.CLOSED),
        ],
        max_workers=2,
        duration=0.4,
        started_at=datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc),
        protocol="tcp",
    )


def _discovery() -> DiscoveryReport:
    return DiscoveryReport(
        spec="192.168.1.0/30",
        results=[
            HostDiscoveryResult(
                ip="192.168.1.1",
                state=HostState.UP,
                evidence="tcp/80 CLOSED",
                response_time=0.004,
            ),
            HostDiscoveryResult(ip="192.168.1.2", state=HostState.DOWN),
        ],
        timeout=0.5,
        max_workers=4,
        duration=0.8,
        started_at=datetime(2026, 8, 26, 13, 0, tzinfo=timezone.utc),
    )


def test_port_scan_roundtrip(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    scan_id = store.save(_scan())
    loaded = store.load(scan_id)
    assert isinstance(loaded, ScanReport)
    assert loaded.target == "127.0.0.1"
    assert loaded.resolved_ip == "127.0.0.1"
    assert [item.port for item in loaded.results] == [22, 80]
    assert loaded.results[0].state is PortState.OPEN
    assert loaded.results[0].banner == "SSH-2.0-test"
    assert loaded.results[0].banner_product == "OpenSSH"
    assert loaded.results[1].state is PortState.CLOSED
    assert loaded.count(PortState.OPEN) == 1


def test_discovery_roundtrip(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    scan_id = store.save(_discovery())
    loaded = store.load(scan_id)
    assert isinstance(loaded, DiscoveryReport)
    assert loaded.spec == "192.168.1.0/30"
    assert loaded.results[0].state is HostState.UP
    assert loaded.results[0].evidence == "tcp/80 CLOSED"
    assert loaded.count(HostState.UP) == 1


def test_list_newest_first_and_target_filter(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    first = store.save(_scan())
    second = store.save(_discovery())
    rows = store.list_scans(limit=10)
    assert [item.id for item in rows] == [second, first]
    assert rows[0].method == "tcp_ping"
    assert rows[1].hits == 1
    filtered = store.list_scans(target="127.0.0.1", limit=10)
    assert [item.id for item in filtered] == [first]


def test_list_missing_file_is_empty(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "missing.db")
    assert store.list_scans() == []


def test_load_unknown_id(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    store.save(_scan())
    with pytest.raises(HistoryError, match="id 99"):
        store.load(99)


def test_diff_open_ports(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    older = _scan()
    newer = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=22,
        end_port=80,
        timeout=0.5,
        results=[
            PortScanResult(port=22, state=PortState.CLOSED),
            PortScanResult(port=80, state=PortState.OPEN),
        ],
    )
    first_id = store.save(older)
    second_id = store.save(newer)
    kind, appeared, disappeared = store.diff(first_id, second_id)
    assert kind == "port"
    assert appeared == [80]
    assert disappeared == [22]


def test_diff_rejects_mixed_kinds(tmp_path: Path) -> None:
    store = ScanHistory(tmp_path / "history.db")
    port_id = store.save(_scan())
    host_id = store.save(_discovery())
    with pytest.raises(HistoryError, match="Cannot compare"):
        store.diff(port_id, host_id)

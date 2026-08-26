"""CLI helper tests. No network I/O."""

from __future__ import annotations

import pytest

from cli.interface import build_parser, render_progress_bar, run
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState


def test_progress_bar_empty_and_full() -> None:
    assert render_progress_bar(0, 10, width=10) == "[..........]   0%"
    assert render_progress_bar(10, 10, width=10) == "[##########] 100%"


def test_progress_bar_midpoint() -> None:
    assert render_progress_bar(5, 10, width=10) == "[#####.....]  50%"


def test_progress_bar_zero_total() -> None:
    assert render_progress_bar(0, 0, width=4) == "[####] 100%"


def test_parser_accepts_profile_or_ports() -> None:
    parser = build_parser()
    profile_args = parser.parse_args(["--target", "127.0.0.1", "--profile", "quick"])
    assert profile_args.profile == "quick"
    assert profile_args.ports is None
    port_args = parser.parse_args(["--target", "127.0.0.1", "--ports", "22,80,443"])
    assert port_args.ports == "22,80,443"
    assert port_args.profile is None
    html_args = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "80", "--format", "html"]
    )
    assert html_args.format == "html"
    pdf_args = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "80", "--format", "pdf"]
    )
    assert pdf_args.format == "pdf"
    ipv6_args = parser.parse_args(["--target", "localhost", "--ports", "80", "--ipv6"])
    assert ipv6_args.ipv6 is True
    udp_args = parser.parse_args(["--target", "127.0.0.1", "--udp", "--profile", "quick"])
    assert udp_args.udp is True
    discover_args = parser.parse_args(["--target", "192.168.1.0/24", "--discover"])
    assert discover_args.discover is True
    assert discover_args.ports is None
    assert discover_args.profile is None


def test_run_rejects_discover_combined_with_scan_flags() -> None:
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--udp"])
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--ports", "80"])
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--profile", "quick"])


def test_parser_accepts_interval_and_runs() -> None:
    args = build_parser().parse_args(
        ["--target", "127.0.0.1", "--profile", "quick", "--interval", "60", "--runs", "3"]
    )
    assert args.interval == "60"
    assert args.runs == "3"


def test_run_rejects_schedule_flag_combos() -> None:
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--profile", "quick", "--runs", "3"])
    with pytest.raises(SystemExit):
        run(["--gui", "--interval", "60"])


def test_scheduled_runs_sleep_and_diff(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("cli.interface.time.sleep", lambda seconds: sleeps.append(seconds))
    reports = [
        ScanReport(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            start_port=80,
            end_port=443,
            timeout=0.5,
            results=[
                PortScanResult(port=80, state=PortState.OPEN),
                PortScanResult(port=443, state=PortState.CLOSED),
            ],
        ),
        ScanReport(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            start_port=80,
            end_port=443,
            timeout=0.5,
            results=[
                PortScanResult(port=80, state=PortState.OPEN),
                PortScanResult(port=443, state=PortState.OPEN),
            ],
        ),
    ]

    class FakeScanner:
        def scan(self, *_args: object, **_kwargs: object) -> ScanReport:
            return reports.pop(0)

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    code = run(
        ["--target", "127.0.0.1", "--ports", "80,443", "--interval", "5", "--runs", "2"]
    )
    assert code == 0
    assert sleeps == [5]
    output = capsys.readouterr().out
    assert "newly open" in output
    assert "443" in output

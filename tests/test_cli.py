"""CLI helper tests. No network I/O."""

from __future__ import annotations

import json
from pathlib import Path

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
    skip = parser.parse_args(
        ["--target", "127.0.0.1", "--profile", "quick", "--exclude", "80,443"]
    )
    assert skip.exclude == "80,443"
    stdout_json = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "80", "--json"]
    )
    assert stdout_json.json is True


def test_run_rejects_discover_combined_with_scan_flags() -> None:
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--udp"])
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--ports", "80"])
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--profile", "quick"])
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--discover", "--exclude", "80"])


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
    monkeypatch.setattr("cli.interface.record_report", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )
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


def test_scan_records_history_unless_disabled(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    recorded: list[object] = []

    def fake_record(report: object) -> int:
        recorded.append(report)
        return 9

    monkeypatch.setattr("cli.interface.record_report", fake_record)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=80,
        end_port=80,
        timeout=0.5,
        results=[PortScanResult(port=80, state=PortState.OPEN)],
    )

    class FakeScanner:
        def scan(self, *_args: object, **_kwargs: object) -> ScanReport:
            return report

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    assert run(["--target", "127.0.0.1", "--ports", "80"]) == 0
    assert len(recorded) == 1
    recorded_out = capsys.readouterr().out
    assert "History recorded: #9" in recorded_out
    assert "OPEN" in recorded_out
    assert "[" in recorded_out
    recorded.clear()
    assert run(["--target", "127.0.0.1", "--ports", "80", "--no-history"]) == 0
    assert recorded == []
    assert "History recorded" not in capsys.readouterr().out


def test_parser_accepts_history_flags() -> None:
    parser = build_parser()
    listed = parser.parse_args(["--history"])
    assert listed.history is True
    one = parser.parse_args(["--history-id", "3"])
    assert one.history_id == 3
    diff = parser.parse_args(["--history-diff", "3", "4"])
    assert diff.history_diff == [3, 4]
    skip = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "80", "--no-history"]
    )
    assert skip.no_history is True
    quiet = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "23", "--no-refs"]
    )
    assert quiet.no_refs is True
    silent = parser.parse_args(
        ["--target", "127.0.0.1", "--ports", "80", "--no-diff"]
    )
    assert silent.no_diff is True
    listed_file = parser.parse_args(
        ["--target-file", "hosts.txt", "--profile", "quick"]
    )
    assert listed_file.target_file == "hosts.txt"


def test_run_rejects_target_file_combos() -> None:
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--target-file", "hosts.txt", "--ports", "80"])
    with pytest.raises(SystemExit):
        run(["--gui", "--target-file", "hosts.txt"])
    with pytest.raises(SystemExit):
        run(["--target-file", "hosts.txt", "--profile", "quick", "--interval", "60"])
    with pytest.raises(SystemExit):
        run(["--history", "--target-file", "hosts.txt"])


def test_cli_prints_reference_notes_unless_disabled(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("cli.interface.record_report", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=23,
        end_port=23,
        timeout=0.5,
        results=[PortScanResult(port=23, state=PortState.OPEN, service="telnet")],
    )

    class FakeScanner:
        def scan(self, *_args: object, **_kwargs: object) -> ScanReport:
            return report

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    assert run(["--target", "127.0.0.1", "--ports", "23"]) == 0
    shown = capsys.readouterr().out
    assert "note:" in shown
    assert "CWE-319" in shown
    assert "not a vulnerability scan" in shown.lower()
    assert run(["--target", "127.0.0.1", "--ports", "23", "--no-refs"]) == 0
    quiet = capsys.readouterr().out
    assert "note:" not in quiet


def test_run_rejects_history_flag_combos() -> None:
    with pytest.raises(SystemExit):
        run(["--gui", "--history"])
    with pytest.raises(SystemExit):
        run(["--history", "--history-id", "1"])
    with pytest.raises(SystemExit):
        run(["--history", "--interval", "60"])


def test_history_list_and_show(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from datetime import datetime, timezone

    from scanner.port import PortState
    from utils.history import ScanHistory

    db_path = tmp_path / "history.db"
    store = ScanHistory(db_path)
    scan_id = store.save(
        ScanReport(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            start_port=80,
            end_port=80,
            timeout=0.5,
            results=[PortScanResult(port=80, state=PortState.OPEN)],
            started_at=datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("cli.interface.ScanHistory", lambda: ScanHistory(db_path))
    assert run(["--history"]) == 0
    listed = capsys.readouterr().out
    assert "tcp_connect" in listed
    assert "127.0.0.1" in listed
    assert "Hits over stored runs" in listed
    assert run(["--history-id", str(scan_id)]) == 0
    shown = capsys.readouterr().out
    assert "OPEN" in shown
    assert "80" in shown


def test_history_diff_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from utils.history import ScanHistory

    db_path = tmp_path / "history.db"
    store = ScanHistory(db_path)
    first = store.save(
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
        )
    )
    second = store.save(
        ScanReport(
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
            start_port=80,
            end_port=443,
            timeout=0.5,
            results=[
                PortScanResult(port=80, state=PortState.CLOSED),
                PortScanResult(port=443, state=PortState.OPEN),
            ],
        )
    )
    monkeypatch.setattr("cli.interface.ScanHistory", lambda: ScanHistory(db_path))
    assert run(["--history-diff", str(first), str(second)]) == 0
    output = capsys.readouterr().out
    assert "newly open" in output
    assert "443" in output
    assert "80" in output
    assert "no longer open" in output


def test_scan_diffs_against_stored_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "history.db"
    monkeypatch.setattr("utils.history.DEFAULT_DB_PATH", db_path)
    first = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=80,
        end_port=443,
        timeout=0.5,
        results=[
            PortScanResult(port=80, state=PortState.OPEN),
            PortScanResult(port=443, state=PortState.CLOSED),
        ],
    )
    second = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=80,
        end_port=443,
        timeout=0.5,
        results=[
            PortScanResult(port=80, state=PortState.OPEN),
            PortScanResult(port=443, state=PortState.OPEN),
        ],
    )
    queue = [first, second, second]

    class FakeScanner:
        def scan(self, *_args: object, **_kwargs: object) -> ScanReport:
            return queue.pop(0)

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    assert run(["--target", "127.0.0.1", "--ports", "80,443"]) == 0
    assert "Changes vs stored" not in capsys.readouterr().out
    assert run(["--target", "127.0.0.1", "--ports", "80,443"]) == 0
    changed = capsys.readouterr().out
    assert "Changes vs stored #" in changed
    assert "newly open" in changed
    assert "443" in changed
    assert run(["--target", "127.0.0.1", "--ports", "80,443", "--no-diff"]) == 0
    assert "Changes vs stored" not in capsys.readouterr().out


def test_target_file_scans_sequentially(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("127.0.0.1\nlocalhost\n", encoding="utf-8")
    monkeypatch.setattr("cli.interface.record_report", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )
    seen: list[str] = []

    class FakeScanner:
        def scan(self, target: str, *_args: object, **_kwargs: object) -> ScanReport:
            seen.append(target)
            return ScanReport(
                target=target,
                resolved_ip="127.0.0.1",
                start_port=80,
                end_port=80,
                timeout=0.5,
                results=[PortScanResult(port=80, state=PortState.OPEN)],
            )

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    code = run(["--target-file", str(hosts), "--ports", "80"])
    assert code == 0
    assert seen == ["127.0.0.1", "localhost"]
    output = capsys.readouterr().out
    assert "Target 1/2" in output
    assert "Target 2/2" in output
    assert "sequential" in output
    assert "2/2 target(s) succeeded" in output


def test_exclude_drops_ports_from_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cli.interface.record_report", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )
    seen: list[list[int]] = []

    class FakeScanner:
        def scan(self, *_args: object, **kwargs: object) -> ScanReport:
            raw = kwargs["ports"]
            assert isinstance(raw, (list, tuple))
            ports = list(raw)
            seen.append(ports)
            return ScanReport(
                target="127.0.0.1",
                resolved_ip="127.0.0.1",
                start_port=ports[0],
                end_port=ports[-1],
                timeout=0.5,
                results=[
                    PortScanResult(port=port, state=PortState.CLOSED) for port in ports
                ],
            )

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    assert run(["--target", "127.0.0.1", "--ports", "22,80,443", "--exclude", "80"]) == 0
    assert seen == [[22, 443]]
    seen.clear()
    assert run(["--target", "127.0.0.1", "--ports", "80", "--exclude", "80"]) == 1


def test_run_rejects_json_combos() -> None:
    with pytest.raises(SystemExit):
        run(["--target", "127.0.0.1", "--ports", "80", "--json", "--format", "json"])
    with pytest.raises(SystemExit):
        run(["--gui", "--json"])
    with pytest.raises(SystemExit):
        run(["--target-file", "hosts.txt", "--profile", "quick", "--json"])
    with pytest.raises(SystemExit):
        run(["--history", "--json"])


def test_json_prints_report_on_stdout(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("cli.interface.record_report", lambda *_a, **_k: 1)
    monkeypatch.setattr(
        "cli.interface.ScanHistory.previous_for",
        lambda _self, _report: None,
    )

    class FakeScanner:
        def scan(self, *_args: object, **_kwargs: object) -> ScanReport:
            return ScanReport(
                target="127.0.0.1",
                resolved_ip="127.0.0.1",
                start_port=80,
                end_port=80,
                timeout=0.5,
                results=[PortScanResult(port=80, state=PortState.OPEN)],
            )

    monkeypatch.setattr("cli.interface.TcpConnectScanner", FakeScanner)
    assert run(["--target", "127.0.0.1", "--ports", "80", "--json"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["target"] == "127.0.0.1"
    assert payload["scan_method"] == "tcp_connect"
    assert "[+]" not in captured.out
    assert "authorized" in captured.err.lower()

"""Report export tests. No network I/O."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState, PortScanResult, ScanReport
from scanner.port import PortState
from utils.exporter import (
    ExportError,
    ExportFormat,
    discovery_to_dict,
    export_report,
    infer_format,
    path_for_run,
    report_to_dict,
    report_to_html,
    report_to_pdf,
)


def _sample_report(*, banner: str | None = "SSH-2.0-test") -> ScanReport:
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
                banner=banner,
                response_time=0.012,
            ),
            PortScanResult(port=80, state=PortState.CLOSED),
        ],
        max_workers=2,
        duration=0.4,
        started_at=datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc),
    )


def test_infer_html_suffix() -> None:
    assert infer_format("reports/scan.html") is ExportFormat.HTML
    assert infer_format("scan.JSON") is ExportFormat.JSON


def test_report_to_html_includes_summary() -> None:
    document = report_to_html(_sample_report())
    assert "<!DOCTYPE html>" in document
    assert "127.0.0.1" in document
    assert "SSH-2.0-test" in document
    assert ">22<" in document
    assert "OPEN" in document
    assert "CLOSED" in document
    assert "tcp_connect" in document
    assert "Notes" in document
    assert "SSH remote login" in document
    assert "<svg" in document
    assert 'xmlns="http://www.w3.org/2000/svg"' in document


def test_report_to_html_escapes_banner() -> None:
    document = report_to_html(_sample_report(banner="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


def test_export_html_writes_file(tmp_path: Path) -> None:
    output = tmp_path / "scan.html"
    saved = export_report(_sample_report(), output, ExportFormat.HTML)
    assert saved == output
    text = output.read_text(encoding="utf-8")
    assert "Scan report" in text
    assert "22" in text


def test_sparse_json_includes_ports_list() -> None:
    payload = report_to_dict(_sample_report())
    assert payload["ports"] == [22, 80]
    results = payload["results"]
    assert isinstance(results, list)
    first = results[0]
    assert isinstance(first, dict)
    assert first["advisories"][0]["title"] == "SSH remote login"


def test_invalid_format() -> None:
    with pytest.raises(ExportError, match="json, csv, html, or pdf"):
        export_report(_sample_report(), "out.bin", "docx")


def _sample_discovery() -> DiscoveryReport:
    return DiscoveryReport(
        spec="192.168.1.0/30",
        results=[
            HostDiscoveryResult(
                ip="192.168.1.1",
                state=HostState.UP,
                evidence="tcp/80 CLOSED",
                response_time=0.01,
            ),
            HostDiscoveryResult(ip="192.168.1.2", state=HostState.DOWN),
        ],
        timeout=0.5,
        max_workers=2,
        duration=0.2,
        started_at=datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc),
    )


def test_discovery_json_uses_tcp_ping() -> None:
    payload = discovery_to_dict(_sample_discovery())
    assert payload["scan_method"] == "tcp_ping"
    assert payload["target"] == "192.168.1.0/30"
    assert payload["live_hosts"] == ["192.168.1.1"]
    assert payload["summary"] == {"scanned": 2, "up": 1, "down": 1}


def test_export_discovery_html(tmp_path: Path) -> None:
    output = tmp_path / "discovery.html"
    saved = export_report(_sample_discovery(), output, ExportFormat.HTML)
    text = saved.read_text(encoding="utf-8")
    assert "Host discovery" in text
    assert "tcp_ping" in text
    assert "192.168.1.1" in text
    assert 'class="UP"' in text
    assert 'class="DOWN"' in text
    assert "<svg" in text


def test_path_for_run_suffix() -> None:
    first = path_for_run("reports/scan.json", 1)
    second = path_for_run("reports/scan.json", 2)
    assert first.as_posix() == "reports/scan.json"
    assert second.as_posix() == "reports/scan_run2.json"


def test_infer_pdf_suffix() -> None:
    assert infer_format("reports/scan.pdf") is ExportFormat.PDF


def test_export_pdf_contains_header(tmp_path: Path) -> None:
    output = tmp_path / "scan.pdf"
    saved = export_report(_sample_report(), output, ExportFormat.PDF)
    data = saved.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"%%EOF" in data
    assert b"Scan report" in data
    assert b"127.0.0.1" in data
    assert b"OPEN" in data
    assert b"tcp_connect" in data
    assert b"SSH-2.0-test" in data


def test_pdf_escapes_parentheses() -> None:
    payload = report_to_pdf(_sample_report(banner="ready (vsFTPd)"))
    assert b"ready \\(vsFTPd\\)" in payload


def test_export_discovery_pdf(tmp_path: Path) -> None:
    output = tmp_path / "discovery.pdf"
    saved = export_report(_sample_discovery(), output, ExportFormat.PDF)
    data = saved.read_bytes()
    assert data.startswith(b"%PDF-1.4")
    assert b"tcp_ping" in data
    assert b"192.168.1.1" in data


def test_pdf_paginates_many_rows() -> None:
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=1,
        end_port=80,
        timeout=0.5,
        results=[PortScanResult(port=port, state=PortState.CLOSED) for port in range(1, 81)],
    )
    payload = report_to_pdf(report)
    assert b"cont." in payload
    assert b"Page 2" in payload

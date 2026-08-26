"""Report export tests. No network I/O."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from utils.exporter import (
    ExportError,
    ExportFormat,
    export_report,
    infer_format,
    report_to_dict,
    report_to_html,
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


def test_invalid_format() -> None:
    with pytest.raises(ExportError, match="json, csv, or html"):
        export_report(_sample_report(), "out.bin", "pdf")

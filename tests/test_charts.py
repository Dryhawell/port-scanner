"""Chart helper tests. No network I/O, no Tkinter."""

from __future__ import annotations

from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState, PortScanResult, ScanReport
from scanner.port import PortState
from utils.charts import bars_ascii, bars_from_report, bars_svg, scale_lengths, trend_ascii


def test_scale_lengths_empty_and_zero() -> None:
    assert scale_lengths([], 10) == []
    assert scale_lengths([0, 0], 10) == [0, 0]
    assert scale_lengths([5], 0) == [0]


def test_scale_lengths_peaks_at_full_width() -> None:
    assert scale_lengths([1, 2, 4], 8) == [2, 4, 8]


def test_bars_ascii_from_scan() -> None:
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=22,
        end_port=80,
        timeout=0.5,
        results=[
            PortScanResult(port=22, state=PortState.OPEN),
            PortScanResult(port=80, state=PortState.CLOSED),
            PortScanResult(port=443, state=PortState.TIMEOUT),
        ],
    )
    chart = bars_ascii(bars_from_report(report), width=10)
    assert "OPEN" in chart
    assert "CLOSED" in chart
    assert "TIMEOUT" in chart
    assert "[" in chart and "]" in chart
    assert "    1" in chart


def test_bars_ascii_discovery() -> None:
    report = DiscoveryReport(
        spec="192.168.1.0/30",
        results=[
            HostDiscoveryResult(ip="192.168.1.1", state=HostState.UP),
            HostDiscoveryResult(ip="192.168.1.2", state=HostState.DOWN),
        ],
        timeout=0.5,
    )
    chart = bars_ascii(bars_from_report(report), width=4)
    assert "UP" in chart
    assert "DOWN" in chart


def test_bars_svg_includes_counts_and_colors() -> None:
    report = ScanReport(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        start_port=22,
        end_port=22,
        timeout=0.5,
        results=[PortScanResult(port=22, state=PortState.OPEN)],
    )
    document = bars_svg(bars_from_report(report))
    assert document.startswith("<svg")
    assert 'xmlns="http://www.w3.org/2000/svg"' in document
    assert "#3fb950" in document
    assert ">OPEN<" in document
    assert ">1</text>" in document


def test_trend_ascii_oldest_left() -> None:
    chart = trend_ascii([1, 3, 0], height=3)
    lines = chart.splitlines()
    assert lines[0].strip() == ".#."
    assert lines[1].strip() == ".#."
    assert lines[2].strip() == "##."
    assert "1 3 0" in chart


def test_trend_ascii_empty() -> None:
    assert "no history" in trend_ascii([])

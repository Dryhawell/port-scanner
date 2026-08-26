"""Simple charts for scan counts. No matplotlib, no JavaScript.

Horizontal bars (OPEN / CLOSED / TIMEOUT, or UP / DOWN) go into the CLI,
the HTML report (SVG), and the Tkinter canvas. Column charts show hits
across stored history runs. Counts are observations, not a risk score.
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from dataclasses import dataclass

from scanner.models import DiscoveryReport, HostState, ScanReport
from scanner.port import PortState

COLOR_OPEN = "#3fb950"
COLOR_CLOSED = "#f85149"
COLOR_TIMEOUT = "#d29922"
COLOR_TRACK = "#21262d"
COLOR_TEXT = "#e6edf3"
COLOR_MUTED = "#8b949e"
ASCII_BAR_WIDTH = 20
SVG_WIDTH = 640
SVG_ROW = 28


@dataclass(frozen=True, slots=True)
class BarSpec:
    """One named count and the color used to draw it."""

    label: str
    value: int
    color: str


def bars_from_report(report: ScanReport | DiscoveryReport) -> tuple[BarSpec, ...]:
    """Build chart bars from a port scan or a discovery report."""
    if isinstance(report, DiscoveryReport):
        return (
            BarSpec("UP", report.count(HostState.UP), COLOR_OPEN),
            BarSpec("DOWN", report.count(HostState.DOWN), COLOR_CLOSED),
        )
    return (
        BarSpec("OPEN", report.count(PortState.OPEN), COLOR_OPEN),
        BarSpec("CLOSED", report.count(PortState.CLOSED), COLOR_CLOSED),
        BarSpec("TIMEOUT", report.count(PortState.TIMEOUT), COLOR_TIMEOUT),
    )


def empty_port_bars() -> tuple[BarSpec, ...]:
    return (
        BarSpec("OPEN", 0, COLOR_OPEN),
        BarSpec("CLOSED", 0, COLOR_CLOSED),
        BarSpec("TIMEOUT", 0, COLOR_TIMEOUT),
    )


def empty_discovery_bars() -> tuple[BarSpec, ...]:
    return (
        BarSpec("UP", 0, COLOR_OPEN),
        BarSpec("DOWN", 0, COLOR_CLOSED),
    )


def scale_lengths(values: Sequence[int], length: int) -> list[int]:
    """Scale values into 0..length pixels or character cells."""
    if length < 0:
        raise ValueError("length must be >= 0")
    peak = max(values) if values else 0
    if peak <= 0 or length == 0:
        return [0] * len(values)
    return [int(round(value / peak * length)) for value in values]


def bars_ascii(bars: Sequence[BarSpec], *, width: int = ASCII_BAR_WIDTH) -> str:
    """Return a compact labeled ASCII bar chart."""
    if not bars:
        return "(no data to chart)"
    lengths = scale_lengths([bar.value for bar in bars], width)
    label_width = max(len(bar.label) for bar in bars)
    lines: list[str] = []
    for bar, filled in zip(bars, lengths, strict=True):
        body = "#" * filled + "." * (width - filled)
        lines.append(f"{bar.label:<{label_width}}  {bar.value:>5}  [{body}]")
    return "\n".join(lines)


def trend_ascii(values: Sequence[int], *, height: int = 6) -> str:
    """Return a column chart, oldest on the left, newest on the right."""
    if not values:
        return "(no history to chart)"
    peak = max(values)
    columns = scale_lengths(values, height)
    lines: list[str] = []
    for row in range(height, 0, -1):
        cells = ["#" if filled >= row else "." for filled in columns]
        lines.append("  " + "".join(cells))
    lines.append("  " + "-" * len(values))
    numbers = " ".join(str(value) for value in values)
    lines.append(f"  {numbers}")
    if peak == 0:
        lines.append("  (all zero)")
    return "\n".join(lines)


def bars_svg(bars: Sequence[BarSpec], *, width: int = SVG_WIDTH) -> str:
    """Return a standalone SVG bar chart for HTML reports."""
    if not bars:
        return ""
    left = 88
    right = 52
    top = 10
    plot_width = max(width - left - right, 1)
    height = top + SVG_ROW * len(bars) + 8
    lengths = scale_lengths([bar.value for bar in bars], plot_width)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="{height}" role="img" '
        'aria-label="Result counts">'
    ]
    for index, (bar, filled) in enumerate(zip(bars, lengths, strict=True)):
        y = top + index * SVG_ROW
        track_y = y + 8
        label = html.escape(bar.label)
        parts.append(
            f'<text x="0" y="{y + 18}" fill="{COLOR_MUTED}" font-size="12" '
            f'font-family="Consolas,ui-monospace,monospace">{label}</text>'
        )
        parts.append(
            f'<rect x="{left}" y="{track_y}" width="{plot_width}" height="12" '
            f'rx="3" fill="{COLOR_TRACK}"/>'
        )
        if filled > 0:
            parts.append(
                f'<rect x="{left}" y="{track_y}" width="{filled}" height="12" '
                f'rx="3" fill="{html.escape(bar.color)}"/>'
            )
        parts.append(
            f'<text x="{left + plot_width + 8}" y="{y + 18}" fill="{COLOR_TEXT}" '
            f'font-size="12" font-family="Consolas,ui-monospace,monospace">'
            f"{bar.value}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)

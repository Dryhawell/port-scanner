"""Export scan reports to JSON or CSV.

Generated files go under reports/ by default and are gitignored.
The JSON shape is meant to be consumed by other tools without scraping CLI text.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from utils.logger import get_logger

logger = get_logger()

REPORTS_DIR = Path("reports")
JSON_INDENT = 2


class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"


class ExportError(ValueError):
    """Raised when a report cannot be written."""


def report_to_dict(report: ScanReport) -> dict[str, object]:
    """Serialize a scan into a stable JSON-friendly dictionary."""
    open_ports = [item.port for item in report.open_results]
    return {
        "tool": "port-scanner",
        "scan_method": "tcp_connect",
        "target": report.target,
        "resolved_ip": report.resolved_ip,
        "scan_time": _isoformat(report.started_at),
        "duration": _round_time(report.duration),
        "timeout": report.timeout,
        "threads": report.max_workers,
        "port_range": {
            "start": report.start_port,
            "end": report.end_port,
        },
        "open_ports": open_ports,
        "summary": {
            "scanned": len(report.results),
            "open": report.count(PortState.OPEN),
            "closed": report.count(PortState.CLOSED),
            "timeout": report.count(PortState.TIMEOUT),
        },
        "results": [_result_to_dict(item) for item in report.results],
    }


def export_report(
    report: ScanReport,
    path: str | Path,
    fmt: ExportFormat | str,
) -> Path:
    """Write the report and return the resolved file path."""
    format_name = _parse_format(fmt)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if format_name is ExportFormat.JSON:
        _write_json(report, output)
    else:
        _write_csv(report, output)
    logger.info("Report saved: %s", output)
    return output


def default_output_path(fmt: ExportFormat | str) -> Path:
    """Build reports/scan_YYYY-MM-DD_HHMM.<format>, with seconds on collision."""
    format_name = _parse_format(fmt)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    candidate = REPORTS_DIR / f"scan_{stamp}.{format_name.value}"
    if not candidate.exists():
        return candidate
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return REPORTS_DIR / f"scan_{stamp}.{format_name.value}"


def infer_format(path: str | Path) -> ExportFormat | None:
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix in {item.value for item in ExportFormat}:
        return ExportFormat(suffix)
    return None


def _write_json(report: ScanReport, path: Path) -> None:
    try:
        path.write_text(
            json.dumps(report_to_dict(report), indent=JSON_INDENT, ensure_ascii=True)
            + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        logger.error("Could not write JSON report: %s", exc)
        raise ExportError(f"Could not write JSON report: {exc}") from exc


def _write_csv(report: ScanReport, path: Path) -> None:
    fieldnames = ("port", "state", "protocol", "service", "response_time", "banner")
    try:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in report.results:
                writer.writerow(_result_to_csv_row(item))
    except OSError as exc:
        logger.error("Could not write CSV report: %s", exc)
        raise ExportError(f"Could not write CSV report: {exc}") from exc


def _result_to_dict(result: PortScanResult) -> dict[str, object]:
    return {
        "port": result.port,
        "state": result.state.value,
        "protocol": result.protocol,
        "service": result.service,
        "response_time": _round_time(result.response_time),
        "banner": result.banner,
        "timestamp": _isoformat(result.timestamp),
    }


def _result_to_csv_row(result: PortScanResult) -> dict[str, object]:
    response = _round_time(result.response_time)
    return {
        "port": result.port,
        "state": result.state.value,
        "protocol": result.protocol,
        "service": result.service or "",
        "response_time": "" if response is None else response,
        "banner": result.banner or "",
    }


def _parse_format(fmt: ExportFormat | str) -> ExportFormat:
    if isinstance(fmt, ExportFormat):
        return fmt
    cleaned = fmt.strip().lower()
    try:
        return ExportFormat(cleaned)
    except ValueError as exc:
        raise ExportError("Format must be json or csv.") from exc


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _round_time(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 6)

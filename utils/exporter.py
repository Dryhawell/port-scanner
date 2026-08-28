"""Export scan reports to JSON, CSV, HTML, or PDF.

Generated files go under reports/ by default and are gitignored.
JSON is for other tools; HTML is a self-contained page you can open in a browser,
with a small SVG bar chart of result counts. PDF is a simple stdlib-built
document (Helvetica/Courier, no images).
"""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

from scanner.advisory import DISCLAIMER, advisory_label, lookup_advisories
from scanner.constants import APP_NAME, APP_VERSION
from scanner.models import DiscoveryReport, HostDiscoveryResult, HostState, PortScanResult, ScanReport
from scanner.port import PortState
from utils.charts import bars_from_report, bars_svg
from utils.logger import get_logger
from utils.pdf import build_pdf

logger = get_logger()

REPORTS_DIR = Path("reports")
JSON_INDENT = 2


class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"


class ExportError(ValueError):
    """Raised when a report cannot be written."""


def report_to_dict(report: ScanReport, *, open_only: bool = False) -> dict[str, object]:
    """Serialize a scan into a stable JSON-friendly dictionary."""
    open_ports = [item.port for item in report.open_results]
    scanned_ports = [item.port for item in report.results]
    rows = report.open_results if open_only else report.results
    payload: dict[str, object] = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "scan_method": "udp_probe" if report.protocol == "udp" else "tcp_connect",
        "target": report.target,
        "resolved_ip": report.resolved_ip,
        "ip_version": report.ip_version,
        "protocol": report.protocol,
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
        "results": [_result_to_dict(item) for item in rows],
    }
    if open_only:
        payload["open_only"] = True
    contiguous = scanned_ports == list(range(report.start_port, report.end_port + 1))
    if scanned_ports and not contiguous:
        payload["ports"] = scanned_ports
    return payload


def report_to_json(
    report: ScanReport | DiscoveryReport,
    *,
    open_only: bool = False,
) -> str:
    """Return the same JSON text that export writes to a .json file."""
    payload = (
        discovery_to_dict(report, open_only=open_only)
        if isinstance(report, DiscoveryReport)
        else report_to_dict(report, open_only=open_only)
    )
    return json.dumps(payload, indent=JSON_INDENT, ensure_ascii=True) + "\n"


def discovery_to_dict(
    report: DiscoveryReport,
    *,
    open_only: bool = False,
) -> dict[str, object]:
    """Serialize a TCP ping discovery into a JSON-friendly dictionary."""
    live = [item.ip for item in report.up_results]
    rows = report.up_results if open_only else report.results
    payload: dict[str, object] = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "scan_method": "tcp_ping",
        "target": report.spec,
        "ip_version": report.ip_version,
        "scan_time": _isoformat(report.started_at),
        "duration": _round_time(report.duration),
        "timeout": report.timeout,
        "threads": report.max_workers,
        "live_hosts": live,
        "summary": {
            "scanned": len(report.results),
            "up": report.count(HostState.UP),
            "down": report.count(HostState.DOWN),
        },
        "results": [_host_to_dict(item) for item in rows],
    }
    if open_only:
        payload["open_only"] = True
    return payload


def export_report(
    report: ScanReport | DiscoveryReport,
    path: str | Path,
    fmt: ExportFormat | str,
    *,
    open_only: bool = False,
) -> Path:
    """Write the report and return the resolved file path."""
    format_name = _parse_format(fmt)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(report, DiscoveryReport):
        writers = {
            ExportFormat.JSON: _write_discovery_json,
            ExportFormat.CSV: _write_discovery_csv,
            ExportFormat.HTML: _write_discovery_html,
            ExportFormat.PDF: _write_discovery_pdf,
        }
    else:
        writers = {
            ExportFormat.JSON: _write_json,
            ExportFormat.CSV: _write_csv,
            ExportFormat.HTML: _write_html,
            ExportFormat.PDF: _write_pdf,
        }
    writers[format_name](report, output, open_only=open_only)
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


def path_for_run(path: str | Path, run_index: int) -> Path:
    """Return stem_runN.suffix so scheduled exports do not overwrite each other."""
    output = Path(path)
    if run_index <= 1:
        return output
    return output.with_name(f"{output.stem}_run{run_index}{output.suffix}")


def infer_format(path: str | Path) -> ExportFormat | None:
    suffix = Path(path).suffix.lower().lstrip(".")
    if suffix in {item.value for item in ExportFormat}:
        return ExportFormat(suffix)
    return None


def _write_json(report: ScanReport, path: Path, *, open_only: bool = False) -> None:
    try:
        path.write_text(report_to_json(report, open_only=open_only), encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write JSON report: %s", exc)
        raise ExportError(f"Could not write JSON report: {exc}") from exc


def _write_csv(report: ScanReport, path: Path, *, open_only: bool = False) -> None:
    fieldnames = (
        "port",
        "state",
        "protocol",
        "service",
        "product",
        "version",
        "response_time",
        "banner",
        "refs",
    )
    rows = report.open_results if open_only else report.results
    try:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in rows:
                writer.writerow(_result_to_csv_row(item))
    except OSError as exc:
        logger.error("Could not write CSV report: %s", exc)
        raise ExportError(f"Could not write CSV report: {exc}") from exc


def _write_discovery_json(
    report: DiscoveryReport,
    path: Path,
    *,
    open_only: bool = False,
) -> None:
    try:
        path.write_text(report_to_json(report, open_only=open_only), encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write JSON report: %s", exc)
        raise ExportError(f"Could not write JSON report: {exc}") from exc


def _write_discovery_csv(
    report: DiscoveryReport,
    path: Path,
    *,
    open_only: bool = False,
) -> None:
    fieldnames = ("ip", "state", "evidence", "response_time")
    rows = report.up_results if open_only else report.results
    try:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in rows:
                response = _round_time(item.response_time)
                writer.writerow(
                    {
                        "ip": item.ip,
                        "state": item.state.value,
                        "evidence": item.evidence or "",
                        "response_time": "" if response is None else response,
                    }
                )
    except OSError as exc:
        logger.error("Could not write CSV report: %s", exc)
        raise ExportError(f"Could not write CSV report: {exc}") from exc


def _write_discovery_html(
    report: DiscoveryReport,
    path: Path,
    *,
    open_only: bool = False,
) -> None:
    try:
        path.write_text(_discovery_to_html(report, open_only=open_only), encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write HTML report: %s", exc)
        raise ExportError(f"Could not write HTML report: {exc}") from exc


def _discovery_to_html(report: DiscoveryReport, *, open_only: bool = False) -> str:
    up_count = report.count(HostState.UP)
    down_count = report.count(HostState.DOWN)
    duration = "—" if report.duration is None else f"{report.duration:.2f}s"
    scan_time = _isoformat(report.started_at) or "—"
    table_rows = report.up_results if open_only else report.results
    rows = "\n".join(_html_host_row(item) for item in table_rows)
    if not rows:
        rows = '<tr><td colspan="4" class="empty">No hosts in this report.</td></tr>'
    filter_note = " Open-only rows shown." if open_only else ""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(APP_NAME)} discovery — {html.escape(report.spec)}</title>\n"
        f"<style>{_HTML_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"<p class=\"notice\">{html.escape(APP_NAME)} {html.escape(APP_VERSION)}"
        " — authorized TCP ping discovery only. Not a vulnerability assessment."
        f"{html.escape(filter_note)}</p>\n"
        "<h1>Host discovery</h1>\n"
        "<section class=\"meta\">\n"
        f"<div><span>Target</span><strong>{html.escape(report.spec)}</strong></div>\n"
        f"<div><span>IP version</span><strong>IPv{report.ip_version}</strong></div>\n"
        f"<div><span>Method</span><strong>tcp_ping</strong></div>\n"
        f"<div><span>Scan time</span><strong>{html.escape(scan_time)}</strong></div>\n"
        f"<div><span>Duration</span><strong>{html.escape(duration)}</strong></div>\n"
        f"<div><span>Timeout</span><strong>{html.escape(str(report.timeout))}s</strong></div>\n"
        f"<div><span>Threads</span><strong>{html.escape(str(report.max_workers))}</strong></div>\n"
        "</section>\n"
        "<section class=\"summary\">\n"
        f"<div class=\"stat\"><span>Scanned</span><strong>{len(report.results)}</strong></div>\n"
        f"<div class=\"stat open\"><span>Up</span><strong>{up_count}</strong></div>\n"
        f"<div class=\"stat closed\"><span>Down</span><strong>{down_count}</strong></div>\n"
        "</section>\n"
        f"<section class=\"chart\">{bars_svg(bars_from_report(report))}</section>\n"
        "<table>\n"
        "<thead><tr><th>Host</th><th>State</th><th>Evidence</th><th>Response</th></tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n"
        "</table>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _html_host_row(result: HostDiscoveryResult) -> str:
    latency = result.latency_label() or "—"
    evidence = result.evidence or "—"
    state = result.state.value
    return (
        f'<tr class="{html.escape(state)}">'
        f"<td>{html.escape(result.ip)}</td>"
        f"<td>{html.escape(state)}</td>"
        f"<td>{html.escape(evidence)}</td>"
        f"<td>{html.escape(latency)}</td>"
        "</tr>"
    )


def report_to_html(report: ScanReport, *, open_only: bool = False) -> str:
    """Build a standalone HTML document for a scan report."""
    open_count = report.count(PortState.OPEN)
    closed_count = report.count(PortState.CLOSED)
    timeout_count = report.count(PortState.TIMEOUT)
    duration = "—" if report.duration is None else f"{report.duration:.2f}s"
    scan_time = _isoformat(report.started_at) or "—"
    table_rows = report.open_results if open_only else report.results
    rows = "\n".join(_html_result_row(item) for item in table_rows)
    if not rows:
        rows = (
            '<tr><td colspan="8" class="empty">No ports in this report.</td></tr>'
        )
    filter_note = " Open-only rows shown." if open_only else ""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{html.escape(APP_NAME)} report — {html.escape(report.target)}</title>\n"
        f"<style>{_HTML_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"<p class=\"notice\">{html.escape(APP_NAME)} {html.escape(APP_VERSION)}"
        " — authorized TCP connect scan only. Not a vulnerability assessment. "
        f"{html.escape(DISCLAIMER)}{html.escape(filter_note)}</p>\n"
        "<h1>Scan report</h1>\n"
        "<section class=\"meta\">\n"
        f"<div><span>Target</span><strong>{html.escape(report.target)}</strong></div>\n"
        f"<div><span>Resolved IP</span><strong>{html.escape(report.resolved_ip)}</strong></div>\n"
        f"<div><span>IP version</span><strong>IPv{report.ip_version}</strong></div>\n"
        f"<div><span>Protocol</span><strong>{html.escape(report.protocol)}</strong></div>\n"
        f"<div><span>Ports</span><strong>{html.escape(report.port_label())}</strong></div>\n"
        f"<div><span>Scan time</span><strong>{html.escape(scan_time)}</strong></div>\n"
        f"<div><span>Duration</span><strong>{html.escape(duration)}</strong></div>\n"
        f"<div><span>Timeout</span><strong>{html.escape(str(report.timeout))}s</strong></div>\n"
        f"<div><span>Threads</span><strong>{html.escape(str(report.max_workers))}</strong></div>\n"
        f"<div><span>Method</span><strong>tcp_connect</strong></div>\n"
        "</section>\n"
        "<section class=\"summary\">\n"
        f"<div class=\"stat\"><span>Scanned</span><strong>{len(report.results)}</strong></div>\n"
        f"<div class=\"stat open\"><span>Open</span><strong>{open_count}</strong></div>\n"
        f"<div class=\"stat closed\"><span>Closed</span><strong>{closed_count}</strong></div>\n"
        f"<div class=\"stat timeout\"><span>Timeout</span><strong>{timeout_count}</strong></div>\n"
        "</section>\n"
        f"<section class=\"chart\">{bars_svg(bars_from_report(report))}</section>\n"
        "<table>\n"
        "<thead><tr>"
        "<th>Port</th><th>State</th><th>Protocol</th>"
        "<th>Service</th><th>Product</th><th>Response</th><th>Banner</th><th>Notes</th>"
        "</tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n"
        "</table>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _write_html(report: ScanReport, path: Path, *, open_only: bool = False) -> None:
    try:
        path.write_text(report_to_html(report, open_only=open_only), encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write HTML report: %s", exc)
        raise ExportError(f"Could not write HTML report: {exc}") from exc


def report_to_pdf(report: ScanReport, *, open_only: bool = False) -> bytes:
    """Build a simple PDF for a port-scan report."""
    duration = "-" if report.duration is None else f"{report.duration:.2f}s"
    method = "udp_probe" if report.protocol == "udp" else "tcp_connect"
    table_rows = report.open_results if open_only else report.results
    meta = [
        f"Tool: {APP_NAME} {APP_VERSION}",
        f"Target: {report.target}  ({report.resolved_ip})  IPv{report.ip_version}",
        f"Protocol: {report.protocol}    Method: {method}",
        f"Ports: {report.port_label()}    Timeout: {report.timeout}s    Threads: {report.max_workers}",
        "Notes: local reference table, not a vulnerability scan.",
        f"Scan time: {_isoformat(report.started_at) or '-'}    Duration: {duration}",
        (
            f"Scanned: {len(report.results)}    "
            f"Open: {report.count(PortState.OPEN)}    "
            f"Closed: {report.count(PortState.CLOSED)}    "
            f"Timeout: {report.count(PortState.TIMEOUT)}"
        ),
    ]
    if open_only:
        meta.append("Rows: OPEN ports only")
    header = f"{'Port':<6}{'State':<10}{'Proto':<7}{'Service':<12}{'Product':<18}{'Time':<10}Banner"
    rows = [header, "-" * 96]
    for item in table_rows:
        rows.append(
            f"{item.port:<6}"
            f"{item.state.value:<10}"
            f"{item.protocol:<7}"
            f"{(item.service or '-'):<12.12}"
            f"{(item.product_label() or '-'):<18.18}"
            f"{(item.latency_label() or '-'):<10}"
            f"{item.banner or ''}"
        )
    if not table_rows:
        rows.append("(no ports in this report)")
    return build_pdf(
        "Scan report",
        meta=meta,
        rows=rows,
        note="Authorized scan only. Not a vulnerability assessment.",
    )


def discovery_to_pdf(report: DiscoveryReport, *, open_only: bool = False) -> bytes:
    """Build a simple PDF for a TCP ping discovery report."""
    duration = "-" if report.duration is None else f"{report.duration:.2f}s"
    table_rows = report.up_results if open_only else report.results
    meta = [
        f"Tool: {APP_NAME} {APP_VERSION}",
        f"Target: {report.spec}    IPv{report.ip_version}    Method: tcp_ping",
        f"Timeout: {report.timeout}s    Threads: {report.max_workers}",
        f"Scan time: {_isoformat(report.started_at) or '-'}    Duration: {duration}",
        (
            f"Scanned: {len(report.results)}    "
            f"Up: {report.count(HostState.UP)}    "
            f"Down: {report.count(HostState.DOWN)}"
        ),
    ]
    if open_only:
        meta.append("Rows: UP hosts only")
    header = f"{'Host':<42}{'State':<8}{'Evidence':<22}Time"
    rows = [header, "-" * 96]
    for item in table_rows:
        rows.append(
            f"{item.ip:<42}"
            f"{item.state.value:<8}"
            f"{(item.evidence or '-'):<22.22}"
            f"{item.latency_label() or '-'}"
        )
    if not table_rows:
        rows.append("(no hosts in this report)")
    return build_pdf(
        "Host discovery",
        meta=meta,
        rows=rows,
        note="Authorized TCP ping discovery only. Not a vulnerability assessment.",
    )


def _write_pdf(report: ScanReport, path: Path, *, open_only: bool = False) -> None:
    try:
        path.write_bytes(report_to_pdf(report, open_only=open_only))
    except OSError as extra:
        logger.error("Could not write PDF report: %s", extra)
        raise ExportError(f"Could not write PDF report: {extra}") from extra


def _write_discovery_pdf(
    report: DiscoveryReport,
    path: Path,
    *,
    open_only: bool = False,
) -> None:
    try:
        path.write_bytes(discovery_to_pdf(report, open_only=open_only))
    except OSError as extra:
        logger.error("Could not write PDF report: %s", extra)
        raise ExportError(f"Could not write PDF report: {extra}") from extra


def _html_result_row(result: PortScanResult) -> str:
    latency = result.latency_label() or "—"
    service = result.service or "—"
    product = result.product_label() or "—"
    banner = result.banner or "—"
    notes = "; ".join(item.short_label() for item in lookup_advisories(result)) or "—"
    state = result.state.value
    return (
        f'<tr class="{html.escape(state)}">'
        f"<td>{result.port}</td>"
        f"<td>{html.escape(state)}</td>"
        f"<td>{html.escape(result.protocol)}</td>"
        f"<td>{html.escape(service)}</td>"
        f"<td>{html.escape(product)}</td>"
        f"<td>{html.escape(latency)}</td>"
        f"<td class=\"banner\">{html.escape(banner)}</td>"
        f"<td>{html.escape(notes)}</td>"
        "</tr>"
    )


_HTML_CSS = """
body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.45 Segoe UI,system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 20px 48px}
h1{font:600 28px Consolas,ui-monospace,monospace;margin:0 0 16px}
.notice{color:#8b949e;margin:0 0 12px;font-size:12px}
.meta,.summary{display:grid;gap:10px;margin:0 0 18px}
.meta{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.summary{grid-template-columns:repeat(4,minmax(0,1fr))}
.meta div,.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 12px}
.meta span,.stat span{display:block;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.meta strong,.stat strong{font:600 15px Consolas,ui-monospace,monospace}
.stat.open strong{color:#3fb950}
.stat.closed strong{color:#f85149}
.stat.timeout strong{color:#d29922}
.chart{margin:0 0 18px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px}
.chart svg{display:block}
table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #30363d;font:13px Consolas,ui-monospace,monospace}
th{color:#8b949e;font-size:11px;text-transform:uppercase}
tr.OPEN td:nth-child(2),tr.UP td:nth-child(2){color:#3fb950}
tr.CLOSED td:nth-child(2),tr.DOWN td:nth-child(2){color:#f85149}
tr.TIMEOUT td:nth-child(2){color:#d29922}
td.banner{color:#8b949e;word-break:break-word}
td.empty{text-align:center;color:#8b949e}
@media (max-width:700px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
""".replace("\n", "")


def _host_to_dict(result: HostDiscoveryResult) -> dict[str, object]:
    return {
        "ip": result.ip,
        "state": result.state.value,
        "evidence": result.evidence,
        "response_time": _round_time(result.response_time),
    }


def _result_to_dict(result: PortScanResult) -> dict[str, object]:
    return {
        "port": result.port,
        "state": result.state.value,
        "protocol": result.protocol,
        "service": result.service,
        "banner_kind": result.banner_kind,
        "banner_product": result.banner_product,
        "banner_version": result.banner_version,
        "response_time": _round_time(result.response_time),
        "banner": result.banner,
        "timestamp": _isoformat(result.timestamp),
        "advisories": [item.to_dict() for item in lookup_advisories(result)],
    }


def _result_to_csv_row(result: PortScanResult) -> dict[str, object]:
    response = _round_time(result.response_time)
    return {
        "port": result.port,
        "state": result.state.value,
        "protocol": result.protocol,
        "service": result.service or "",
        "product": result.banner_product or "",
        "version": result.banner_version or "",
        "response_time": "" if response is None else response,
        "banner": result.banner or "",
        "refs": advisory_label(result),
    }


def _parse_format(fmt: ExportFormat | str) -> ExportFormat:
    if isinstance(fmt, ExportFormat):
        return fmt
    cleaned = fmt.strip().lower()
    try:
        return ExportFormat(cleaned)
    except ValueError as exc:
        raise ExportError("Format must be json, csv, html, or pdf.") from exc


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _round_time(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 6)

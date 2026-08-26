"""Command-line interface for the TCP connect scanner.

This module parses arguments and prints results. It does not open sockets
itself; scanning stays in the scanner package.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from scanner.constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_MAX_WORKERS,
    DEFAULT_TIMEOUT,
    MAX_INTERVAL,
    MAX_RUNS,
    MAX_WORKERS,
    MIN_INTERVAL,
    PROGRESS_BAR_WIDTH,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    SCAN_PROFILES,
)
from scanner.compare import live_host_delta, open_port_delta
from scanner.discover import discover_hosts
from scanner.models import (
    DiscoveryReport,
    HostDiscoveryResult,
    HostState,
    PortScanResult,
    ScanReport,
)
from scanner.port import PortState
from scanner.scanner import ScannerError, TcpConnectScanner
from scanner.validator import (
    ValidationError,
    parse_ports,
    resolve_scan_profile,
    validate_interval,
    validate_runs,
    validate_target,
)
from utils.exporter import (
    ExportError,
    ExportFormat,
    default_output_path,
    export_report,
    infer_format,
    path_for_run,
)
from utils.logger import setup_logging

_STATE_PREFIX = {
    PortState.OPEN: "[+]",
    PortState.CLOSED: "[-]",
    PortState.TIMEOUT: "[?]",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "TCP connect or UDP probe scanner for authorized systems only. "
            "Scan localhost, your own devices, or hosts you have permission to test."
        ),
        epilog=(
            "examples:\n"
            "  python main.py --gui\n"
            "  python main.py --target ::1 --profile quick\n"
            "  python main.py --target localhost --ipv6 --ports 22,80,443\n"
            "  python main.py --target 127.0.0.1 --ports 22,80,443\n"
            "  python main.py --target 127.0.0.1 --ports 1-1000\n"
            "  python main.py --target localhost --ports 20-100 --threads 50 --timeout 0.5\n"
            "  python main.py --target 127.0.0.1 --ports 1-100 --output reports/scan.json\n"
            "  python main.py --target 127.0.0.1 --ports 22 --format csv\n"
            "  python main.py --target 127.0.0.1 --udp --ports 53,123,161\n"
            "  python main.py --target 127.0.0.1 --discover\n"
            "  python main.py --target 192.168.1.0/24 --discover --show-closed\n"
            "  python main.py --target 127.0.0.1 --profile quick --interval 60 --runs 3\n"
            "\n"
            "Closed and timeout ports are hidden unless --show-closed is set. "
            "Too many threads can slow this machine and inflate timeouts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Open the Tkinter interface instead of running a CLI scan",
    )
    parser.add_argument(
        "--target",
        "-t",
        help="IPv4, IPv6, hostname, or IPv4 CIDR with --discover (required for CLI)",
    )
    parser.add_argument(
        "--ports",
        "-p",
        help="Port list or range, e.g. 80, 1-1000, or 22,80,443",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(SCAN_PROFILES),
        help="Scan a named port set: quick or common (instead of --ports)",
    )
    parser.add_argument(
        "--timeout",
        default=str(DEFAULT_TIMEOUT),
        help=f"Connect timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--threads",
        default=str(DEFAULT_MAX_WORKERS),
        help=f"Max worker threads, 1-{MAX_WORKERS} (default: {DEFAULT_MAX_WORKERS})",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="Resolve hostnames to IPv6 (AAAA). Literals still use their own family",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="UDP probe instead of TCP connect (silence is TIMEOUT / open|filtered)",
    )
    parser.add_argument(
        "--discover",
        "-d",
        action="store_true",
        help="TCP ping hosts instead of a port scan (IPv4 CIDR /24 or smaller)",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Print CLOSED/TIMEOUT ports, or DOWN hosts during discovery",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Report file path. Defaults to reports/scan_<timestamp>.<format> when --format is set",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=[item.value for item in ExportFormat],
        help="Report format: json, csv, or html (default: json when exporting)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print DEBUG log lines to the console (the log file always stores DEBUG)",
    )
    parser.add_argument(
        "--interval",
        help=(
            f"Seconds to wait between authorized repeats "
            f"({MIN_INTERVAL}-{MAX_INTERVAL}; requires staying in the foreground)"
        ),
    )
    parser.add_argument(
        "--runs",
        help=(
            f"How many times to scan when --interval is set, 1-{MAX_RUNS} "
            "(omit to repeat until Ctrl+C)"
        ),
    )
    return parser


def format_result(result: PortScanResult) -> str:
    prefix = _STATE_PREFIX[result.state]
    parts = [prefix, str(result.port), result.state.value]
    if result.service:
        parts.append(result.service)
    product = result.product_label()
    if product:
        parts.append(product)
    latency = result.latency_label()
    if latency:
        parts.append(latency)
    if result.banner:
        parts.append(result.banner)
    return " ".join(parts)


def print_report(report: ScanReport, *, show_closed: bool = False) -> None:
    scanned = len(report.results)
    open_count = report.count(PortState.OPEN)
    closed_count = report.count(PortState.CLOSED)
    timeout_count = report.count(PortState.TIMEOUT)

    print(f"Target: {report.target} ({report.resolved_ip})")
    print(f"Protocol: {report.protocol}")
    print(f"Ports:  {report.port_label()}")
    print(f"Timeout: {report.timeout}s")
    print(f"Threads: {report.max_workers}")
    if report.duration is not None:
        print(f"Duration: {report.duration:.2f}s")
    print(
        f"Scanned: {scanned} ports "
        f"(open={open_count}, closed={closed_count}, timeout={timeout_count})"
    )
    print()

    visible = report.results if show_closed else report.open_results
    if not visible:
        print("No open ports found." if not show_closed else "No ports to display.")
        return

    for result in visible:
        print(format_result(result))

    print()
    print(f"Found: {open_count} open port(s)")


def format_host_result(result: HostDiscoveryResult) -> str:
    prefix = "[+]" if result.state is HostState.UP else "[?]"
    parts = [prefix, result.ip, result.state.value]
    if result.evidence:
        parts.append(result.evidence)
    latency = result.latency_label()
    if latency:
        parts.append(latency)
    return " ".join(parts)


def print_discovery_report(report: DiscoveryReport, *, show_closed: bool = False) -> None:
    up_count = report.count(HostState.UP)
    down_count = report.count(HostState.DOWN)
    print(f"Target: {report.spec}")
    print(f"Method: tcp_ping (ports 80,443,22,445)")
    print(f"Timeout: {report.timeout}s")
    print(f"Threads: {report.max_workers}")
    if report.duration is not None:
        print(f"Duration: {report.duration:.2f}s")
    print(f"Hosts:  {len(report.results)} (up={up_count}, down={down_count})")
    print()

    visible = report.results if show_closed else report.up_results
    if not visible:
        print("No live hosts found." if not show_closed else "No hosts to display.")
        return

    for result in visible:
        print(format_host_result(result))

    print()
    print(f"Live: {up_count} host(s)")


def render_progress_bar(completed: int, total: int, width: int = PROGRESS_BAR_WIDTH) -> str:
    """Return a single-line ASCII progress bar, e.g. [########........]  50%."""
    if total <= 0:
        filled = width
        percent = 100
    else:
        ratio = min(max(completed / total, 0.0), 1.0)
        filled = min(width, int(round(ratio * width)))
        percent = int(round(ratio * 100))
    return f"[{'#' * filled}{'.' * (width - filled)}] {percent:3d}%"


def _print_progress(completed: int, total: int, open_count: int) -> None:
    bar = render_progress_bar(completed, total)
    line = f"\rProgress: {bar}  Found: {open_count} open ports"
    print(line, end="", file=sys.stderr, flush=True)


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        if args.interval or args.runs:
            parser.error("do not combine --gui with --interval or --runs")
        from gui.app import run_app

        return run_app()

    if not args.target:
        parser.error("--target is required unless --gui is used")
    if args.discover and args.udp:
        parser.error("host discovery uses TCP ping; do not combine --discover with --udp")
    if args.discover and (args.ports or args.profile):
        parser.error("do not combine --discover with --ports or --profile")
    if args.ports and args.profile:
        parser.error("use either --ports or --profile, not both")
    if not args.discover and not args.ports and not args.profile:
        parser.error("--ports, --profile, or --discover is required unless --gui is used")
    if args.runs and not args.interval:
        parser.error("--runs requires --interval")

    logger = setup_logging(verbose=args.verbose)
    try:
        interval = validate_interval(args.interval) if args.interval else None
        runs = validate_runs(args.runs) if args.runs else None
    except ValidationError as exc:
        return _cli_error(logger, exc)

    if interval is None:
        if args.discover:
            code, _report = _run_discovery(args, logger)
            return code
        code, _report = _run_scan(args, logger)
        return code
    return _run_scheduled(args, logger, interval, runs)


def _run_scheduled(
    args: argparse.Namespace,
    logger: logging.Logger,
    interval: float,
    runs: int | None,
) -> int:
    print("Use this tool only on systems you are authorized to test.")
    print(
        "Repeating an authorized scan in this process — not a background service, "
        "cron job, or persistence mechanism."
    )
    if runs is None:
        print(f"Interval: {interval}s  (Ctrl+C to stop)")
    else:
        print(f"Interval: {interval}s  Runs: {runs}")
    sys.stdout.flush()

    previous: ScanReport | DiscoveryReport | None = None
    run_index = 0
    while True:
        run_index += 1
        if runs is not None:
            print(f"--- Run {run_index}/{runs} ---")
        else:
            print(f"--- Run {run_index} ---")
        sys.stdout.flush()
        if args.discover:
            code, report = _run_discovery(args, logger, run_index=run_index, announce=False)
        else:
            code, report = _run_scan(args, logger, run_index=run_index, announce=False)
        if code != 0 or report is None:
            return code
        if previous is not None:
            _print_delta(previous, report)
        previous = report
        if runs is not None and run_index >= runs:
            return 0
        print(
            f"Waiting {interval:g}s until next run (Ctrl+C to stop).",
            file=sys.stderr,
        )
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            logger.warning("Schedule interrupted.")
            print("Scan interrupted.", file=sys.stderr)
            return 130


def _print_delta(
    previous: ScanReport | DiscoveryReport,
    current: ScanReport | DiscoveryReport,
) -> None:
    print("Changes since last run:")
    if isinstance(previous, DiscoveryReport) and isinstance(current, DiscoveryReport):
        appeared, disappeared = live_host_delta(previous, current)
        if not appeared and not disappeared:
            print("  (none)")
            return
        for host in appeared:
            print(f"  [+] {host} newly up")
        for host in disappeared:
            print(f"  [-] {host} no longer up")
        return
    if isinstance(previous, ScanReport) and isinstance(current, ScanReport):
        appeared, disappeared = open_port_delta(previous, current)
        if not appeared and not disappeared:
            print("  (none)")
            return
        for port in appeared:
            print(f"  [+] {port} newly open")
        for port in disappeared:
            print(f"  [-] {port} no longer open")
        return
    print("  (none)")


def _run_scan(
    args: argparse.Namespace,
    logger: logging.Logger,
    *,
    run_index: int = 1,
    announce: bool = True,
) -> tuple[int, ScanReport | None]:
    protocol = PROTOCOL_UDP if args.udp else PROTOCOL_TCP

    try:
        target = validate_target(args.target)
        port_list = (
            resolve_scan_profile(args.profile, protocol=protocol)
            if args.profile
            else parse_ports(args.ports)
        )
    except ValidationError as exc:
        return _cli_error(logger, exc), None

    if announce:
        print("Use this tool only on systems you are authorized to test.")
    print(f"Scanning {target}...")
    sys.stdout.flush()

    open_found = 0

    def on_progress(completed: int, total: int, result: PortScanResult) -> None:
        nonlocal open_found
        if result.state is PortState.OPEN:
            open_found += 1
        if not args.verbose:
            _print_progress(completed, total, open_found)

    try:
        report = TcpConnectScanner().scan(
            target,
            timeout=args.timeout,
            max_workers=args.threads,
            on_progress=on_progress,
            ports=port_list,
            prefer_ipv6=args.ipv6,
            protocol=protocol,
        )
    except ValidationError as exc:
        _end_progress_line(args.verbose)
        return _cli_error(logger, exc), None
    except ScannerError as exc:
        _end_progress_line(args.verbose)
        return _cli_error(logger, exc), None
    except KeyboardInterrupt:
        _end_progress_line(args.verbose)
        logger.warning("Scan interrupted.")
        print("Scan interrupted.", file=sys.stderr)
        return 130, None

    _end_progress_line(args.verbose)
    print_report(report, show_closed=args.show_closed)

    try:
        saved = _maybe_export(report, args.output, args.format, run_index=run_index)
    except ExportError as exc:
        return _cli_error(logger, exc), None

    if saved is not None:
        print(f"Report saved: {saved}")
    return 0, report


def _run_discovery(
    args: argparse.Namespace,
    logger: logging.Logger,
    *,
    run_index: int = 1,
    announce: bool = True,
) -> tuple[int, DiscoveryReport | None]:
    if announce:
        print("Use this tool only on systems you are authorized to test.")
    print(f"Discovering {args.target}...")
    sys.stdout.flush()

    live_found = 0

    def on_progress(completed: int, total: int, result: HostDiscoveryResult) -> None:
        nonlocal live_found
        if result.state is HostState.UP:
            live_found += 1
        if not args.verbose:
            _print_discovery_progress(completed, total, live_found)

    try:
        report = discover_hosts(
            args.target,
            timeout=args.timeout,
            max_workers=args.threads,
            on_progress=on_progress,
            prefer_ipv6=args.ipv6,
        )
    except ValidationError as exc:
        _end_progress_line(args.verbose)
        return _cli_error(logger, exc), None
    except ScannerError as exc:
        _end_progress_line(args.verbose)
        return _cli_error(logger, exc), None
    except KeyboardInterrupt:
        _end_progress_line(args.verbose)
        logger.warning("Discovery interrupted.")
        print("Scan interrupted.", file=sys.stderr)
        return 130, None

    _end_progress_line(args.verbose)
    print_discovery_report(report, show_closed=args.show_closed)

    try:
        saved = _maybe_export(report, args.output, args.format, run_index=run_index)
    except ExportError as exc:
        return _cli_error(logger, exc), None

    if saved is not None:
        print(f"Report saved: {saved}")
    return 0, report


def _print_discovery_progress(completed: int, total: int, live_count: int) -> None:
    bar = render_progress_bar(completed, total)
    line = f"\rProgress: {bar}  Found: {live_count} live hosts"
    print(line, end="", file=sys.stderr, flush=True)


def _maybe_export(
    report: ScanReport | DiscoveryReport,
    output: str | None,
    fmt: str | None,
    *,
    run_index: int = 1,
) -> Path | None:
    if output is None and fmt is None:
        return None

    format_name = _resolve_format(output, fmt)
    path = Path(output) if output else default_output_path(format_name)
    path = path_for_run(path, run_index)
    return export_report(report, path, format_name)


def _resolve_format(output: str | None, fmt: str | None) -> ExportFormat:
    if fmt:
        return ExportFormat(fmt)
    if output:
        inferred = infer_format(output)
        if inferred is not None:
            return inferred
    return ExportFormat.JSON


def _end_progress_line(verbose: bool) -> None:
    if not verbose:
        print(file=sys.stderr)


def _cli_error(logger: logging.Logger, exc: BaseException) -> int:
    logger.error("%s", exc)
    print(f"Error: {exc}", file=sys.stderr)
    return 1

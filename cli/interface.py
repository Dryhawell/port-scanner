"""Command-line interface for the TCP connect scanner.

This module parses arguments and prints results. It does not open sockets
itself; scanning stays in the scanner package.
"""

from __future__ import annotations

import argparse
import sys

from scanner.constants import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT, MAX_WORKERS
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.scanner import ScannerError, TcpConnectScanner
from scanner.validator import ValidationError, parse_port_range, validate_target

_STATE_PREFIX = {
    PortState.OPEN: "[+]",
    PortState.CLOSED: "[-]",
    PortState.TIMEOUT: "[?]",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "TCP connect port scanner for authorized systems only. "
            "Scan localhost, your own devices, or hosts you have permission to test."
        ),
        epilog=(
            "examples:\n"
            "  python main.py --target 127.0.0.1 --ports 1-1000\n"
            "  python main.py --target localhost --ports 20-100 --threads 50 --timeout 0.5\n"
            "\n"
            "Closed and timeout ports are hidden unless --show-closed is set. "
            "Too many threads can slow this machine and inflate timeouts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="IPv4 address or hostname to scan",
    )
    parser.add_argument(
        "--ports",
        "-p",
        required=True,
        help="Single port or inclusive range, e.g. 80 or 1-1000",
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
        "--show-closed",
        action="store_true",
        help="Print CLOSED and TIMEOUT ports as well as OPEN ports",
    )
    return parser


def format_result(result: PortScanResult) -> str:
    prefix = _STATE_PREFIX[result.state]
    parts = [prefix, str(result.port), result.state.value]
    if result.service:
        parts.append(result.service)
    if result.response_time is not None:
        parts.append(f"{result.response_time * 1000:.1f}ms")
    if result.banner:
        parts.append(result.banner)
    return " ".join(parts)


def print_report(report: ScanReport, *, show_closed: bool = False) -> None:
    scanned = len(report.results)
    open_count = report.count(PortState.OPEN)
    closed_count = report.count(PortState.CLOSED)
    timeout_count = report.count(PortState.TIMEOUT)

    print(f"Target: {report.target} ({report.resolved_ip})")
    print(f"Ports:  {report.start_port}-{report.end_port}")
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
        if show_closed or result.state is PortState.OPEN:
            print(format_result(result))

    print()
    print(f"Found: {open_count} open port(s)")


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        target = validate_target(args.target)
        start_port, end_port = parse_port_range(args.ports)
    except ValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print("Use this tool only on systems you are authorized to test.")
    print(f"Scanning {target}...")

    try:
        report = TcpConnectScanner().scan(
            target,
            start_port,
            end_port,
            args.timeout,
            args.threads,
        )
    except ValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ScannerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130

    print_report(report, show_closed=args.show_closed)
    return 0

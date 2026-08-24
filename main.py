"""Port Scanner giris noktasi.

PHASE 5: eszamanli TCP connect tarama + temel servis tespiti.
Tam CLI (argparse) PHASE 8'de gelecek.
"""

from __future__ import annotations

import sys

from scanner.constants import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.scanner import ScannerError, TcpConnectScanner
from scanner.validator import ValidationError

USAGE = """Port Scanner - authorized systems only.

Usage:
  python main.py <target> <start-port> <end-port> [timeout] [threads]

Examples:
  python main.py 127.0.0.1 1 100
  python main.py localhost 20 100 0.5
  python main.py 127.0.0.1 1 1000 0.5 50

Closed and timeout ports are hidden by default.
Too many threads can slow this machine and inflate timeouts.
"""


def format_open_result(result: PortScanResult) -> str:
    if result.service:
        return f"[+] {result.port} {result.state.value} {result.service}"
    return f"[+] {result.port} {result.state.value}"


def print_report(report: ScanReport) -> None:
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

    open_results = report.open_results
    if not open_results:
        print("No open ports found.")
        return

    for result in open_results:
        print(format_open_result(result))
    print()
    print(f"Found: {len(open_results)} open port(s)")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in {3, 4, 5}:
        print(USAGE)
        return 1

    target, start_port, end_port = args[0], args[1], args[2]
    timeout: float | str = args[3] if len(args) >= 4 else DEFAULT_TIMEOUT
    threads: int | str = args[4] if len(args) == 5 else DEFAULT_MAX_WORKERS

    print("Use this tool only on systems you are authorized to test.")
    print(f"Scanning {target}...")

    try:
        report = TcpConnectScanner().scan(
            target,
            start_port,
            end_port,
            timeout,
            threads,
        )
    except ValidationError as exc:
        print(f"Error: {exc}")
        return 1
    except ScannerError as exc:
        print(f"Error: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130

    print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

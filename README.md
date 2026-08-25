# Port Scanner

Version **1.0.0** — an educational TCP connect scanner for **authorized** hosts. It probes a port range on an IPv4 address or hostname, reports OPEN / CLOSED / TIMEOUT, and can attach a service-name hint, connection time, and a passive banner.

CLI and GUI share the same scan engine. The tool is built with Python 3.12+ and the standard library (Tkinter for the GUI, pytest for tests).

## Overview

A TCP port is a numbered endpoint on a host. This scanner acts as a client: for each port it attempts a full TCP handshake. If the handshake completes, the port is **OPEN**. If the host refuses the connection, it is **CLOSED**. If nothing useful comes back before the timeout, it is **TIMEOUT** (which may be a drop, a filter, or a slow host — not a certain “filtered” verdict).

Use it to learn sockets, timeouts, concurrency, and how service banners look on systems you are allowed to test.

## Features

- IPv4 address and hostname targets (hostname syntax check, then DNS at scan time)
- Inclusive port range `1-65535` with input validation
- Concurrent TCP connect scan via `ThreadPoolExecutor` (default 50 workers, max 200)
- OPEN / CLOSED / TIMEOUT classification from `connect_ex` / `SO_ERROR`
- Service-name hint with `socket.getservbyport()` (IANA/OS table, not proof of the app)
- Passive banner grab (read only; no HTTP/SMTP probes)
- Per-port latency with `time.perf_counter()`
- CLI (`argparse`) and dark-themed Tkinter GUI
- JSON and CSV reports under `reports/`
- File logging to `logs/scanner.log`
- Unit tests that mock sockets and DNS (no internet required)

## Technologies

| Area | Choice |
|---|---|
| Language | Python 3.12+ |
| Sockets | `socket` |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| CLI | `argparse` |
| GUI | Tkinter / `ttk` |
| Reports | `json`, `csv` |
| Logging | `logging` |
| Tests | `pytest` |

Runtime scanning has **no third-party dependencies**. Install pytest only to run tests.

## Installation

```powershell
git clone https://github.com/Dryhawell/port-scanner.git
cd port-scanner
python -m pip install -r requirements.txt
```

`requirements.txt` currently pins pytest. Tkinter ships with most CPython Windows/macOS builds.

## Usage

```powershell
python main.py --help
python main.py --version
python main.py --gui
python main.py --target 127.0.0.1 --ports 1-1000
```

| Flag | Meaning |
|---|---|
| `--target` / `-t` | IPv4 or hostname (required for CLI) |
| `--ports` / `-p` | `80` or `1-1000` (required for CLI) |
| `--timeout` | Connect timeout in seconds (default `0.5`) |
| `--threads` | Max workers, `1-200` (default `50`) |
| `--show-closed` | Print CLOSED and TIMEOUT as well as OPEN |
| `--output` / `-o` | Report path |
| `--format` / `-f` | `json` or `csv` |
| `--verbose` / `-v` | DEBUG lines on the console |
| `--gui` | Open the Tkinter UI |

Closed and timeout ports are hidden on the CLI unless `--show-closed` is set. They are still stored in reports.

## CLI Examples

```powershell
python main.py --target 127.0.0.1 --ports 1-1000
python main.py --target localhost --ports 20-100 --threads 50 --timeout 0.5
python main.py --target 127.0.0.1 --ports 1-100 --output reports/scan.json
python main.py --target 127.0.0.1 --ports 22 --format csv
python main.py -t 127.0.0.1 -p 1-80 --show-closed --verbose
```

## GUI

```powershell
python main.py --gui
```

Fields: target, start/end port, timeout, threads, **START SCAN**. Below: status, open-port count, progress bar, result table (Port, State, Protocol, Service, Response Time, Banner).

The scan runs on a **background thread**. Progress events go through a `queue.Queue`; only the Tk main thread updates widgets, so the window should stay responsive.

## Example Output

```text
Use this tool only on systems you are authorized to test.
Scanning 127.0.0.1...
Target: 127.0.0.1 (127.0.0.1)
Ports:  1-1000
Timeout: 0.5s
Threads: 50
Duration: 1.25s
Scanned: 1000 ports (open=3, closed=0, timeout=997)

[+] 22 OPEN ssh 12.3ms SSH-2.0-OpenSSH_9.2
[+] 80 OPEN http 4.1ms
[+] 443 OPEN https 8.0ms

Found: 3 open port(s)
Report saved: reports/scan_2026-08-25_1710.json
```

On some Windows hosts, unused localhost ports time out instead of returning RST. That is a TIMEOUT, not a scanner bug.

## Architecture

```text
main.py                 entry point
cli/interface.py        argparse, console report
gui/app.py              Tkinter UI + background worker
scanner/
  validator.py          target / port / timeout / threads
  scanner.py            TCP connect engine
  port.py               OPEN / CLOSED / TIMEOUT
  models.py             PortScanResult, ScanReport
  service.py            getservbyport hint
  banner.py             passive recv + sanitize
utils/
  exporter.py           JSON / CSV
  logger.py             logs/scanner.log
tests/                  pytest
reports/                generated reports (gitignored)
logs/                   scanner.log (gitignored)
```

Interfaces never open sockets themselves. They call `TcpConnectScanner`.

## How It Works

1. Validate target, port range, timeout, and thread count.
2. Resolve hostname to IPv4 with `socket.getaddrinfo` (`AF_INET` only).
3. Probe each port concurrently (bounded thread pool).
4. Map the connect result to OPEN / CLOSED / TIMEOUT.
5. For OPEN ports, look up a service name and optionally read a banner.
6. Sort results by port number and print, export, or show in the GUI.

## TCP Connect Scanning

The probe uses a non-blocking TCP socket and `connect_ex((ip, port))`:

- **0** — handshake completed → **OPEN**
- Connection refused (e.g. `ECONNREFUSED` / `WSAECONNREFUSED`) → **CLOSED**
- Timeout / unreachable → **TIMEOUT**

On Windows, `connect_ex` often returns `WSAEWOULDBLOCK` (10035) before the handshake finishes. That is **in progress**, not CLOSED. The scanner waits with `select` and then reads `SO_ERROR`.

`connect()` would raise on every closed port. `connect_ex()` returns an errno instead, which is a better fit for a scanner. This is a **full connect scan**, not SYN-only, not stealth, and not a firewall bypass.

TIMEOUT is not a reliable IDS/firewall fingerprint.

## Service Detection

Open ports get a name from `socket.getservbyport()`, which reads the OS services table (on Windows, `drivers\etc\services`).

Examples: `22 → ssh`, `80 → http`, `443 → https`, `25 → smtp`, `53 → domain`.

A name is a **convention**, not proof that that daemon is running. Anything can listen on port 80.

## Performance

Port scanning is I/O-bound: workers wait on the network, they do not burn CPU. `ThreadPoolExecutor` overlaps those waits. Too many threads can slow this machine, load the target, and increase timeouts. The cap is 200.

Worker count is `min(requested, port_count)`.

## Testing

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

Tests cover validation, connect-code mapping, mocked probes, mocked DNS, and service lookup. They do not scan the public internet.

## Limitations

- IPv4 / TCP only (no UDP, no IPv6)
- Connect scan only (no SYN/FIN/Xmas, no spoofing)
- Service names are table lookups, not protocol fingerprinting
- Banners are passive; HTTP/TLS often send nothing until the client speaks
- TIMEOUT vs CLOSED depends on the OS and firewall
- One target per run; no host discovery

## Authorized Use

This project is for:

- `localhost`
- devices you own
- lab or test systems you have **permission** to scan

Do not scan networks or hosts without authorization. Unauthorized scanning can be illegal.

Out of scope on purpose: stealth scanning, IDS/IPS bypass, firewall evasion, source spoofing, anonymization, and attack automation.

Logs and reports may contain IP addresses, port numbers, and banners. Do not log passwords; this tool does not ask for them.

## Future Improvements

- UDP scanning
- IPv6 support
- Advanced service detection
- Better banner parsing
- Host discovery
- Scan profiles
- Scheduled authorized scans
- HTML / PDF reports
- Scan history in a database
- Visualization
- Optional vulnerability-information lookup (reference data only)

## License

MIT. See [LICENSE](LICENSE).

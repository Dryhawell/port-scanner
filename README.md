# Port Scanner

Version **1.6.0** — an educational TCP connect / UDP probe scanner for **authorized** hosts. It probes a port range, a comma-separated list, or a named profile on an IPv4/IPv6 address or hostname, reports OPEN / CLOSED / TIMEOUT, and can attach a service-name hint, connection time, and a parsed passive banner.

CLI and GUI share the same scan engine. The tool is built with Python 3.12+ and the standard library (Tkinter for the GUI, pytest for tests).

## Overview

A TCP port is a numbered endpoint on a host. This scanner can act as a TCP client (full handshake) or send a tiny UDP datagram. TCP **OPEN** means the handshake completed. TCP **CLOSED** means the host refused. UDP **OPEN** means a datagram came back. UDP **CLOSED** means ICMP port-unreachable. In both modes, **TIMEOUT** means nothing useful arrived in time — for UDP that is often open|filtered, not proof the port is down.

Use it to learn sockets, timeouts, concurrency, and how service banners look on systems you are allowed to test.

## Features

- IPv4, IPv6, and hostname targets (hostname syntax check, then DNS at scan time)
- Inclusive port range `1-65535`, comma-separated lists (`22,80,443`), and named profiles (`quick`, `common`)
- Concurrent TCP connect or UDP probe scan via `ThreadPoolExecutor` (default 50 workers, max 200)
- OPEN / CLOSED / TIMEOUT from TCP `connect_ex` / `SO_ERROR`, or from UDP reply vs ICMP unreachable
- Service-name hint with `socket.getservbyport()` (IANA/OS table, not proof of the app)
- Passive banner grab (read only; no HTTP/SMTP probes) with light parsing (SSH, FTP, SMTP, POP3, IMAP)
- Per-port latency with `time.perf_counter()`
- CLI (`argparse`) with a live progress bar, plus a dark-themed Tkinter GUI
- JSON, CSV, and self-contained HTML reports under `reports/`
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
| Reports | `json`, `csv`, HTML |
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
python main.py --target 127.0.0.1 --ports 22,80,443
python main.py --target 127.0.0.1 --profile quick
python main.py --target ::1 --profile quick
python main.py --target localhost --ipv6 --ports 22,80,443
python main.py --target 127.0.0.1 --udp --profile quick --show-closed
```

| Flag | Meaning |
|---|---|
| `--target` / `-t` | IPv4, IPv6, or hostname (required for CLI) |
| `--ports` / `-p` | `80`, `1-1000`, or `22,80,443` (required unless `--profile`) |
| `--profile` | Named port set: `quick` or `common` (instead of `--ports`) |
| `--timeout` | Connect timeout in seconds (default `0.5`) |
| `--threads` | Max workers, `1-200` (default `50`) |
| `--ipv6` | Resolve hostnames to IPv6 (AAAA). Literals keep their own family |
| `--udp` | UDP probe instead of TCP connect |
| `--show-closed` | Print CLOSED and TIMEOUT as well as OPEN |
| `--output` / `-o` | Report path |
| `--format` / `-f` | `json`, `csv`, or `html` |
| `--verbose` / `-v` | DEBUG lines on the console |
| `--gui` | Open the Tkinter UI |

Closed and timeout ports are hidden on the CLI unless `--show-closed` is set. They are still stored in reports. During a CLI scan, stderr shows a live ASCII progress bar (`Progress: [########........]  50%  Found: N open ports`). `--verbose` skips the bar so DEBUG lines stay readable.

## CLI Examples

```powershell
python main.py --target 127.0.0.1 --ports 1-1000
python main.py --target 127.0.0.1 --ports 22,80,443
python main.py --target 127.0.0.1 --profile quick
python main.py --target ::1 --profile quick
python main.py --target localhost --ipv6 --ports 22,80,443
python main.py --target 127.0.0.1 --profile common --show-closed
python main.py --target localhost --ports 20-100 --threads 50 --timeout 0.5
python main.py --target 127.0.0.1 --ports 1-100 --output reports/scan.json
python main.py --target 127.0.0.1 --ports 22 --format csv
python main.py --target 127.0.0.1 --profile quick --format html
python main.py --target 127.0.0.1 --udp --ports 53,123,161 --show-closed
python main.py --target 127.0.0.1 --udp --profile quick --show-closed
python main.py -t 127.0.0.1 -p 1-80 --show-closed --verbose
```

## GUI

```powershell
python main.py --gui
```

Fields: target, start/end port, timeout, threads, profile (Custom / Quick / Common), **Protocol** (TCP / UDP), **Prefer IPv6**, **START SCAN**. Below: status, open-port count, progress bar, result table (Port, State, Protocol, Service, Product, Response Time, Banner). Quick and Common ignore the start/end fields; UDP uses a different port set (DNS, NTP, SNMP, …). After a scan finishes, **SAVE HTML** writes a self-contained report you can open in a browser. IPv4/IPv6 literals pick their family; **Prefer IPv6** only changes hostname resolution (AAAA).

The scan runs on a **background thread**. Progress events go through a `queue.Queue`; only the Tk main thread updates widgets, so the window should stay responsive.

## Example Output

```text
Use this tool only on systems you are authorized to test.
Scanning 127.0.0.1...
Target: 127.0.0.1 (127.0.0.1)
Protocol: tcp
Ports:  1-1000
Timeout: 0.5s
Threads: 50
Duration: 1.25s
Scanned: 1000 ports (open=3, closed=0, timeout=997)

[+] 22 OPEN ssh OpenSSH 9.2 12.3ms SSH-2.0-OpenSSH_9.2
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
  validator.py          target / ports / profiles / timeout / threads
  scanner.py            TCP connect engine
  port.py               OPEN / CLOSED / TIMEOUT
  models.py             PortScanResult, ScanReport
  service.py            getservbyport hint
  banner.py             passive recv, sanitize, parse
utils/
  exporter.py           JSON / CSV / HTML
  logger.py             logs/scanner.log
tests/                  pytest
reports/                generated reports (gitignored)
logs/                   scanner.log (gitignored)
```

Interfaces never open sockets themselves. They call `TcpConnectScanner`.

## How It Works

1. Validate target, ports (range, list, or profile), timeout, and thread count.
2. Resolve hostname to IPv4 (A) or IPv6 (AAAA) with `socket.getaddrinfo`. Literals skip DNS. Dual-stack names prefer IPv4 unless `--ipv6` / Prefer IPv6.
3. Probe each port concurrently (TCP connect or UDP datagram, bounded thread pool).
4. Map the outcome to OPEN / CLOSED / TIMEOUT.
5. For OPEN TCP ports, look up a service name, read a banner if the peer speaks first, and parse that greeting. UDP OPEN ports get a table name if the OS knows one; there is no TCP-style banner parse.
6. Sort results by port number and print, export (JSON, CSV, or HTML), or show in the GUI.

## TCP Connect Scanning

The probe uses a non-blocking TCP socket and `connect_ex`. IPv4 uses `(ip, port)`; IPv6 uses `(ip, port, 0, 0)` on an `AF_INET6` socket:

- **0** — handshake completed → **OPEN**
- Connection refused (e.g. `ECONNREFUSED` / `WSAECONNREFUSED`) → **CLOSED**
- Timeout / unreachable → **TIMEOUT**

On Windows, `connect_ex` often returns `WSAEWOULDBLOCK` (10035) before the handshake finishes. That is **in progress**, not CLOSED. The scanner waits with `select` and then reads `SO_ERROR`.

`connect()` would raise on every closed port. `connect_ex()` returns an errno instead, which is a better fit for a scanner. This is a **full connect scan**, not SYN-only, not stealth, and not a firewall bypass.

TIMEOUT is not a reliable IDS/firewall fingerprint.

## UDP Probing

UDP has no handshake. The scanner connects a datagram socket (so ICMP errors attach to it), sends a single null byte (`\x00`), and waits. No DNS/NTP/SNMP payload is crafted, and no raw sockets are required.

- A UDP reply → **OPEN**
- ICMP port-unreachable, seen as `ECONNREFUSED` / `WSAECONNRESET` (10054) → **CLOSED**
- Silence until timeout → **TIMEOUT** (open, filtered, dropped, or ICMP rate-limited)

`--profile quick` / `common` under `--udp` uses UDP-oriented ports (53, 123, 161, …), not the TCP web/SSH set. Many UDP services stay silent unless you speak their protocol, so `--show-closed` is useful. Too many parallel UDP probes can make a host rate-limit ICMP and inflate TIMEOUT.

This is not a stealth scan and not an amplification attack.

## Service Detection

Open ports get a name from `socket.getservbyport()`, which reads the OS services table (on Windows, `drivers\etc\services`).

Examples: `22 → ssh`, `80 → http`, `443 → https`, `25 → smtp`, `53 → domain`.

A name is a **convention**, not proof that that daemon is running. Anything can listen on port 80.

## Banner Parsing

After the TCP handshake, the scanner **only reads**. It does not send `GET /`, `EHLO`, or a TLS ClientHello. SSH, FTP, SMTP, POP3, and IMAP often greet first; HTTP and TLS usually do not.

`parse_banner()` then classifies that text:

| Greeting | Kind | Example product |
|---|---|---|
| `SSH-2.0-OpenSSH_9.2` | ssh | OpenSSH 9.2 |
| `220 (vsFTPd 3.0.3)` | ftp | vsftpd 3.0.3 |
| `220 host ESMTP Postfix` | smtp | Postfix |
| `+OK Dovecot ready` | pop3 | Dovecot |
| `* OK ... Dovecot ready` | imap | Dovecot |

A 220 line without FTP or SMTP keywords is left unclassified. The raw banner stays in reports as evidence. If the OS services table has no name, the banner kind may fill `service`; a table name is never overwritten, so a mismatch (port 80 + SSH banner) stays visible.

This is not fingerprinting and not a CVE lookup.

## Performance

Port scanning is I/O-bound: workers wait on the network, they do not burn CPU. `ThreadPoolExecutor` overlaps those waits. Too many threads can slow this machine, load the target, and increase timeouts. The cap is 200.

Worker count is `min(requested, port_count)`.

## Testing

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

Tests cover validation, connect-code mapping, mocked TCP/UDP probes, mocked DNS, service lookup, and banner parsing. They do not scan the public internet.

## Limitations

- One address family per run (IPv4 or IPv6, not both at once)
- One protocol per run (TCP or UDP, not both at once)
- IPv6 zone identifiers (`fe80::1%eth0`) are not supported
- No SYN/FIN/Xmas, no spoofing, no raw ICMP sockets
- UDP TIMEOUT is open|filtered, not a certain closed verdict
- UDP payload is a null byte, not a protocol handshake
- Service names are table lookups, not protocol fingerprinting
- Banner parsing is heuristic and passive; HTTP/TLS often send nothing until the client speaks
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

- Advanced service detection
- Host discovery
- Scheduled authorized scans
- PDF reports
- Scan history in a database
- Visualization
- Optional vulnerability-information lookup (reference data only)

## License

MIT. See [LICENSE](LICENSE).

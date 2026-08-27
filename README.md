# Port Scanner

[![Tests](https://github.com/Dryhawell/port-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Dryhawell/port-scanner/actions/workflows/tests.yml)

Version **1.17.0** — an educational TCP connect / UDP probe scanner for **authorized** hosts. It can TCP-ping a host or a small IPv4 CIDR, then probe a port range, a comma-separated list, or a named profile on an IPv4/IPv6 address or hostname. `--exclude` drops ports from that list (`80`, `80,443`, or `1-1023`). A UTF-8 `--target-file` lists up to 256 authorized hosts and scans them one after another (not a parallel sweep). It reports OPEN / CLOSED / TIMEOUT (and UP / DOWN for discovery), and can attach a service-name hint, connection time, a parsed passive banner, and a local reference note on some open ports. Repeats stay in the foreground (`--interval` / `--runs`). Completed runs are stored in a local sqlite file (`reports/history.db`) and a new run is compared to the last stored scan of the same target. Counts are drawn as ASCII / SVG / Canvas bars (no matplotlib).

CLI and GUI share the same scan engine. The tool is built with Python 3.12+ and the standard library (Tkinter for the GUI, pytest for tests).

## Overview

A TCP port is a numbered endpoint on a host. This scanner can act as a TCP client (full handshake) or send a tiny UDP datagram. TCP **OPEN** means the handshake completed. TCP **CLOSED** means the host refused. UDP **OPEN** means a datagram came back. UDP **CLOSED** means ICMP port-unreachable. In both modes, **TIMEOUT** means nothing useful arrived in time — for UDP that is often open|filtered, not proof the port is down.

Host discovery is a **TCP ping**, not ICMP. Ports **80, 443, 22, 445** are probed in that order. **OPEN** or **CLOSED** means the stack answered, so the host is **UP**. All **TIMEOUT** is **DOWN** for this tool — the address may still be alive behind a filter.

Use it to learn sockets, timeouts, concurrency, and how service banners look on systems you are allowed to test.

## Features

- IPv4, IPv6, and hostname targets (hostname syntax check, then DNS at scan time)
- Sequential inventory from a UTF-8 `--target-file` (one host per line, max 256; comments allowed)
- Host discovery via TCP ping (`--discover`); IPv4 CIDR `/24` or smaller (max 256 addresses)
- Inclusive port range `1-65535`, comma-separated lists (`22,80,443`), and named profiles (`quick`, `common`)
- `--exclude` / `-x` to skip ports from a range or profile (same syntax as `--ports`)
- Concurrent TCP connect or UDP probe scan via `ThreadPoolExecutor` (default 50 workers, max 200)
- OPEN / CLOSED / TIMEOUT from TCP `connect_ex` / `SO_ERROR`, or from UDP reply vs ICMP unreachable
- Service-name hint: OS `getservbyport()` first, then a small fallback map for ports some tables omit
- Passive banner grab (read only; no HTTP/SMTP/TLS probes) with ASCII and binary greeting parse
- Per-port latency with `time.perf_counter()`
- CLI (`argparse`) with a live progress bar, plus a dark-themed Tkinter GUI
- Scheduled repeats in this process (`--interval` 5–86400s, `--runs` or Ctrl+C), with a diff of newly open / gone ports
- JSON, CSV, HTML, and simple PDF reports under `reports/`
- Local sqlite scan history (`reports/history.db`) with list / show / diff
- Automatic baseline diff vs the last stored scan of the same target (`--no-diff` to skip)
- Result-count charts: ASCII on the CLI, SVG in HTML reports, Tkinter canvas in the GUI
- Local reference notes on some OPEN ports (hardening / historical CVE ids; not a vuln scan)
- File logging to `logs/scanner.log`
- Unit tests that mock sockets and DNS (no internet required)
- GitHub Actions runs pytest on push and pull requests to `main` (Python 3.12 and 3.13)

## Technologies

| Area | Choice |
|---|---|
| Language | Python 3.12+ |
| Sockets | `socket` |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` |
| CLI | `argparse` |
| GUI | Tkinter / `ttk` |
| Reports | `json`, `csv`, HTML, PDF (stdlib writer) |
| History | `sqlite3` (`reports/history.db`) |
| Charts | ASCII / SVG / Tkinter `Canvas` (stdlib) |
| Notes | Static local table (`scanner/advisory.py`) |
| Logging | `logging` |
| Tests | `pytest` |
| CI | GitHub Actions (pytest only; no live scans) |

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
python main.py --target 127.0.0.1 --discover
python main.py --target 192.168.1.0/24 --discover --show-closed
python main.py --target 127.0.0.1 --profile quick --interval 60 --runs 3
python main.py --history
python main.py --history-id 3
python main.py --history-diff 3 4
python main.py --target-file hosts.txt --profile quick
python main.py --target 127.0.0.1 --profile quick --exclude 80,443
```

| Flag | Meaning |
|---|---|
| `--target` / `-t` | IPv4, IPv6, hostname, or IPv4 CIDR with `--discover` (required for CLI unless `--target-file`) |
| `--target-file` | UTF-8 list of authorized targets, one per line, max 256. Sequential scans, not a parallel sweep. Do not combine with `--target`, `--gui`, `--interval` / `--runs`, or history query flags |
| `--ports` / `-p` | `80`, `1-1000`, or `22,80,443` (required unless `--profile` or `--discover`) |
| `--profile` | Named port set: `quick` or `common` (instead of `--ports`) |
| `--exclude` / `-x` | Ports to skip, same syntax as `--ports`. Do not combine with `--discover`. Empty remainder is an error |
| `--timeout` | Connect timeout in seconds (default `0.5`) |
| `--threads` | Max workers, `1-200` (default `50`) |
| `--ipv6` | Resolve hostnames to IPv6 (AAAA). Literals keep their own family |
| `--udp` | UDP probe instead of TCP connect |
| `--discover` / `-d` | TCP ping instead of a port scan (do not combine with `--udp`, `--ports`, `--profile`, or `--exclude`) |
| `--show-closed` | Print CLOSED and TIMEOUT, or DOWN hosts during discovery |
| `--output` / `-o` | Report path |
| `--format` / `-f` | `json`, `csv`, `html`, or `pdf` |
| `--verbose` / `-v` | DEBUG lines on the console |
| `--interval` | Seconds to wait between authorized repeats (`5`–`86400`). Process stays in the foreground |
| `--runs` | How many repeats when `--interval` is set (`1`–`1000`). Omit to loop until Ctrl+C |
| `--history` | List stored scans from `reports/history.db` (optional `--target` filter, `--history-limit`) |
| `--history-id` | Print one stored scan by row id (optional `--output` / `--format` to re-export) |
| `--history-diff` | Compare two stored ids (`OLD NEW`): newly open / gone ports, or newly up / gone hosts |
| `--no-history` | Do not record this run |
| `--no-refs` | Do not print local reference notes on the CLI |
| `--no-diff` | Do not compare this run to the last stored scan of the same target |
| `--gui` | Open the Tkinter UI |

Closed and timeout ports are hidden on the CLI unless `--show-closed` is set. They are still stored in reports. During discovery, DOWN hosts are hidden the same way. During a CLI scan, stderr shows a live ASCII progress bar (`Progress: [########........]  50%  Found: N open ports` or `live hosts`). `--verbose` skips the bar so DEBUG lines stay readable.

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
python main.py --target 127.0.0.1 --profile quick --format pdf
python main.py --target 127.0.0.1 --udp --ports 53,123,161 --show-closed
python main.py --target 127.0.0.1 --udp --profile quick --show-closed
python main.py --target 127.0.0.1 --discover
python main.py --target 192.168.1.0/24 --discover --show-closed
python main.py --target 127.0.0.1 --profile quick --interval 60 --runs 3
python main.py --history
python main.py --history --target 127.0.0.1
python main.py --history-id 3
python main.py --history-id 3 --format html
python main.py --history-diff 3 4
python main.py --target 127.0.0.1 --ports 21,23
python main.py --target 127.0.0.1 --ports 21,23 --no-refs
python main.py --target 127.0.0.1 --profile quick --no-diff
python main.py --target-file hosts.txt --profile quick
python main.py --target-file nets.txt --discover --show-closed
python main.py --target 127.0.0.1 --profile quick --exclude 80,443
python main.py --target 127.0.0.1 --ports 1-1023 --exclude 80,443
python main.py -t 127.0.0.1 -p 1-80 --show-closed --verbose
```

Example `hosts.txt` (UTF-8, `#` comments, blanks ignored; duplicates keep the first line):

```text
# lab VMs I own
127.0.0.1
localhost
```

With `--discover`, a line may be an IPv4 CIDR (`192.168.1.0/24`). Without `--discover`, CIDR is rejected. History and `--no-diff` still apply **per host**. If one host fails (DNS, etc.), the rest continue; the process exits `1` if any failed.

## GUI

```powershell
python main.py --gui
```

Fields: target (or IPv4 CIDR), start/end port, timeout, threads, profile (Custom / Quick / Common), **Exclude ports**, **Protocol** (TCP / UDP), **Prefer IPv6**, **Host discovery**, **Interval (s)** / **Runs**, **START SCAN**. Leave interval empty for a single scan. Set interval (at least 5 seconds) and runs greater than 1 to repeat in this window — not a system task scheduler. Below: status, open-port (or live-host) count, progress bar, result table. Port-scan columns: Port, State, Protocol, Service, Product, Response Time, Banner, Notes. Discovery columns: Host, State, Evidence, Response Time. Quick and Common ignore the start/end fields; UDP uses a different port set (DNS, NTP, SNMP, …). **Exclude ports** uses the same syntax as `--ports` and is ignored (rejected) during host discovery. Host discovery ignores ports, profile, and UDP: it TCP-pings 80, 443, 22, and 445. After a run finishes, **SAVE REPORT** writes HTML or PDF (the file extension chooses the format). **HISTORY** lists stored runs from `reports/history.db`; double-click or **LOAD** to show one in the table. A bar chart under the progress bar shows OPEN / CLOSED / TIMEOUT (or UP / DOWN); the history window charts hits across stored runs. A single scan’s status line can include `vs history #N` when a previous stored run of the same target exists. IPv4/IPv6 literals pick their family; **Prefer IPv6** only changes hostname resolution (AAAA).

The GUI still takes **one target**. Use `--target-file` on the CLI for a small authorized inventory.

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

OPEN         3  [....................]
CLOSED       0  [....................]
TIMEOUT    997  [####################]

[+] 22 OPEN ssh OpenSSH 9.2 12.3ms SSH-2.0-OpenSSH_9.2
    note: SSH remote login. Encrypted admin access. Prefer keys over passwords and keep the daemon patched. An open 22 is expected, not a finding.
[+] 80 OPEN http 4.1ms
    note: HTTP without TLS [CWE-319]. Application data is cleartext unless the app redirects to HTTPS. This scan does not send GET or read certificates.
[+] 443 OPEN https 8.0ms

Found: 3 open port(s)
Report saved: reports/scan_2026-08-25_1710.json
History recorded: #4
```

On some Windows hosts, unused localhost ports time out instead of returning RST. That is a TIMEOUT, not a scanner bug.

Discovery (`--discover`) prints live hosts instead of ports:

```text
Use this tool only on systems you are authorized to test.
Discovering 192.168.1.0/24...
Target: 192.168.1.0/24
Method: tcp_ping (ports 80,443,22,445)
Timeout: 0.5s
Threads: 50
Hosts:  254 (up=2, down=252)

[+] 192.168.1.1 UP tcp/80 CLOSED 4.2ms
[+] 192.168.1.10 UP tcp/443 OPEN 8.1ms

Live: 2 host(s)
```

## Architecture

```text
main.py                 entry point
cli/interface.py        argparse, console report
gui/app.py              Tkinter UI + background worker
scanner/
  validator.py          target / CIDR / target file / ports / exclude / timeout / threads / interval
  scanner.py            TCP connect and UDP probe engine
  discover.py           TCP ping host discovery
  compare.py            newly open / gone ports between runs
  port.py               OPEN / CLOSED / TIMEOUT
  models.py             scan and discovery report types
  service.py            getservbyport plus a small fallback map
  banner.py             passive recv, ASCII + binary greeting parse
  advisory.py           local OPEN-port reference notes (not a vuln scan)
utils/
  exporter.py           JSON / CSV / HTML / PDF
  pdf.py                stdlib PDF 1.4 writer (Helvetica / Courier)
  history.py            sqlite scan history (reports/history.db)
  charts.py             ASCII / SVG bar charts from result counts
  logger.py             logs/scanner.log
tests/                  pytest
.github/workflows/      pytest on push / pull request (no live scans)
reports/                generated reports and history.db (gitignored)
logs/                   scanner.log (gitignored)
```

Interfaces never open sockets themselves. They call `TcpConnectScanner` or `discover_hosts`.

## How It Works

1. Validate the target (host, IPv4 CIDR for discovery, or each line of `--target-file`), ports (range, list, or profile), optional `--exclude`, timeout, and thread count. A target file is scanned **sequentially**; each host still uses the thread pool. Exclude is applied after the port list is built, so a `quick` profile can skip 80 and 443.
2. Resolve hostname to IPv4 (A) or IPv6 (AAAA) with `socket.getaddrinfo`. Literals skip DNS. Dual-stack names prefer IPv4 unless `--ipv6` / Prefer IPv6. CIDR discovery expands IPv4 hosts and skips DNS.
3. Probe each host (TCP ping) or each port concurrently (TCP connect or UDP datagram, bounded thread pool).
4. Map the outcome to UP / DOWN, or OPEN / CLOSED / TIMEOUT.
5. For OPEN TCP ports, look up a service name (OS table, then fallback map). If the peer speaks first, classify that greeting (ASCII or a few binary signatures). UDP OPEN ports get a table/fallback name if known; there is no TCP-style banner parse. Discovery does not grab banners. OPEN ports may also get a **local reference note** (hardening or a historical CVE id). That is a table lookup, not a live CVE feed and not a confirmation.
6. Sort results and print, export (JSON, CSV, HTML, or PDF), or show in the GUI. HTML includes an SVG count chart; the CLI prints ASCII bars.
7. Record the run in `reports/history.db` unless `--no-history` is set. If an older stored scan of the same target exists, print a baseline diff (ports probed in both runs only). `--interval` run 2+ diffs in-process instead.
8. If `--interval` is set, wait and repeat. After the second run, print ports (or hosts) that appeared or disappeared.

## Scheduled Scans

`--interval` / `--runs` (and the GUI Interval / Runs fields) repeat the **same authorized scan in this process**. This is not cron, not Windows Task Scheduler, not a service, and not persistence.

- Minimum wait is **5 seconds** so a typo cannot hammer a host.
- `--runs` is required in the GUI when repeating. On the CLI, omitting `--runs` loops until Ctrl+C.
- After run 2+, the tool diffs **currently open** ports (or **up** hosts) against the previous run.
- Repeated `--output` files get a `_run2` suffix so they do not overwrite run 1.
- Do not combine `--gui` with `--interval` / `--runs` on the command line; use the GUI fields instead.

This is a change detector for a lab you own, not an alerting platform.

## PDF Reports

`--format pdf` writes a **PDF 1.4** file with the standard Helvetica and Courier fonts. There is no ReportLab or other PDF library: the bytes are built in `utils/pdf.py`. Non-Latin characters become `?`. Parentheses in banners are escaped. Long result lists continue on extra pages.

This is a portable lab hand-in, not a designed layout. HTML remains the richer on-screen report.

## Scan History

Every successful CLI or GUI run is stored in **`reports/history.db`** (sqlite3, standard library). This is a local lab notebook: it is not a SIEM, not a remote log, and not a reason to leave scans running unattended.

```powershell
python main.py --history
python main.py --history --target 127.0.0.1
python main.py --history-id 3
python main.py --history-id 3 --format html
python main.py --history-diff 3 4
python main.py --target 127.0.0.1 --profile quick --no-history
```

`--history-diff OLD NEW` treats the first id as the baseline and reuses the same open-port / live-host diff as `--interval`. You cannot compare a port scan with a discovery run. The GUI **HISTORY** button lists recent rows; **LOAD** (or double-click) shows one in the results table without writing a duplicate row.

A normal scan also diffs against the **latest stored run** of the same target, kind, and protocol (`localhost` and `127.0.0.1` are different strings). Only ports (or hosts) probed in **both** runs are compared, so a `quick` follow-up (or `--exclude`) does not pretend that unprobed ports vanished. `--interval` run 2+ keeps the in-process diff and skips this extra lookup. `--target-file` uses `run_index=1` per host so each line still gets that sqlite baseline. `--no-diff` turns the automatic baseline off. This is still a lab change detector, not an alerting platform.

The database is gitignored. It can hold IP addresses, port numbers, and banners from systems you scanned — keep it on a machine you control.

## Visualization

Counts are drawn with the **standard library only**. There is no matplotlib, no Chart.js, and no network call to render a graph.

- **CLI** — after the summary, a three-line (or two-line for discovery) ASCII bar chart. `--history` also prints a column chart of hits across stored runs (oldest on the left).
- **HTML** — an inline SVG next to the summary cards. Open the file in a browser; no extra assets.
- **GUI** — a Tkinter `Canvas` under the progress bar. The **HISTORY** window charts hits per stored run.

Bar length is relative to the largest count in that chart, not to 65535. A full TIMEOUT bar on a 1000-port scan means “almost everything timed out”, not “the host is 100% filtered”. This is a count picture, not a vulnerability score and not a network map.

PDF reports stay text-only.

## TCP Connect Scanning

The probe uses a non-blocking TCP socket and `connect_ex`. IPv4 uses `(ip, port)`; IPv6 uses `(ip, port, 0, 0)` on an `AF_INET6` socket:

- **0** — handshake completed → **OPEN**
- Connection refused (e.g. `ECONNREFUSED` / `WSAECONNREFUSED`) → **CLOSED**
- Timeout / unreachable → **TIMEOUT**

On Windows, `connect_ex` often returns `WSAEWOULDBLOCK` (10035) before the handshake finishes. That is **in progress**, not CLOSED. The scanner waits with `select` and then reads `SO_ERROR`.

`connect()` would raise on every closed port. `connect_ex()` returns an errno instead, which is a better fit for a scanner. This is a **full connect scan**, not SYN-only, not stealth, and not a firewall bypass.

TIMEOUT is not a reliable IDS/firewall fingerprint.

## Host Discovery

`--discover` does not send ICMP echo and does not use ARP. It TCP-pings **80, 443, 22, 445** with the same `connect_ex` path as a port scan, but without waiting for a banner.

- SYN-ACK (**OPEN**) or RST (**CLOSED**) → the host stack answered → **UP**
- All four probes **TIMEOUT** → **DOWN** for this tool (offline, filtered, or those ports are unused and silent)

A closed port is still evidence the host is there. Silence is not proof it is gone. IPv4 CIDR `/24` or smaller is expanded (`/32` is one address). `/16` and IPv6 networks are rejected. Port scans still reject a slash in `--target`.

This is not a stealth scan, not ICMP, and not an ARP sweep.

## UDP Probing

UDP has no handshake. The scanner connects a datagram socket (so ICMP errors attach to it), sends a single null byte (`\x00`), and waits. No DNS/NTP/SNMP payload is crafted, and no raw sockets are required.

- A UDP reply → **OPEN**
- ICMP port-unreachable, seen as `ECONNREFUSED` / `WSAECONNRESET` (10054) → **CLOSED**
- Silence until timeout → **TIMEOUT** (open, filtered, dropped, or ICMP rate-limited)

`--profile quick` / `common` under `--udp` uses UDP-oriented ports (53, 123, 161, …), not the TCP web/SSH set. Many UDP services stay silent unless you speak their protocol, so `--show-closed` is useful. Too many parallel UDP probes can make a host rate-limit ICMP and inflate TIMEOUT.

This is not a stealth scan and not an amplification attack.

## Service Detection

Open ports get a name in this order:

1. `socket.getservbyport()` — the OS services table (on Windows, `drivers\etc\services`)
2. A small built-in fallback for ports that table often omits (`6379 → redis`, `5432 → postgresql`, `27017 → mongodb`, `8080 → http-alt`, …)
3. The banner kind (`ssh`, `mysql`, `vnc`, …) only if both maps are empty

A table or fallback name is **never overwritten**. If port 80 is `http` but the greeting is SSH, both stay visible.

Examples: `22 → ssh`, `80 → http`, `443 → https`, `25 → smtp`, `53 → domain`.

A name is a **convention**, not proof that that daemon is running. Anything can listen on port 80. This is not nmap-style probe matching.

## Banner Parsing

After the TCP handshake, the scanner **only reads**. It does not send `GET /`, `EHLO`, `PING`, or a TLS ClientHello. SSH, FTP, SMTP, POP3, IMAP, VNC, and MySQL often greet first; HTTP and TLS usually do not.

`classify_banner()` checks raw bytes first, then `parse_banner()` on sanitized text:

| Greeting | Kind | Example product |
|---|---|---|
| `SSH-2.0-OpenSSH_9.2` | ssh | OpenSSH 9.2 |
| `220 (vsFTPd 3.0.3)` | ftp | vsftpd 3.0.3 |
| `220 host ESMTP Postfix` | smtp | Postfix |
| `+OK Dovecot ready` | pop3 | Dovecot |
| `* OK ... Dovecot ready` | imap | Dovecot |
| `RFB 003.008` | vnc | VNC |
| `HTTP/1.1 … Server: nginx/1.24.0` | http | nginx 1.24.0 |
| `-NOAUTH` / `-ERR` | redis | |
| MySQL protocol-10 handshake | mysql | MySQL / MariaDB |
| TLS record `0x16 0x03 …` | tls | TLS |
| `AMQP` magic | amqp | AMQP |
| Telnet IAC (`0xFF` WILL/DO/…) | telnet | |

A 220 line without FTP or SMTP keywords is left unclassified. Binary protocols that have no printable greeting get a short label in the banner field. If the OS table has no name, the banner kind may fill `service`; a table name is never overwritten, so a mismatch (port 80 + SSH banner) stays visible.

This is not fingerprinting, not a probe database, and not a CVE lookup.

## Reference Notes

OPEN ports can pick up a line from a **static table** in `scanner/advisory.py`. That is not a vulnerability scanner, not a live NVD query, and not exploit documentation.

- **Port notes** — hardening hints (Telnet/FTP are cleartext; Redis/MongoDB historically had no AUTH; RDP/SMB mention historical patch IDs). The id is a catalog pointer. This tool does not test the bug.
- **Version notes** — exact `product + version` from the passive banner, and only a handful of classroom builds (today: vsftpd 2.3.4 → CVE-2011-2523). There is no “all CVEs for OpenSSH < 8” matcher.
- CLOSED and TIMEOUT ports stay silent. Host discovery has no notes.
- `--no-refs` hides the CLI lines. JSON/HTML still include derived `advisories` so a lab report stays complete.
- History reload recomputes notes from the current table; they are not frozen as “the host was vulnerable”.

A note means the service is worth reading about. It does not mean the host is compromised. Missing a note does not mean the host is safe.

## Performance

Port scanning is I/O-bound: workers wait on the network, they do not burn CPU. `ThreadPoolExecutor` overlaps those waits. Too many threads can slow this machine, load the target, and increase timeouts. The cap is 200.

Worker count is `min(requested, port_count)`.

## Testing

```powershell
python -m pip install -r requirements.txt
python -m pytest
```

Tests cover validation (including `--target-file` lists and `--exclude`), connect-code mapping, mocked TCP/UDP probes, mocked DNS, TCP ping discovery, service lookup (including the fallback map), banner parsing, sqlite history round-trips, ASCII/SVG charts, and local reference notes. They do not scan the public internet.

The same `python -m pytest` command runs on GitHub Actions for pushes and pull requests to `main` (Python 3.12 and 3.13). CI is a unit-test gate, not a live scan of any host.

## Limitations

- One address family per run (IPv4 or IPv6, not both at once)
- One protocol per run (TCP or UDP, not both at once)
- IPv6 zone identifiers (`fe80::1%eth0`) are not supported
- No SYN/FIN/Xmas, no spoofing, no raw ICMP or ARP
- Host discovery is TCP ping on 80/443/22/445, not ICMP echo; DOWN includes filtered/silent hosts
- Discovery CIDR is IPv4 `/24` or smaller (max 256 addresses); IPv6 networks are not expanded
- `--target-file` is a sequential lab inventory (max 256 unique hosts), not a mass scanner or a parallel sweep
- Port scans still take one host at a time; CIDR lines in a file are only valid with `--discover`
- `--target-file` is CLI-only: do not combine it with `--gui`, `--interval` / `--runs`, or history query flags
- `--exclude` only drops ports from a port scan; it does not change discovery probes. If nothing remains, the scan is rejected
- UDP TIMEOUT is open|filtered, not a certain closed verdict
- UDP payload is a null byte, not a protocol handshake
- Service names are table lookups plus a small fallback map, not protocol fingerprinting
- Banner parsing is heuristic and passive; HTTP/TLS often send nothing until the client speaks
- TIMEOUT vs CLOSED depends on the OS and firewall
- Repeats run in the foreground; this is not a system scheduler or a persistence mechanism
- Scan history is a local sqlite file, not an alerting platform or a remote archive
- Baseline diffs match the target string exactly and only ports/hosts seen in both runs
- Charts scale to the largest count in that picture; they are not a risk score or a network map
- Reference notes are a small local table, not a CVE feed, not version-wide matching, and not a confirmation
- PDF uses built-in Helvetica/Courier only; it is not a full print layout engine
- GitHub Actions runs mocked unit tests only; it does not scan hosts and is not a security audit of pull requests

## Authorized Use

This project is for:

- `localhost`
- devices you own
- lab or test systems you have **permission** to scan

Do not scan networks or hosts without authorization. Unauthorized scanning can be illegal.

Out of scope on purpose: stealth scanning, IDS/IPS bypass, firewall evasion, source spoofing, anonymization, attack automation, live CVE APIs, and exploit tooling.

Logs and reports may contain IP addresses, port numbers, and banners. Do not log passwords; this tool does not ask for them.

## License

MIT. See [LICENSE](LICENSE).

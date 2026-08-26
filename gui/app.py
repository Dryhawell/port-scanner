"""Tkinter GUI for the TCP connect scanner.

The scan runs on a background thread. Progress events travel through a
thread-safe queue; only the Tk main thread touches widgets.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any

from scanner.advisory import advisory_label
from scanner.constants import (
    APP_VERSION,
    DEFAULT_MAX_WORKERS,
    DEFAULT_TIMEOUT,
    PROTOCOL_UDP,
    SCAN_PROFILES,
    UDP_SCAN_PROFILES,
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
from scanner.validator import ValidationError, validate_interval, validate_runs
from utils.charts import (
    BarSpec,
    COLOR_TRACK,
    bars_from_report,
    empty_discovery_bars,
    empty_port_bars,
    scale_lengths,
)
from utils.exporter import ExportError, ExportFormat, export_report, infer_format
from utils.history import HistoryError, ScanHistory, ScanSummary, record_report
from utils.logger import get_logger, setup_logging

logger = get_logger()

BG = "#0d1117"
PANEL = "#161b22"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#3fb950"
CLOSED = "#f85149"
TIMEOUT = "#d29922"
ENTRY_BG = "#21262d"
BUTTON_BG = "#238636"
BUTTON_FG = "#ffffff"
COLUMNS = ("port", "state", "protocol", "service", "product", "response_time", "banner", "refs")
DISCOVERY_COLUMNS = ("host", "state", "evidence", "response_time")
POLL_MS = 50


def run_app() -> int:
    setup_logging()
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()
    return 0


class ScannerApp:
    """Dark-themed authorized TCP connect scanner window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"Port Scanner {APP_VERSION}")
        self.root.geometry("1040x720")
        self.root.minsize(820, 580)
        self.root.configure(bg=BG)
        self._scanner = TcpConnectScanner()
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._open_seen = 0
        self._delta_note: str | None = None
        self._last_report: ScanReport | DiscoveryReport | None = None
        self._chart_bars: tuple[BarSpec, ...] = empty_port_bars()
        self._build_style()
        self._build_layout()

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=PANEL,
            foreground=FG,
            fieldbackground=PANEL,
            bordercolor=PANEL,
            rowheight=26,
            font=("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            background=ENTRY_BG,
            foreground=FG,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", BUTTON_BG)])
        style.configure(
            "TCombobox",
            fieldbackground=ENTRY_BG,
            background=ENTRY_BG,
            foreground=FG,
            arrowcolor=FG,
        )
        style.configure(
            "Scan.Horizontal.TProgressbar",
            troughcolor=ENTRY_BG,
            background=ACCENT,
            bordercolor=ENTRY_BG,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

    def _build_layout(self) -> None:
        pad = {"padx": 16, "pady": 8}
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", **pad)
        tk.Label(
            header,
            text="PORT SCANNER",
            bg=BG,
            fg=ACCENT,
            font=("Consolas", 18, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Authorized systems only  |  localhost, your devices, permitted test hosts",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        form = tk.Frame(
            self.root,
            bg=PANEL,
            highlightbackground="#30363d",
            highlightthickness=1,
        )
        form.pack(fill="x", padx=16, pady=(4, 8))
        inner = tk.Frame(form, bg=PANEL)
        inner.pack(fill="x", padx=12, pady=12)

        self.target_var = tk.StringVar(value="127.0.0.1")
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="100")
        self.timeout_var = tk.StringVar(value=str(DEFAULT_TIMEOUT))
        self.threads_var = tk.StringVar(value=str(DEFAULT_MAX_WORKERS))
        self.profile_var = tk.StringVar(value="Custom")
        self.protocol_var = tk.StringVar(value="TCP")
        self.discover_var = tk.BooleanVar(value=False)
        self.ipv6_var = tk.BooleanVar(value=False)
        self.interval_var = tk.StringVar(value="")
        self.runs_var = tk.StringVar(value="1")

        fields = (
            ("Target / CIDR", self.target_var, 0, 0, 2),
            ("Start Port", self.start_port_var, 0, 2, 1),
            ("End Port", self.end_port_var, 0, 3, 1),
            ("Timeout (s)", self.timeout_var, 1, 0, 1),
            ("Threads", self.threads_var, 1, 1, 1),
        )
        for label, variable, row, column, span in fields:
            self._labeled_entry(inner, label, variable, row, column, span)
        self._labeled_combo(
            inner,
            "Profile",
            self.profile_var,
            1,
            2,
            ("Custom", "Quick", "Common"),
        )

        self.start_button = tk.Button(
            inner,
            text="START SCAN",
            command=self.start_scan,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            activebackground=ACCENT,
            activeforeground=BG,
            relief="flat",
            font=("Consolas", 11, "bold"),
            cursor="hand2",
            padx=18,
            pady=8,
        )
        self.start_button.grid(row=1, column=3, sticky="e", padx=8, pady=8)
        ipv6_cell = tk.Frame(inner, bg=PANEL)
        ipv6_cell.grid(row=2, column=0, sticky="w", padx=8, pady=(0, 4))
        tk.Checkbutton(
            ipv6_cell,
            text="Prefer IPv6 (hostnames)",
            variable=self.ipv6_var,
            bg=PANEL,
            fg=FG,
            selectcolor=ENTRY_BG,
            activebackground=PANEL,
            activeforeground=FG,
            highlightthickness=0,
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        self._labeled_combo(
            inner,
            "Protocol",
            self.protocol_var,
            2,
            1,
            ("TCP", "UDP"),
        )
        discover_cell = tk.Frame(inner, bg=PANEL)
        discover_cell.grid(row=2, column=2, sticky="w", padx=8, pady=(0, 4))
        tk.Checkbutton(
            discover_cell,
            text="Host discovery",
            variable=self.discover_var,
            bg=PANEL,
            fg=FG,
            selectcolor=ENTRY_BG,
            activebackground=PANEL,
            activeforeground=FG,
            highlightthickness=0,
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        self._labeled_entry(inner, "Interval (s)", self.interval_var, 3, 0, 1)
        self._labeled_entry(inner, "Runs", self.runs_var, 3, 1, 1)
        for index in range(4):
            inner.grid_columnconfigure(index, weight=1)

        status_row = tk.Frame(self.root, bg=BG)
        status_row.pack(fill="x", padx=16)
        self.status_var = tk.StringVar(value="Idle. Ready to scan an authorized target.")
        self.open_count_var = tk.StringVar(value="Open ports: 0")
        tk.Label(
            status_row,
            textvariable=self.status_var,
            bg=BG,
            fg=FG,
            font=("Segoe UI", 10),
        ).pack(side="left")
        tk.Label(
            status_row,
            textvariable=self.open_count_var,
            bg=BG,
            fg=ACCENT,
            font=("Consolas", 10, "bold"),
        ).pack(side="right")

        self.progress = ttk.Progressbar(
            self.root,
            style="Scan.Horizontal.TProgressbar",
            mode="determinate",
            maximum=100,
            value=0,
        )
        self.progress.pack(fill="x", padx=16, pady=8)

        chart_frame = tk.Frame(
            self.root,
            bg=PANEL,
            highlightbackground="#30363d",
            highlightthickness=1,
        )
        chart_frame.pack(fill="x", padx=16, pady=(0, 8))
        self._chart_canvas = tk.Canvas(
            chart_frame,
            bg=PANEL,
            highlightthickness=0,
            height=84,
        )
        self._chart_canvas.pack(fill="x", padx=8, pady=6)
        self._chart_canvas.bind("<Configure>", lambda _event: self._redraw_chart())

        table_frame = tk.Frame(self.root, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        heading_row = tk.Frame(table_frame, bg=BG)
        heading_row.pack(fill="x", pady=(0, 4))
        tk.Label(
            heading_row,
            text="RESULTS",
            bg=BG,
            fg=MUTED,
            font=("Consolas", 10, "bold"),
        ).pack(side="left")
        self.save_button = tk.Button(
            heading_row,
            text="SAVE REPORT",
            command=self.save_html_report,
            bg=ENTRY_BG,
            fg=FG,
            activebackground=BUTTON_BG,
            activeforeground=BUTTON_FG,
            relief="flat",
            font=("Consolas", 9, "bold"),
            cursor="hand2",
            padx=10,
            pady=4,
            state="disabled",
        )
        self.save_button.pack(side="right")
        self.history_button = tk.Button(
            heading_row,
            text="HISTORY",
            command=self.show_history,
            bg=ENTRY_BG,
            fg=FG,
            activebackground=BUTTON_BG,
            activeforeground=BUTTON_FG,
            relief="flat",
            font=("Consolas", 9, "bold"),
            cursor="hand2",
            padx=10,
            pady=4,
        )
        self.history_button.pack(side="right", padx=(0, 8))

        scroll = ttk.Scrollbar(table_frame)
        scroll.pack(side="right", fill="y")
        self.table = ttk.Treeview(
            table_frame,
            columns=COLUMNS,
            show="headings",
            yscrollcommand=scroll.set,
            selectmode="browse",
        )
        scroll.config(command=self.table.yview)
        self.table.tag_configure("OPEN", foreground=ACCENT)
        self.table.tag_configure("CLOSED", foreground=CLOSED)
        self.table.tag_configure("TIMEOUT", foreground=TIMEOUT)
        self.table.tag_configure("UP", foreground=ACCENT)
        self.table.tag_configure("DOWN", foreground=CLOSED)
        self._set_table_mode(discover=False)
        self.table.pack(fill="both", expand=True)

    def _set_table_mode(self, *, discover: bool) -> None:
        if discover:
            columns = DISCOVERY_COLUMNS
            headings = {
                "host": "Host",
                "state": "State",
                "evidence": "Evidence",
                "response_time": "Response Time",
            }
            widths = {"host": 180, "state": 90, "evidence": 180, "response_time": 130}
            stretch = "host"
        else:
            columns = COLUMNS
            headings = {
                "port": "Port",
                "state": "State",
                "protocol": "Protocol",
                "service": "Service",
                "product": "Product",
                "response_time": "Response Time",
                "banner": "Banner",
                "refs": "Notes",
            }
            widths = {
                "port": 70,
                "state": 90,
                "protocol": 80,
                "service": 90,
                "product": 140,
                "response_time": 110,
                "banner": 200,
                "refs": 180,
            }
            stretch = "banner"
        self.table.configure(columns=columns)
        self.table["displaycolumns"] = columns
        for key, title in headings.items():
            self.table.heading(key, text=title, anchor="w")
            self.table.column(key, width=widths[key], stretch=key == stretch, anchor="w")

    def _labeled_entry(
        self,
        parent: tk.Frame,
        label: str,
        variable: tk.StringVar,
        row: int,
        column: int,
        span: int,
    ) -> None:
        cell = tk.Frame(parent, bg=PANEL)
        cell.grid(row=row, column=column, columnspan=span, sticky="ew", padx=8, pady=6)
        tk.Label(cell, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        entry = tk.Entry(
            cell,
            textvariable=variable,
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            relief="flat",
            font=("Consolas", 11),
        )
        entry.pack(fill="x", ipady=5)

    def _labeled_combo(
        self,
        parent: tk.Frame,
        label: str,
        variable: tk.StringVar,
        row: int,
        column: int,
        values: tuple[str, ...],
    ) -> None:
        cell = tk.Frame(parent, bg=PANEL)
        cell.grid(row=row, column=column, sticky="ew", padx=8, pady=6)
        tk.Label(cell, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        combo = ttk.Combobox(
            cell,
            textvariable=variable,
            values=values,
            state="readonly",
            font=("Consolas", 11),
        )
        combo.pack(fill="x", ipady=3)

    def start_scan(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return

        target = self.target_var.get()
        start_port = self.start_port_var.get()
        end_port = self.end_port_var.get()
        timeout = self.timeout_var.get()
        threads = self.threads_var.get()
        profile = self.profile_var.get()
        prefer_ipv6 = bool(self.ipv6_var.get())
        protocol = self.protocol_var.get()
        discover = bool(self.discover_var.get())
        interval_raw = self.interval_var.get().strip()
        runs_raw = self.runs_var.get().strip() or "1"
        try:
            interval = validate_interval(interval_raw) if interval_raw else None
            runs = validate_runs(runs_raw)
        except ValidationError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        if runs > 1 and interval is None:
            messagebox.showerror(
                "Invalid input",
                "Set an interval of at least 5 seconds to repeat a scan.",
            )
            return

        self._clear_table()
        self._set_table_mode(discover=discover)
        self._open_seen = 0
        self._delta_note = None
        self._last_report = None
        self.save_button.config(state="disabled")
        self.progress["value"] = 0
        self._set_chart_bars(empty_discovery_bars() if discover else empty_port_bars())
        self.open_count_var.set("Live hosts: 0" if discover else "Open ports: 0")
        self.status_var.set("Discovering..." if discover else "Scanning...")
        self.start_button.config(state="disabled")

        self._worker = threading.Thread(
            target=self._scan_worker,
            args=(
                target,
                start_port,
                end_port,
                timeout,
                threads,
                profile,
                prefer_ipv6,
                protocol,
                discover,
                interval,
                runs,
            ),
            daemon=True,
            name="scan-worker",
        )
        self._worker.start()
        self.root.after(POLL_MS, self._poll_events)

    def _scan_worker(
        self,
        target: str,
        start_port: str,
        end_port: str,
        timeout: str,
        threads: str,
        profile: str,
        prefer_ipv6: bool,
        protocol: str,
        discover: bool,
        interval: float | None,
        runs: int,
    ) -> None:
        previous: ScanReport | DiscoveryReport | None = None
        total_runs = max(1, runs)

        def on_host_progress(completed: int, total: int, result: HostDiscoveryResult) -> None:
            self._events.put(("host_progress", completed, total, result))

        def on_progress(completed: int, total: int, result: PortScanResult) -> None:
            self._events.put(("progress", completed, total, result))

        def one_discovery() -> DiscoveryReport:
            return discover_hosts(
                target,
                timeout=timeout,
                max_workers=threads,
                on_progress=on_host_progress,
                prefer_ipv6=prefer_ipv6,
            )

        def one_scan() -> ScanReport:
            profile_key = profile.strip().lower()
            scan_protocol = protocol.strip().lower()
            profiles = UDP_SCAN_PROFILES if scan_protocol == PROTOCOL_UDP else SCAN_PROFILES
            if profile_key in profiles:
                return self._scanner.scan(
                    target,
                    timeout=timeout,
                    max_workers=threads,
                    on_progress=on_progress,
                    ports=profiles[profile_key],
                    prefer_ipv6=prefer_ipv6,
                    protocol=scan_protocol,
                )
            return self._scanner.scan(
                target,
                start_port,
                end_port,
                timeout,
                threads,
                on_progress=on_progress,
                prefer_ipv6=prefer_ipv6,
                protocol=scan_protocol,
            )

        for index in range(1, total_runs + 1):
            self._events.put(("run_start", index, total_runs))
            try:
                report: ScanReport | DiscoveryReport = (
                    one_discovery() if discover else one_scan()
                )
            except ValidationError as extra:
                logger.error("%s", extra)
                self._events.put(("error", str(extra)))
                return
            except ScannerError as extra:
                logger.error("%s", extra)
                self._events.put(("error", str(extra)))
                return
            except KeyboardInterrupt:
                self._events.put(("error", "Scan interrupted."))
                return
            if previous is not None:
                if isinstance(previous, DiscoveryReport) and isinstance(report, DiscoveryReport):
                    appeared, disappeared = live_host_delta(previous, report)
                    self._events.put(("delta", appeared, disappeared, True))
                elif isinstance(previous, ScanReport) and isinstance(report, ScanReport):
                    appeared, disappeared = open_port_delta(previous, report)
                    self._events.put(("delta", appeared, disappeared, False))
            previous = report
            if index == total_runs:
                self._events.put(("host_done" if discover else "done", report))
                return
            self._events.put(("snapshot", report))
            self._events.put(("wait", interval or 0, index, total_runs))
            time.sleep(interval or 0)

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._events.get_nowait()
                kind = event[0]
                if kind == "progress":
                    _name, completed, total, result = event
                    self._handle_progress(completed, total, result)
                elif kind == "host_progress":
                    _name, completed, total, result = event
                    self._handle_host_progress(completed, total, result)
                elif kind == "run_start":
                    _name, index, total = event
                    self._clear_table()
                    self._open_seen = 0
                    self._delta_note = None
                    self.progress["value"] = 0
                    self.status_var.set(f"Run {index}/{total}...")
                elif kind == "snapshot":
                    report = event[1]
                    if isinstance(report, DiscoveryReport):
                        self._show_discovery_report(report, finished=False)
                    else:
                        self._show_report(report, finished=False)
                elif kind == "delta":
                    _name, appeared, disappeared, is_host = event
                    label = "up" if is_host else "open"
                    self._delta_note = (
                        f"Newly {label}: {len(appeared)}; gone: {len(disappeared)}"
                    )
                    self.status_var.set(self._delta_note)
                elif kind == "wait":
                    _name, wait_s, index, total = event
                    note = f"  {self._delta_note}" if self._delta_note else ""
                    self.status_var.set(
                        f"Waiting {wait_s:g}s until run {index + 1}/{total}.{note}"
                    )
                elif kind == "done":
                    self._show_report(event[1], finished=True)
                    return
                elif kind == "host_done":
                    self._show_discovery_report(event[1], finished=True)
                    return
                elif kind == "error":
                    self._finish_with_error(event[1])
                    return
        except queue.Empty:
            pass

        if self._worker is not None and self._worker.is_alive():
            self.root.after(POLL_MS, self._poll_events)
        elif not self._events.empty():
            self.root.after(POLL_MS, self._poll_events)

    def _handle_progress(
        self,
        completed: int,
        total: int,
        result: PortScanResult,
    ) -> None:
        percent = (completed / total) * 100 if total else 100
        self.progress["value"] = percent
        if result.state is PortState.OPEN:
            self._open_seen += 1
            self.open_count_var.set(f"Open ports: {self._open_seen}")
            self._insert_result(result)
        self.status_var.set(
            f"Scanning {result.port}...  {completed}/{total}  ({percent:.0f}%)"
        )

    def _handle_host_progress(
        self,
        completed: int,
        total: int,
        result: HostDiscoveryResult,
    ) -> None:
        percent = (completed / total) * 100 if total else 100
        self.progress["value"] = percent
        if result.state is HostState.UP:
            self._open_seen += 1
            self.open_count_var.set(f"Live hosts: {self._open_seen}")
            self._insert_host(result)
        self.status_var.set(
            f"Checking {result.ip}...  {completed}/{total}  ({percent:.0f}%)"
        )

    def _show_report(self, report: ScanReport, *, finished: bool = True, record: bool = True) -> None:
        self._clear_table()
        self._set_table_mode(discover=False)
        for result in report.results:
            self._insert_result(result)
        open_count = report.count(PortState.OPEN)
        self.open_count_var.set(f"Open ports: {open_count}")
        duration = f"{report.duration:.2f}s" if report.duration is not None else "?"
        status = (
            f"Done. {report.target} ({report.resolved_ip})  |  "
            f"{report.port_label()}  |  {duration}"
        )
        if self._delta_note:
            status = f"{status}  |  {self._delta_note}"
        if record:
            history_note = self._record_history(report)
            if history_note:
                status = f"{status}  |  {history_note}"
        self.status_var.set(status)
        self.progress["value"] = 100
        self._last_report = report
        self.save_button.config(state="normal")
        if finished:
            self.start_button.config(state="normal")
        self._set_chart_bars(bars_from_report(report))

    def _show_discovery_report(
        self,
        report: DiscoveryReport,
        *,
        finished: bool = True,
        record: bool = True,
    ) -> None:
        self._clear_table()
        self._set_table_mode(discover=True)
        for result in report.results:
            self._insert_host(result)
        up_count = report.count(HostState.UP)
        self.open_count_var.set(f"Live hosts: {up_count}")
        duration = f"{report.duration:.2f}s" if report.duration is not None else "?"
        status = f"Done. {report.spec}  |  {len(report.results)} hosts  |  {duration}"
        if self._delta_note:
            status = f"{status}  |  {self._delta_note}"
        if record:
            history_note = self._record_history(report)
            if history_note:
                status = f"{status}  |  {history_note}"
        self.status_var.set(status)
        self.progress["value"] = 100
        self._last_report = report
        self.save_button.config(state="normal")
        if finished:
            self.start_button.config(state="normal")
        self._set_chart_bars(bars_from_report(report))

    def save_html_report(self) -> None:
        if self._last_report is None:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=(
                ("HTML", "*.html"),
                ("PDF", "*.pdf"),
                ("All files", "*.*"),
            ),
            initialfile="scan_report.html",
        )
        if not path:
            return
        fmt = infer_format(path) or ExportFormat.HTML
        try:
            saved = export_report(self._last_report, path, fmt)
        except ExportError as exc:
            logger.error("%s", exc)
            messagebox.showerror("Export failed", str(exc))
            return
        self.status_var.set(f"Report saved: {saved}")

    def _record_history(self, report: ScanReport | DiscoveryReport) -> str | None:
        try:
            scan_id = record_report(report)
        except HistoryError as extra:
            logger.error("%s", extra)
            return "history not saved"
        return f"history #{scan_id}"

    def show_history(self) -> None:
        try:
            rows = ScanHistory().list_scans(limit=50)
        except HistoryError as extra:
            messagebox.showerror("History failed", str(extra))
            return
        window = tk.Toplevel(self.root)
        window.title("Scan history")
        window.configure(bg=BG)
        window.geometry("760x520")
        window.transient(self.root)
        tk.Label(
            window,
            text="Local sqlite history  |  reports/history.db  |  not a remote log",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(12, 6))
        tk.Label(
            window,
            text="Hits over stored runs (oldest → newest; open ports or live hosts)",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=12)
        trend = tk.Canvas(window, bg=PANEL, highlightthickness=0, height=88)
        trend.pack(fill="x", padx=12, pady=(4, 8))
        self._draw_history_trend(trend, rows)
        table_frame = tk.Frame(window, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=12)
        scroll = ttk.Scrollbar(table_frame)
        scroll.pack(side="right", fill="y")
        columns = ("id", "time", "method", "target", "result")
        table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            yscrollcommand=scroll.set,
            selectmode="browse",
        )
        scroll.config(command=table.yview)
        headings = {
            "id": "ID",
            "time": "UTC time",
            "method": "Method",
            "target": "Target",
            "result": "Result",
        }
        widths = {"id": 50, "time": 150, "method": 110, "target": 220, "result": 120}
        for key, title in headings.items():
            table.heading(key, text=title, anchor="w")
            table.column(key, width=widths[key], stretch=key == "target", anchor="w")
        for item in rows:
            unit = "up" if item.kind == "discovery" else "open"
            table.insert(
                "",
                "end",
                iid=str(item.id),
                values=(
                    item.id,
                    item.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                    item.method,
                    item.target,
                    f"{item.hits}/{item.scanned} {unit}",
                ),
            )
        table.pack(fill="both", expand=True)
        if not rows:
            tk.Label(
                window,
                text="No stored scans yet. Run a scan to record one.",
                bg=BG,
                fg=MUTED,
                font=("Segoe UI", 10),
            ).pack(pady=8)

        def load_selected() -> None:
            selection = table.selection()
            if not selection:
                messagebox.showinfo("Scan history", "Select a stored scan first.")
                return
            self._load_history_id(int(selection[0]))
            window.destroy()

        buttons = tk.Frame(window, bg=BG)
        buttons.pack(fill="x", padx=12, pady=12)
        tk.Button(
            buttons,
            text="LOAD",
            command=load_selected,
            bg=BUTTON_BG,
            fg=BUTTON_FG,
            activebackground=ACCENT,
            activeforeground=BG,
            relief="flat",
            font=("Consolas", 9, "bold"),
            cursor="hand2",
            padx=12,
            pady=4,
        ).pack(side="right")
        table.bind("<Double-1>", lambda _event: load_selected())

    def _load_history_id(self, scan_id: int) -> None:
        try:
            report = ScanHistory().load(scan_id)
        except HistoryError as extra:
            messagebox.showerror("History failed", str(extra))
            return
        self._delta_note = None
        if isinstance(report, DiscoveryReport):
            self._show_discovery_report(report, record=False)
        else:
            self._show_report(report, record=False)
        self.status_var.set(f"{self.status_var.get()}  |  loaded #{scan_id}")

    def _set_chart_bars(self, bars: tuple[BarSpec, ...]) -> None:
        self._chart_bars = bars
        self._redraw_chart()

    def _redraw_chart(self) -> None:
        canvas = self._chart_canvas
        canvas.delete("all")
        bars = self._chart_bars or empty_port_bars()
        width = max(int(canvas.winfo_width()), 240)
        height = int(canvas.winfo_height()) or 84
        label_x = 8
        plot_x = 78
        value_x = width - 8
        plot_width = max(width - plot_x - 48, 40)
        row_h = height / max(len(bars), 1)
        fills = scale_lengths([bar.value for bar in bars], plot_width)
        for index, (bar, filled) in enumerate(zip(bars, fills, strict=True)):
            y = index * row_h
            track_y = y + row_h * 0.38
            track_h = max(row_h * 0.28, 8)
            canvas.create_text(
                label_x,
                y + row_h / 2,
                text=bar.label,
                anchor="w",
                fill=MUTED,
                font=("Consolas", 9),
            )
            canvas.create_rectangle(
                plot_x,
                track_y,
                plot_x + plot_width,
                track_y + track_h,
                fill=COLOR_TRACK,
                outline="",
            )
            if filled > 0:
                canvas.create_rectangle(
                    plot_x,
                    track_y,
                    plot_x + filled,
                    track_y + track_h,
                    fill=bar.color,
                    outline="",
                )
            canvas.create_text(
                value_x,
                y + row_h / 2,
                text=str(bar.value),
                anchor="e",
                fill=FG,
                font=("Consolas", 9),
            )

    def _draw_history_trend(self, canvas: tk.Canvas, rows: list[ScanSummary]) -> None:
        canvas.delete("all")
        if not rows:
            canvas.create_text(
                12,
                44,
                text="No stored scans yet.",
                anchor="w",
                fill=MUTED,
                font=("Segoe UI", 10),
            )
            return

        def paint(_event: object | None = None) -> None:
            canvas.delete("all")
            width = max(int(canvas.winfo_width()), 200)
            height = max(int(canvas.winfo_height()), 72)
            chronological = list(reversed(rows))
            values = [item.hits for item in chronological]
            plot_left = 16
            plot_right = width - 16
            plot_top = 10
            plot_bottom = height - 18
            plot_height = max(plot_bottom - plot_top, 10)
            plot_width = max(plot_right - plot_left, 10)
            gap = 4
            bar_w = max((plot_width / len(values)) - gap, 2)
            heights = scale_lengths(values, plot_height)
            peak = max(values)
            for index, (item, bar_h) in enumerate(zip(chronological, heights, strict=True)):
                x = plot_left + index * (bar_w + gap)
                y = plot_bottom - bar_h
                color = ACCENT if item.kind != "discovery" else TIMEOUT
                canvas.create_rectangle(
                    x,
                    y if bar_h else plot_bottom - 2,
                    x + bar_w,
                    plot_bottom,
                    fill=color,
                    outline="",
                )
            canvas.create_text(
                plot_left,
                height - 6,
                text=f"n={len(values)}  peak={peak}",
                anchor="w",
                fill=MUTED,
                font=("Consolas", 8),
            )

        canvas.bind("<Configure>", paint)
        canvas.after(1, paint)

    def _insert_result(self, result: PortScanResult) -> None:
        self.table.insert(
            "",
            "end",
            values=(
                result.port,
                result.state.value,
                result.protocol,
                result.service or "",
                result.product_label() or "",
                result.latency_label() or "",
                result.banner or "",
                advisory_label(result),
            ),
            tags=(result.state.value,),
        )

    def _insert_host(self, result: HostDiscoveryResult) -> None:
        self.table.insert(
            "",
            "end",
            values=(
                result.ip,
                result.state.value,
                result.evidence or "",
                result.latency_label() or "",
            ),
            tags=(result.state.value,),
        )

    def _finish_with_error(self, message: str) -> None:
        self.status_var.set(f"Error: {message}")
        self.progress["value"] = 0
        self._last_report = None
        self.save_button.config(state="disabled")
        self.start_button.config(state="normal")
        self._set_chart_bars(empty_port_bars())

    def _clear_table(self) -> None:
        for row_id in self.table.get_children():
            self.table.delete(row_id)

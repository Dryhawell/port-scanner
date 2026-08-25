"""Tkinter GUI for the TCP connect scanner.

The scan runs on a background thread. Progress events travel through a
thread-safe queue; only the Tk main thread touches widgets.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

from scanner.constants import APP_VERSION, DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT, SCAN_PROFILES
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.scanner import ScannerError, TcpConnectScanner
from scanner.validator import ValidationError
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
COLUMNS = ("port", "state", "protocol", "service", "response_time", "banner")
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
        self.root.geometry("980x640")
        self.root.minsize(820, 520)
        self.root.configure(bg=BG)
        self._scanner = TcpConnectScanner()
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._open_seen = 0
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

        fields = (
            ("Target IP / Hostname", self.target_var, 0, 0, 2),
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

        table_frame = tk.Frame(self.root, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        tk.Label(
            table_frame,
            text="RESULTS",
            bg=BG,
            fg=MUTED,
            font=("Consolas", 10, "bold"),
        ).pack(anchor="w", pady=(0, 4))

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
        headings = {
            "port": "Port",
            "state": "State",
            "protocol": "Protocol",
            "service": "Service",
            "response_time": "Response Time",
            "banner": "Banner",
        }
        widths = {
            "port": 80,
            "state": 100,
            "protocol": 90,
            "service": 110,
            "response_time": 130,
            "banner": 320,
        }
        for key, title in headings.items():
            self.table.heading(key, text=title, anchor="w")
            self.table.column(key, width=widths[key], stretch=key == "banner", anchor="w")
        self.table.tag_configure("OPEN", foreground=ACCENT)
        self.table.tag_configure("CLOSED", foreground=CLOSED)
        self.table.tag_configure("TIMEOUT", foreground=TIMEOUT)
        self.table.pack(fill="both", expand=True)

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

        self._clear_table()
        self._open_seen = 0
        self.progress["value"] = 0
        self.open_count_var.set("Open ports: 0")
        self.status_var.set("Scanning...")
        self.start_button.config(state="disabled")

        self._worker = threading.Thread(
            target=self._scan_worker,
            args=(target, start_port, end_port, timeout, threads, profile),
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
    ) -> None:
        def on_progress(completed: int, total: int, result: PortScanResult) -> None:
            self._events.put(("progress", completed, total, result))

        profile_key = profile.strip().lower()
        try:
            if profile_key in SCAN_PROFILES:
                report = self._scanner.scan(
                    target,
                    timeout=timeout,
                    max_workers=threads,
                    on_progress=on_progress,
                    ports=SCAN_PROFILES[profile_key],
                )
            else:
                report = self._scanner.scan(
                    target,
                    start_port,
                    end_port,
                    timeout,
                    threads,
                    on_progress=on_progress,
                )
        except ValidationError as exc:
            logger.error("%s", exc)
            self._events.put(("error", str(exc)))
            return
        except ScannerError as exc:
            logger.error("%s", exc)
            self._events.put(("error", str(exc)))
            return
        self._events.put(("done", report))

    def _poll_events(self) -> None:
        try:
            while True:
                event = self._events.get_nowait()
                kind = event[0]
                if kind == "progress":
                    _name, completed, total, result = event
                    self._handle_progress(completed, total, result)
                elif kind == "done":
                    self._show_report(event[1])
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

    def _show_report(self, report: ScanReport) -> None:
        self._clear_table()
        for result in report.results:
            self._insert_result(result)
        open_count = report.count(PortState.OPEN)
        self.open_count_var.set(f"Open ports: {open_count}")
        duration = f"{report.duration:.2f}s" if report.duration is not None else "?"
        self.status_var.set(
            f"Done. {report.target} ({report.resolved_ip})  |  "
            f"{report.port_label()}  |  {duration}"
        )
        self.progress["value"] = 100
        self.start_button.config(state="normal")

    def _insert_result(self, result: PortScanResult) -> None:
        self.table.insert(
            "",
            "end",
            values=(
                result.port,
                result.state.value,
                result.protocol,
                result.service or "",
                result.latency_label() or "",
                result.banner or "",
            ),
            tags=(result.state.value,),
        )

    def _finish_with_error(self, message: str) -> None:
        self.status_var.set(f"Error: {message}")
        self.progress["value"] = 0
        self.start_button.config(state="normal")

    def _clear_table(self) -> None:
        for row_id in self.table.get_children():
            self.table.delete(row_id)

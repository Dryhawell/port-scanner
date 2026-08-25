"""Tkinter GUI for the TCP connect scanner.

PHASE 12 builds the window and runs the scan on the Tk main thread.
The window can freeze on large ranges; PHASE 13 moves the scan to a worker.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from scanner.constants import DEFAULT_MAX_WORKERS, DEFAULT_TIMEOUT
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
OPEN = "#3fb950"
CLOSED = "#f85149"
TIMEOUT = "#d29922"
ENTRY_BG = "#21262d"
BUTTON_BG = "#238636"
BUTTON_FG = "#ffffff"
COLUMNS = ("port", "state", "protocol", "service", "response_time", "banner")


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
        self.root.title("Port Scanner")
        self.root.geometry("980x640")
        self.root.minsize(820, 520)
        self.root.configure(bg=BG)
        self._scanner = TcpConnectScanner()
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
        style.map("Treeview", background=[("selected", "#238636")])
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

        form = tk.Frame(self.root, bg=PANEL, highlightbackground="#30363d", highlightthickness=1)
        form.pack(fill="x", padx=16, pady=(4, 8))
        inner = tk.Frame(form, bg=PANEL)
        inner.pack(fill="x", padx=12, pady=12)

        self.target_var = tk.StringVar(value="127.0.0.1")
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="100")
        self.timeout_var = tk.StringVar(value=str(DEFAULT_TIMEOUT))
        self.threads_var = tk.StringVar(value=str(DEFAULT_MAX_WORKERS))

        fields = (
            ("Target IP / Hostname", self.target_var, 0, 0, 2),
            ("Start Port", self.start_port_var, 0, 2, 1),
            ("End Port", self.end_port_var, 0, 3, 1),
            ("Timeout (s)", self.timeout_var, 1, 0, 1),
            ("Threads", self.threads_var, 1, 1, 1),
        )
        for label, variable, row, column, span in fields:
            self._labeled_entry(inner, label, variable, row, column, span)

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
        self.start_button.grid(row=1, column=2, columnspan=2, sticky="e", padx=8, pady=8)
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
        self.table.tag_configure("OPEN", foreground=OPEN)
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

    def start_scan(self) -> None:
        self._clear_table()
        self.progress["value"] = 0
        self.open_count_var.set("Open ports: 0")
        self.status_var.set("Scanning...")
        self.start_button.config(state="disabled")
        self.root.update_idletasks()

        try:
            report = self._scanner.scan(
                self.target_var.get(),
                self.start_port_var.get(),
                self.end_port_var.get(),
                self.timeout_var.get(),
                self.threads_var.get(),
            )
        except ValidationError as exc:
            logger.error("%s", exc)
            self._finish_with_error(str(exc))
            return
        except ScannerError as exc:
            logger.error("%s", exc)
            self._finish_with_error(str(exc))
            return
        except tk.TclError:
            return

        self._show_report(report)

    def _show_report(self, report: ScanReport) -> None:
        for result in report.results:
            self._insert_result(result)
        open_count = report.count(PortState.OPEN)
        self.open_count_var.set(f"Open ports: {open_count}")
        duration = f"{report.duration:.2f}s" if report.duration is not None else "?"
        self.status_var.set(
            f"Done. {report.target} ({report.resolved_ip})  |  "
            f"{report.start_port}-{report.end_port}  |  {duration}"
        )
        self.progress["value"] = 100
        self.start_button.config(state="normal")

    def _insert_result(self, result: PortScanResult) -> None:
        response = ""
        if result.response_time is not None:
            response = f"{result.response_time * 1000:.1f} ms"
        self.table.insert(
            "",
            "end",
            values=(
                result.port,
                result.state.value,
                result.protocol,
                result.service or "",
                response,
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

"""Local sqlite history of authorized scans.

This is a lab notebook on disk, not a SIEM, not a remote log, and not
persistence for unattended scanning. The default file is reports/history.db.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

from scanner.compare import live_host_delta, open_port_delta
from scanner.constants import APP_NAME, APP_VERSION, PROTOCOL_TCP, PROTOCOL_UDP
from scanner.models import (
    DiscoveryReport,
    HostDiscoveryResult,
    HostState,
    PortScanResult,
    ScanReport,
)
from scanner.port import PortState
from utils.logger import get_logger

logger = get_logger()

DEFAULT_DB_PATH = Path("reports") / "history.db"
KIND_PORT = "port_scan"
KIND_DISCOVERY = "discovery"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    duration REAL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    resolved_ip TEXT,
    ip_version INTEGER NOT NULL,
    protocol TEXT,
    method TEXT NOT NULL,
    timeout REAL NOT NULL,
    threads INTEGER NOT NULL,
    port_label TEXT,
    start_port INTEGER,
    end_port INTEGER,
    scanned INTEGER NOT NULL,
    hits INTEGER NOT NULL,
    misses INTEGER NOT NULL,
    timeouts INTEGER NOT NULL,
    tool TEXT NOT NULL,
    version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS port_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    banner TEXT,
    banner_kind TEXT,
    banner_product TEXT,
    banner_version TEXT,
    response_time REAL
);

CREATE TABLE IF NOT EXISTS host_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    state TEXT NOT NULL,
    evidence TEXT,
    response_time REAL
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_port_results_scan ON port_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_host_results_scan ON host_results(scan_id);
"""


class HistoryError(ValueError):
    """Raised when the local history database cannot be used."""


@dataclass(slots=True)
class ScanSummary:
    """One stored run, without per-port / per-host rows."""

    id: int
    started_at: datetime
    kind: str
    target: str
    resolved_ip: str | None
    protocol: str | None
    method: str
    scanned: int
    hits: int
    duration: float | None
    port_label: str | None


class ScanHistory:
    """Read and write authorized scan reports in a sqlite file."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_DB_PATH

    def save(self, report: ScanReport | DiscoveryReport) -> int:
        """Insert a report and return its row id."""
        with self._session() as conn:
            if isinstance(report, DiscoveryReport):
                return _insert_discovery(conn, report)
            return _insert_port_scan(conn, report)

    def list_scans(
        self,
        *,
        target: str | None = None,
        limit: int = 20,
    ) -> list[ScanSummary]:
        """Return newest-first summaries. Missing files yield an empty list."""
        if not self.path.exists():
            return []
        if limit < 1:
            raise HistoryError("History limit must be at least 1.")
        with self._session() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE target = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [_row_to_summary(row) for row in rows]

    def load(self, scan_id: int) -> ScanReport | DiscoveryReport:
        """Rebuild a report from a stored row."""
        if scan_id < 1:
            raise HistoryError("History id must be a positive integer.")
        if not self.path.exists():
            raise HistoryError(f"No stored scan with id {scan_id}.")
        with self._session() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                raise HistoryError(f"No stored scan with id {scan_id}.")
            if row["kind"] == KIND_DISCOVERY:
                hosts = conn.execute(
                    "SELECT * FROM host_results WHERE scan_id = ? ORDER BY ip",
                    (scan_id,),
                ).fetchall()
                return _row_to_discovery(row, hosts)
            ports = conn.execute(
                "SELECT * FROM port_results WHERE scan_id = ? ORDER BY port",
                (scan_id,),
            ).fetchall()
            return _row_to_port_scan(row, ports)

    def previous_for(
        self,
        report: ScanReport | DiscoveryReport,
    ) -> tuple[int, ScanReport | DiscoveryReport] | None:
        """Return the newest stored run for the same target/kind/protocol."""
        if not self.path.exists():
            return None
        if isinstance(report, DiscoveryReport):
            kind = KIND_DISCOVERY
            target = report.spec
            protocol: str | None = None
        else:
            kind = KIND_PORT
            target = report.target
            protocol = report.protocol
        with self._session() as conn:
            if protocol is None:
                row = conn.execute(
                    "SELECT id FROM scans WHERE target = ? AND kind = ? "
                    "ORDER BY id DESC LIMIT 1",
                    (target, kind),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT id FROM scans WHERE target = ? AND kind = ? "
                    "AND protocol = ? ORDER BY id DESC LIMIT 1",
                    (target, kind, protocol),
                ).fetchone()
        if row is None:
            return None
        scan_id = int(row["id"])
        return scan_id, self.load(scan_id)

    def diff(
        self,
        first_id: int,
        second_id: int,
    ) -> tuple[str, list[int] | list[str], list[int] | list[str]]:
        """Compare two stored runs. first_id is treated as the older baseline."""
        first = self.load(first_id)
        second = self.load(second_id)
        if type(first) is not type(second):
            raise HistoryError("Cannot compare a port scan with a discovery run.")
        if isinstance(first, DiscoveryReport) and isinstance(second, DiscoveryReport):
            appeared, disappeared = live_host_delta(first, second)
            return "host", appeared, disappeared
        if isinstance(first, ScanReport) and isinstance(second, ScanReport):
            appeared, disappeared = open_port_delta(first, second)
            return "port", appeared, disappeared
        raise HistoryError("Cannot compare a port scan with a discovery run.")

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            _ensure_schema(conn)
            yield conn
            conn.commit()
        except HistoryError:
            conn.rollback()
            raise
        except sqlite3.Error as extra:
            conn.rollback()
            logger.error("History database error: %s", extra)
            raise HistoryError(f"History database error: {extra}") from extra
        finally:
            conn.close()


def record_report(
    report: ScanReport | DiscoveryReport,
    path: str | Path | None = None,
) -> int:
    """Save a report and log the new row id."""
    scan_id = ScanHistory(path).save(report)
    destination = Path(path) if path is not None else DEFAULT_DB_PATH
    logger.info("History recorded: #%s (%s)", scan_id, destination)
    return scan_id


def _ensure_schema(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        conn.executescript(_SCHEMA)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        return
    if version != SCHEMA_VERSION:
        raise HistoryError(
            f"Unsupported history database version {version} "
            f"(expected {SCHEMA_VERSION})."
        )


def _insert_port_scan(conn: sqlite3.Connection, report: ScanReport) -> int:
    method = "udp_probe" if report.protocol == PROTOCOL_UDP else "tcp_connect"
    cursor = conn.execute(
        """
        INSERT INTO scans (
            started_at, duration, kind, target, resolved_ip, ip_version,
            protocol, method, timeout, threads, port_label, start_port,
            end_port, scanned, hits, misses, timeouts, tool, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _isoformat(report.started_at),
            report.duration,
            KIND_PORT,
            report.target,
            report.resolved_ip,
            report.ip_version,
            report.protocol,
            method,
            report.timeout,
            report.max_workers,
            report.port_label(),
            report.start_port,
            report.end_port,
            len(report.results),
            report.count(PortState.OPEN),
            report.count(PortState.CLOSED),
            report.count(PortState.TIMEOUT),
            APP_NAME,
            APP_VERSION,
        ),
    )
    scan_id = cursor.lastrowid
    if scan_id is None:
        raise HistoryError("Could not record scan.")
    scan_id = int(scan_id)
    conn.executemany(
        """
        INSERT INTO port_results (
            scan_id, port, state, protocol, service, banner,
            banner_kind, banner_product, banner_version, response_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                scan_id,
                item.port,
                item.state.value,
                item.protocol,
                item.service,
                item.banner,
                item.banner_kind,
                item.banner_product,
                item.banner_version,
                item.response_time,
            )
            for item in report.results
        ],
    )
    return scan_id


def _insert_discovery(conn: sqlite3.Connection, report: DiscoveryReport) -> int:
    cursor = conn.execute(
        """
        INSERT INTO scans (
            started_at, duration, kind, target, resolved_ip, ip_version,
            protocol, method, timeout, threads, port_label, start_port,
            end_port, scanned, hits, misses, timeouts, tool, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _isoformat(report.started_at),
            report.duration,
            KIND_DISCOVERY,
            report.spec,
            None,
            report.ip_version,
            None,
            "tcp_ping",
            report.timeout,
            report.max_workers,
            None,
            None,
            None,
            len(report.results),
            report.count(HostState.UP),
            report.count(HostState.DOWN),
            0,
            APP_NAME,
            APP_VERSION,
        ),
    )
    scan_id = cursor.lastrowid
    if scan_id is None:
        raise HistoryError("Could not record scan.")
    scan_id = int(scan_id)
    conn.executemany(
        """
        INSERT INTO host_results (scan_id, ip, state, evidence, response_time)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                scan_id,
                item.ip,
                item.state.value,
                item.evidence,
                item.response_time,
            )
            for item in report.results
        ],
    )
    return scan_id


def _row_to_summary(row: sqlite3.Row) -> ScanSummary:
    return ScanSummary(
        id=int(row["id"]),
        started_at=_parse_time(row["started_at"]),
        kind=row["kind"],
        target=row["target"],
        resolved_ip=row["resolved_ip"],
        protocol=row["protocol"],
        method=row["method"],
        scanned=int(row["scanned"]),
        hits=int(row["hits"]),
        duration=row["duration"],
        port_label=row["port_label"],
    )


def _row_to_port_scan(
    row: sqlite3.Row,
    ports: list[sqlite3.Row],
) -> ScanReport:
    results = [
        PortScanResult(
            port=int(item["port"]),
            state=PortState(item["state"]),
            protocol=item["protocol"] or PROTOCOL_TCP,
            service=item["service"],
            response_time=item["response_time"],
            banner=item["banner"],
            banner_kind=item["banner_kind"],
            banner_product=item["banner_product"],
            banner_version=item["banner_version"],
        )
        for item in ports
    ]
    return ScanReport(
        target=row["target"],
        resolved_ip=row["resolved_ip"] or "",
        start_port=int(row["start_port"] or 0),
        end_port=int(row["end_port"] or 0),
        timeout=float(row["timeout"]),
        results=results,
        max_workers=int(row["threads"]),
        duration=row["duration"],
        started_at=_parse_time(row["started_at"]),
        ip_version=int(row["ip_version"]),
        protocol=row["protocol"] or PROTOCOL_TCP,
    )


def _row_to_discovery(
    row: sqlite3.Row,
    hosts: list[sqlite3.Row],
) -> DiscoveryReport:
    results = [
        HostDiscoveryResult(
            ip=item["ip"],
            state=HostState(item["state"]),
            evidence=item["evidence"],
            response_time=item["response_time"],
        )
        for item in hosts
    ]
    return DiscoveryReport(
        spec=row["target"],
        results=results,
        timeout=float(row["timeout"]),
        max_workers=int(row["threads"]),
        duration=row["duration"],
        started_at=_parse_time(row["started_at"]),
        ip_version=int(row["ip_version"]),
    )


def _isoformat(value: datetime) -> str:
    return value.isoformat()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)

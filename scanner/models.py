"""Data models for a single port probe and a full scan report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from scanner.constants import PROTOCOL_TCP
from scanner.port import PortState


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class PortScanResult:
    """Outcome of one TCP connect attempt."""

    port: int
    state: PortState
    protocol: str = PROTOCOL_TCP
    service: str | None = None
    response_time: float | None = None
    banner: str | None = None
    timestamp: datetime = field(default_factory=_utc_now)
    error_code: int | None = None

    def latency_label(self) -> str | None:
        """Return a compact millisecond label, or None if not measured."""
        if self.response_time is None:
            return None
        return f"{self.response_time * 1000:.1f}ms"


@dataclass(slots=True)
class ScanReport:
    """Results for one target and port range."""

    target: str
    resolved_ip: str
    start_port: int
    end_port: int
    timeout: float
    results: list[PortScanResult]
    max_workers: int = 1
    duration: float | None = None
    started_at: datetime = field(default_factory=_utc_now)

    @property
    def open_results(self) -> list[PortScanResult]:
        return [item for item in self.results if item.state is PortState.OPEN]

    def count(self, state: PortState) -> int:
        return sum(1 for item in self.results if item.state is state)

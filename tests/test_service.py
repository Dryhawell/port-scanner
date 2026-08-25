"""Service-name lookup tests. The OS services table is mocked; no network I/O."""

from __future__ import annotations

import pytest

from scanner.banner import sanitize_banner
from scanner.service import lookup_service


def test_lookup_known_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    names = {22: "ssh", 80: "http", 443: "https", 25: "smtp", 53: "domain", 3306: "mysql"}

    def fake_getservbyport(port: int, _protocol: str) -> str:
        if port in names:
            return names[port]
        raise OSError("not found")

    monkeypatch.setattr("scanner.service.socket.getservbyport", fake_getservbyport)
    assert lookup_service(22) == "ssh"
    assert lookup_service(80) == "http"
    assert lookup_service(443) == "https"
    assert lookup_service(25) == "smtp"
    assert lookup_service(53) == "domain"
    assert lookup_service(3306) == "mysql"


def test_lookup_unknown_port(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getservbyport(_port: int, _protocol: str) -> str:
        raise OSError("not found")

    monkeypatch.setattr("scanner.service.socket.getservbyport", fake_getservbyport)
    assert lookup_service(54321) is None


def test_sanitize_banner() -> None:
    assert sanitize_banner(b"SSH-2.0-OpenSSH_9.2\r\n") == "SSH-2.0-OpenSSH_9.2"
    assert sanitize_banner(b"") is None
    assert sanitize_banner(b"\x00\x01") is None
    long_banner = ("A" * 250).encode("ascii")
    cleaned = sanitize_banner(long_banner)
    assert cleaned is not None
    assert cleaned.endswith("...")
    assert len(cleaned) <= 203

"""Scanner tests using mocks. No real remote hosts are contacted."""

from __future__ import annotations

import errno
from unittest.mock import MagicMock

import pytest

from scanner.models import PortScanResult
from scanner.port import PortState
from scanner.scanner import (
    ScannerError,
    TcpConnectScanner,
    _state_from_connect_code,
    probe_tcp_port,
    resolve_ipv4,
)


def test_connect_ex_zero_is_open() -> None:
    assert _state_from_connect_code(0) is PortState.OPEN


def test_connect_ex_refused_is_closed() -> None:
    assert _state_from_connect_code(errno.ECONNREFUSED) is PortState.CLOSED


def test_connect_ex_timed_out_is_timeout() -> None:
    timed_out = getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT)
    assert _state_from_connect_code(timed_out) is PortState.TIMEOUT


def test_probe_open_with_mock_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.connect_ex.return_value = 0
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *args, **kwargs: sock)
    monkeypatch.setattr("scanner.scanner.grab_banner", lambda _sock, _timeout: "SSH-2.0-test")

    result = probe_tcp_port("127.0.0.1", 22, 0.5)
    assert result.state is PortState.OPEN
    assert result.port == 22
    assert result.banner == "SSH-2.0-test"
    assert result.response_time is not None
    sock.close.assert_called_once()


def test_probe_closed_with_mock_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.connect_ex.return_value = errno.ECONNREFUSED
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *args, **kwargs: sock)

    result = probe_tcp_port("127.0.0.1", 81, 0.5)
    assert result.state is PortState.CLOSED
    sock.close.assert_called_once()


def test_probe_timeout_with_mock_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.connect_ex.return_value = getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT)
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *args, **kwargs: sock)

    result = probe_tcp_port("127.0.0.1", 82, 0.5)
    assert result.state is PortState.TIMEOUT
    sock.close.assert_called_once()


def test_resolve_ipv4_uses_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_info = [(None, None, None, None, ("127.0.0.1", 0))]
    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", lambda *args, **kwargs: fake_info)
    assert resolve_ipv4("localhost") == "127.0.0.1"


def test_resolve_ipv4_dns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket as socket_module

    def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise socket_module.gaierror("name failed")

    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", fail)
    with pytest.raises(ScannerError, match="Could not resolve hostname"):
        resolve_ipv4("no-such-host.invalid")


def test_scan_collects_sorted_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.scanner.resolve_ipv4", lambda _target: "127.0.0.1")
    monkeypatch.setattr("scanner.scanner.lookup_service", lambda port, _protocol="tcp": "http" if port == 80 else None)

    def fake_probe(_host: str, port: int, _timeout: float) -> PortScanResult:
        state = PortState.OPEN if port == 80 else PortState.CLOSED
        return PortScanResult(port=port, state=state, response_time=0.01)

    monkeypatch.setattr("scanner.scanner.probe_tcp_port", fake_probe)
    report = TcpConnectScanner().scan("127.0.0.1", 79, 81, timeout=0.5, max_workers=2)

    assert [item.port for item in report.results] == [79, 80, 81]
    assert report.open_results[0].port == 80
    assert report.open_results[0].service == "http"
    assert report.count(PortState.CLOSED) == 2
    assert report.resolved_ip == "127.0.0.1"
    assert report.duration is not None

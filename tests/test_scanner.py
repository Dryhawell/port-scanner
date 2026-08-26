"""Scanner tests using mocks. No real remote hosts are contacted."""

from __future__ import annotations

import errno
import socket
from unittest.mock import MagicMock

import pytest

from scanner.models import PortScanResult
from scanner.port import PortState
from scanner.scanner import (
    ScannerError,
    TcpConnectScanner,
    _state_from_connect_code,
    probe_tcp_port,
    probe_udp_port,
    resolve_host,
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
    monkeypatch.setattr("scanner.scanner.recv_banner", lambda _sock, _timeout: b"SSH-2.0-OpenSSH_9.2")

    result = probe_tcp_port("127.0.0.1", 22, 0.5)
    assert result.state is PortState.OPEN
    assert result.port == 22
    assert result.banner == "SSH-2.0-OpenSSH_9.2"
    assert result.banner_kind == "ssh"
    assert result.banner_product == "OpenSSH"
    assert result.banner_version == "9.2"
    assert result.product_label() == "OpenSSH 9.2"
    assert result.response_time is not None
    sock.close.assert_called_once()


def test_probe_skips_banner_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.connect_ex.return_value = 0
    recv = MagicMock(return_value=b"SSH-2.0-OpenSSH_9.2")
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *args, **kwargs: sock)
    monkeypatch.setattr("scanner.scanner.recv_banner", recv)

    result = probe_tcp_port("127.0.0.1", 22, 0.5, with_banner=False)
    assert result.state is PortState.OPEN
    assert result.banner is None
    recv.assert_not_called()


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
    fake_info = [(socket.AF_INET, None, None, None, ("127.0.0.1", 0))]
    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", lambda *args, **kwargs: fake_info)
    assert resolve_ipv4("localhost") == "127.0.0.1"


def test_resolve_ipv4_dns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise socket.gaierror("name failed")

    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", fail)
    with pytest.raises(ScannerError, match="Could not resolve hostname"):
        resolve_ipv4("no-such-host.invalid")


def test_resolve_host_skips_dns_for_literals(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> list[object]:
        raise AssertionError("literals must not call DNS")

    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", fail)
    ip4, family4 = resolve_host("127.0.0.1")
    assert ip4 == "127.0.0.1"
    assert family4 == socket.AF_INET
    ip6, family6 = resolve_host("::1")
    assert ip6 == "::1"
    assert family6 == socket.AF_INET6


def test_resolve_host_prefers_ipv4_then_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_info = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]

    def fake_getaddrinfo(_host: str, _port: object, family: int = 0, **_kwargs: object) -> list[object]:
        if family == socket.AF_INET6:
            return [fake_info[0]]
        return fake_info

    monkeypatch.setattr("scanner.scanner.socket.getaddrinfo", fake_getaddrinfo)
    ip, family = resolve_host("localhost")
    assert ip == "127.0.0.1"
    assert family == socket.AF_INET
    ip6, family6 = resolve_host("localhost", prefer_ipv6=True)
    assert ip6 == "::1"
    assert family6 == socket.AF_INET6


def test_probe_ipv6_uses_inet6_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.connect_ex.return_value = 0
    families: list[int] = []

    def fake_socket(family: int, *_args: object, **_kwargs: object) -> MagicMock:
        families.append(family)
        return sock

    monkeypatch.setattr("scanner.scanner.socket.socket", fake_socket)
    monkeypatch.setattr("scanner.scanner.recv_banner", lambda _sock, _timeout: None)

    result = probe_tcp_port("::1", 80, 0.5, family=socket.AF_INET6)
    assert result.state is PortState.OPEN
    assert families == [socket.AF_INET6]
    sock.connect_ex.assert_called_once_with(("::1", 80, 0, 0))


def test_scan_collects_sorted_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scanner.scanner.resolve_host",
        lambda _target, prefer_ipv6=False: ("127.0.0.1", socket.AF_INET),
    )
    monkeypatch.setattr("scanner.scanner.lookup_service", lambda port, _protocol="tcp": "http" if port == 80 else None)

    def fake_probe(
        _host: str,
        port: int,
        _timeout: float,
        **_kwargs: object,
    ) -> PortScanResult:
        state = PortState.OPEN if port == 80 else PortState.CLOSED
        return PortScanResult(port=port, state=state, response_time=0.01)

    monkeypatch.setattr("scanner.scanner.probe_tcp_port", fake_probe)
    report = TcpConnectScanner().scan("127.0.0.1", 79, 81, timeout=0.5, max_workers=2)

    assert [item.port for item in report.results] == [79, 80, 81]
    assert report.open_results[0].port == 80
    assert report.open_results[0].service == "http"
    assert report.count(PortState.CLOSED) == 2
    assert report.resolved_ip == "127.0.0.1"
    assert report.ip_version == 4
    assert report.duration is not None


def test_scan_accepts_explicit_port_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scanner.scanner.resolve_host",
        lambda _target, prefer_ipv6=False: ("127.0.0.1", socket.AF_INET),
    )
    monkeypatch.setattr("scanner.scanner.lookup_service", lambda _port, _protocol="tcp": None)

    def fake_probe(
        _host: str,
        port: int,
        _timeout: float,
        **_kwargs: object,
    ) -> PortScanResult:
        return PortScanResult(port=port, state=PortState.CLOSED)

    monkeypatch.setattr("scanner.scanner.probe_tcp_port", fake_probe)
    report = TcpConnectScanner().scan(
        "127.0.0.1",
        timeout=0.5,
        max_workers=2,
        ports=[443, 80, 80],
    )

    assert [item.port for item in report.results] == [80, 443]
    assert report.port_label() == "80,443"


def test_scan_ipv6_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scanner.scanner.resolve_host",
        lambda _target, prefer_ipv6=False: ("::1", socket.AF_INET6),
    )
    monkeypatch.setattr("scanner.scanner.lookup_service", lambda _port, _protocol="tcp": None)

    def fake_probe(
        _host: str,
        port: int,
        _timeout: float,
        **_kwargs: object,
    ) -> PortScanResult:
        return PortScanResult(port=port, state=PortState.CLOSED)

    monkeypatch.setattr("scanner.scanner.probe_tcp_port", fake_probe)
    report = TcpConnectScanner().scan("::1", 80, 80, timeout=0.5, max_workers=1)

    assert report.resolved_ip == "::1"
    assert report.ip_version == 6
    assert [item.port for item in report.results] == [80]


def test_probe_udp_reply_is_open(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.recv.return_value = b"\x00reply"
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *_args, **_kwargs: sock)
    monkeypatch.setattr(
        "scanner.scanner.select.select",
        lambda *_args, **_kwargs: ([sock], [], []),
    )
    result = probe_udp_port("127.0.0.1", 53, 0.5)
    assert result.state is PortState.OPEN
    assert result.protocol == "udp"
    sock.send.assert_called()


def test_probe_udp_icmp_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    sock.recv.side_effect = OSError(errno.ECONNREFUSED, "refused")
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *_args, **_kwargs: sock)
    monkeypatch.setattr(
        "scanner.scanner.select.select",
        lambda *_args, **_kwargs: ([sock], [], []),
    )
    result = probe_udp_port("127.0.0.1", 9, 0.5)
    assert result.state is PortState.CLOSED
    assert result.protocol == "udp"


def test_probe_udp_silence_is_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = MagicMock()
    would_block = getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK)
    sock.recv.side_effect = OSError(would_block, "would block")
    monkeypatch.setattr("scanner.scanner.socket.socket", lambda *_args, **_kwargs: sock)
    monkeypatch.setattr(
        "scanner.scanner.select.select",
        lambda *_args, **_kwargs: ([], [], []),
    )
    result = probe_udp_port("127.0.0.1", 53, 0.5)
    assert result.state is PortState.TIMEOUT
    assert result.protocol == "udp"


def test_scan_udp_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scanner.scanner.resolve_host",
        lambda _target, prefer_ipv6=False: ("127.0.0.1", socket.AF_INET),
    )
    monkeypatch.setattr(
        "scanner.scanner.lookup_service",
        lambda _port, protocol="tcp": "domain" if protocol == "udp" else None,
    )

    def fake_udp(
        _host: str,
        port: int,
        _timeout: float,
        **_kwargs: object,
    ) -> PortScanResult:
        return PortScanResult(port=port, state=PortState.OPEN, protocol="udp")

    monkeypatch.setattr("scanner.scanner.probe_udp_port", fake_udp)
    report = TcpConnectScanner().scan(
        "127.0.0.1",
        53,
        53,
        timeout=0.5,
        max_workers=1,
        protocol="udp",
    )
    assert report.protocol == "udp"
    assert report.open_results[0].service == "domain"

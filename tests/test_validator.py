"""Unit tests for target, port, timeout, and thread validation."""

from __future__ import annotations

import pytest

from scanner.constants import SCAN_PROFILES, UDP_SCAN_PROFILES
from scanner.validator import (
    ValidationError,
    parse_port_range,
    parse_ports,
    resolve_scan_profile,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_target,
    validate_threads,
    validate_timeout,
)


def test_valid_ipv4() -> None:
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target(" 192.168.1.10 ") == "192.168.1.10"


def test_invalid_ipv4() -> None:
    with pytest.raises(ValidationError, match="Invalid IP address"):
        validate_target("999.1.1.1")
    with pytest.raises(ValidationError, match="Invalid IP address"):
        validate_target("127.0.0.256")


def test_valid_hostname() -> None:
    assert validate_target("localhost") == "localhost"
    assert validate_target("example.com") == "example.com"
    assert validate_target("example.com.") == "example.com"


def test_invalid_hostname() -> None:
    with pytest.raises(ValidationError, match="Invalid target"):
        validate_target("")
    with pytest.raises(ValidationError, match="Invalid target"):
        validate_target("http://example.com")
    with pytest.raises(ValidationError, match="Invalid hostname"):
        validate_target("-bad.example.com")


def test_valid_ipv6() -> None:
    assert validate_target("::1") == "::1"
    assert validate_target("[::1]") == "::1"
    assert validate_target("2001:db8::1") == "2001:db8::1"
    assert validate_target(" 2001:0DB8:0000::1 ") == "2001:db8::1"


def test_invalid_ipv6() -> None:
    with pytest.raises(ValidationError, match="Invalid IP address"):
        validate_target("gggg::1")
    with pytest.raises(ValidationError, match="Invalid IP address"):
        validate_target("[::1]:80")
    with pytest.raises(ValidationError, match="zone identifiers"):
        validate_target("fe80::1%eth0")


def test_invalid_port() -> None:
    with pytest.raises(ValidationError, match="between 1 and 65535"):
        validate_port(0)
    with pytest.raises(ValidationError, match="between 1 and 65535"):
        validate_port(65536)
    with pytest.raises(ValidationError, match="between 1 and 65535"):
        validate_port("abc")
    with pytest.raises(ValidationError, match="between 1 and 65535"):
        validate_port(True)


def test_valid_port_range() -> None:
    assert validate_port(80) == 80
    assert validate_port("443") == 443
    assert validate_port_range(1, 1000) == (1, 1000)
    assert validate_port_range("20", "100") == (20, 100)
    assert parse_port_range("80") == (80, 80)
    assert parse_port_range("1-1000") == (1, 1000)


def test_invalid_port_range() -> None:
    with pytest.raises(ValidationError, match="Invalid port range"):
        validate_port_range(1000, 1)
    with pytest.raises(ValidationError, match="Invalid port range"):
        parse_port_range("1-")
    with pytest.raises(ValidationError, match="Invalid port range"):
        parse_port_range("1-2-3")
    with pytest.raises(ValidationError, match="Invalid port range"):
        parse_port_range("")


def test_parse_ports_list_and_range() -> None:
    assert parse_ports("80") == [80]
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]
    assert parse_ports("443,80,80") == [80, 443]


def test_parse_ports_rejects_empty() -> None:
    with pytest.raises(ValidationError, match="Invalid port range"):
        parse_ports("")
    with pytest.raises(ValidationError, match="Invalid port range"):
        parse_ports("22,,80")


def test_resolve_scan_profile() -> None:
    assert resolve_scan_profile("quick") == list(SCAN_PROFILES["quick"])
    assert resolve_scan_profile(" COMMON ") == list(SCAN_PROFILES["common"])
    assert resolve_scan_profile("quick", protocol="udp") == list(UDP_SCAN_PROFILES["quick"])
    with pytest.raises(ValidationError, match="Unknown scan profile"):
        resolve_scan_profile("stealth")


def test_validate_protocol() -> None:
    assert validate_protocol("TCP") == "tcp"
    assert validate_protocol("udp") == "udp"
    with pytest.raises(ValidationError, match="tcp or udp"):
        validate_protocol("icmp")


def test_timeout_and_threads() -> None:
    assert validate_timeout("0.5") == 0.5
    assert validate_timeout(1) == 1.0
    with pytest.raises(ValidationError, match="positive number"):
        validate_timeout(0)
    with pytest.raises(ValidationError, match="positive number"):
        validate_timeout(True)
    assert validate_threads("50") == 50
    with pytest.raises(ValidationError, match="between 1 and"):
        validate_threads(0)
    with pytest.raises(ValidationError, match="between 1 and"):
        validate_threads(201)

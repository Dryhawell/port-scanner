"""Unit tests for target, port, timeout, and thread validation."""

from __future__ import annotations

import pytest

from scanner.validator import (
    ValidationError,
    parse_port_range,
    validate_port,
    validate_port_range,
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
    with pytest.raises(ValidationError, match="IPv6"):
        validate_target("::1")
    with pytest.raises(ValidationError, match="Invalid hostname"):
        validate_target("-bad.example.com")


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

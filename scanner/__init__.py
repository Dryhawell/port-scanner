"""TCP connect scan engine: validation, probing, service hints, and banners."""

from scanner.banner import grab_banner, sanitize_banner
from scanner.models import PortScanResult, ScanReport
from scanner.port import PortState
from scanner.scanner import ScannerError, TcpConnectScanner, probe_tcp_port, resolve_host, resolve_ipv4
from scanner.service import lookup_service
from scanner.validator import (
    ValidationError,
    parse_port_range,
    parse_ports,
    resolve_scan_profile,
    validate_port,
    validate_port_range,
    validate_target,
    validate_threads,
    validate_timeout,
)

__all__ = [
    "PortScanResult",
    "PortState",
    "ScanReport",
    "ScannerError",
    "TcpConnectScanner",
    "ValidationError",
    "grab_banner",
    "lookup_service",
    "parse_port_range",
    "parse_ports",
    "probe_tcp_port",
    "resolve_host",
    "resolve_ipv4",
    "resolve_scan_profile",
    "sanitize_banner",
    "validate_port",
    "validate_port_range",
    "validate_target",
    "validate_threads",
    "validate_timeout",
]

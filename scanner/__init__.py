"""TCP connect scan engine: validation, probing, discovery, service hints, and banners."""

from scanner.banner import (
    BannerHint,
    classify_banner,
    grab_banner,
    parse_banner,
    sanitize_banner,
)
from scanner.discover import discover_hosts, probe_host
from scanner.models import (
    DiscoveryReport,
    HostDiscoveryResult,
    HostState,
    PortScanResult,
    ScanReport,
)
from scanner.port import PortState
from scanner.scanner import (
    ScannerError,
    TcpConnectScanner,
    probe_tcp_port,
    probe_udp_port,
    resolve_host,
    resolve_ipv4,
)
from scanner.service import lookup_service
from scanner.validator import (
    ValidationError,
    parse_discovery_targets,
    parse_port_range,
    parse_ports,
    resolve_scan_profile,
    validate_interval,
    validate_port,
    validate_port_range,
    validate_protocol,
    validate_runs,
    validate_target,
    validate_threads,
    validate_timeout,
)

__all__ = [
    "BannerHint",
    "DiscoveryReport",
    "HostDiscoveryResult",
    "HostState",
    "PortScanResult",
    "PortState",
    "ScanReport",
    "ScannerError",
    "TcpConnectScanner",
    "ValidationError",
    "classify_banner",
    "discover_hosts",
    "grab_banner",
    "lookup_service",
    "parse_banner",
    "parse_discovery_targets",
    "parse_port_range",
    "parse_ports",
    "probe_host",
    "probe_tcp_port",
    "probe_udp_port",
    "resolve_host",
    "resolve_ipv4",
    "resolve_scan_profile",
    "sanitize_banner",
    "validate_interval",
    "validate_port",
    "validate_port_range",
    "validate_protocol",
    "validate_runs",
    "validate_target",
    "validate_threads",
    "validate_timeout",
]

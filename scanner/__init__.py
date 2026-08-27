"""TCP connect scan engine: validation, probing, discovery, service hints, and banners."""

from scanner.advisory import Advisory, lookup_advisories
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
    exclude_ports,
    parse_discovery_targets,
    parse_port_range,
    parse_ports,
    parse_target_file,
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
    "Advisory",
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
    "exclude_ports",
    "grab_banner",
    "lookup_advisories",
    "lookup_service",
    "parse_banner",
    "parse_discovery_targets",
    "parse_port_range",
    "parse_ports",
    "parse_target_file",
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

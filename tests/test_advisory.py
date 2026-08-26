"""Local reference-note tests. No network I/O, no exploit content."""

from __future__ import annotations

from scanner.advisory import advisory_label, lookup_advisories
from scanner.models import PortScanResult
from scanner.port import PortState


def test_closed_port_has_no_note() -> None:
    result = PortScanResult(port=23, state=PortState.CLOSED, service="telnet")
    assert lookup_advisories(result) == ()
    assert advisory_label(result) == ""


def test_telnet_open_is_cleartext_note() -> None:
    result = PortScanResult(port=23, state=PortState.OPEN, service="telnet")
    notes = lookup_advisories(result)
    assert len(notes) == 1
    assert notes[0].ids == ("CWE-319",)
    assert "cleartext" in notes[0].summary.lower() or "encryption" in notes[0].summary.lower()
    assert "exploit" not in notes[0].summary.lower()
    assert "CWE-319" in notes[0].line()


def test_ssh_open_is_hardening_not_cve_dump() -> None:
    result = PortScanResult(
        port=22,
        state=PortState.OPEN,
        service="ssh",
        banner_product="OpenSSH",
        banner_version="9.2",
    )
    notes = lookup_advisories(result)
    assert len(notes) == 1
    assert notes[0].key == "ssh-hardening"
    assert notes[0].ids == ()


def test_vsftpd_historical_version_only() -> None:
    hit = PortScanResult(
        port=21,
        state=PortState.OPEN,
        service="ftp",
        banner_product="vsftpd",
        banner_version="2.3.4",
    )
    notes = lookup_advisories(hit)
    keys = [item.key for item in notes]
    assert "vsftpd-2.3.4" in keys
    assert "ftp-cleartext" in keys
    assert notes[0].ids == ("CVE-2011-2523",)
    assert "does not verify" in notes[0].summary.lower()

    other = PortScanResult(
        port=21,
        state=PortState.OPEN,
        service="ftp",
        banner_product="vsftpd",
        banner_version="3.0.3",
    )
    other_keys = [item.key for item in lookup_advisories(other)]
    assert "vsftpd-2.3.4" not in other_keys
    assert "ftp-cleartext" in other_keys


def test_service_alias_when_port_unusual() -> None:
    result = PortScanResult(port=2323, state=PortState.OPEN, service="telnet")
    notes = lookup_advisories(result)
    assert notes and notes[0].key == "telnet-cleartext"


def test_advisory_label_counts_extra() -> None:
    result = PortScanResult(
        port=21,
        state=PortState.OPEN,
        service="ftp",
        banner_product="vsftpd",
        banner_version="2.3.4",
    )
    label = advisory_label(result)
    assert "vsftpd" in label.lower() or "Historical" in label
    assert "+1" in label

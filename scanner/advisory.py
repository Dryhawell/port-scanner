"""Local reference notes for open ports and a few well-known banners.

This is a static lookup table, not a vulnerability scanner, not a CVE feed,
and not an exploit database. A note means "this service is worth studying",
not "the host is compromised". Version rows match only a handful of famous
lab builds (exact product + version). There is no live NVD query.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.models import PortScanResult
from scanner.port import PortState

DISCLAIMER = "Reference notes are local hints, not a vulnerability scan."


@dataclass(frozen=True, slots=True)
class Advisory:
    """One hardening or historical pointer. No exploit steps."""

    key: str
    title: str
    summary: str
    ids: tuple[str, ...] = ()

    def line(self) -> str:
        extra = f" [{', '.join(self.ids)}]" if self.ids else ""
        return f"{self.title}{extra}. {self.summary}"

    def short_label(self) -> str:
        if self.ids:
            return f"{self.title} ({self.ids[0]})"
        return self.title

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "summary": self.summary,
            "ids": list(self.ids),
        }


# Exact product (lowercase) + version from the passive banner. Lab textbook
# cases only. This is not a CPE matcher and not "all CVEs for OpenSSH < 8".
_VERSION_NOTES: dict[tuple[str, str], Advisory] = {
    ("vsftpd", "2.3.4"): Advisory(
        key="vsftpd-2.3.4",
        title="Historical vsftpd 2.3.4 backdoor",
        summary=(
            "This specific release is a well-known classroom incident. "
            "Look up the CVE on NVD if you are studying it. This tool "
            "does not verify, trigger, or exploit it."
        ),
        ids=("CVE-2011-2523",),
    ),
}

# Port + protocol. Exposure / hardening only. Historical CVE IDs are patch
# pointers, not a claim that this host is unpatched.
_PORT_NOTES: dict[tuple[int, str], Advisory] = {
    (21, "tcp"): Advisory(
        key="ftp-cleartext",
        title="FTP is cleartext",
        summary="USER/PASS and file data are not encrypted. Prefer SFTP or FTPS on systems you manage.",
        ids=("CWE-319",),
    ),
    (23, "tcp"): Advisory(
        key="telnet-cleartext",
        title="Telnet is cleartext",
        summary="Remote login without encryption. Prefer SSH. A listening telnetd is not proof of a CVE.",
        ids=("CWE-319",),
    ),
    (25, "tcp"): Advisory(
        key="smtp-open",
        title="SMTP submission",
        summary="Mail transfer. Restrict relay; do not treat an open 25 as a confirmed bug.",
    ),
    (69, "udp"): Advisory(
        key="tftp",
        title="TFTP has no login",
        summary="Trivial File Transfer is unauthenticated. Limit to a lab VLAN if you still need it.",
        ids=("CWE-306",),
    ),
    (111, "tcp"): Advisory(
        key="rpcbind",
        title="RPC portmapper",
        summary="Often paired with NFS. Do not expose rpcbind to untrusted networks.",
    ),
    (135, "tcp"): Advisory(
        key="msrpc",
        title="Windows RPC endpoint mapper",
        summary="Keep the host patched and off the public internet. This scan does not speak MS-RPC.",
    ),
    (139, "tcp"): Advisory(
        key="netbios",
        title="NetBIOS session",
        summary="Legacy Windows file sharing. Prefer disabling SMBv1 and NetBIOS on modern hosts.",
    ),
    (161, "udp"): Advisory(
        key="snmp",
        title="SNMP community strings",
        summary="Default or public communities leak host data. Use SNMPv3. This probe does not guess communities.",
        ids=("CWE-259",),
    ),
    (389, "tcp"): Advisory(
        key="ldap",
        title="LDAP directory",
        summary="Prefer LDAP over TLS. An open 389 is a service hint, not a bind bypass.",
    ),
    (445, "tcp"): Advisory(
        key="smb",
        title="SMB file sharing",
        summary=(
            "High-value Windows/Samba service. Disable SMBv1; apply vendor patches. "
            "MS17-010 is a historical patch reference, not a detection."
        ),
        ids=("CVE-2017-0144",),
    ),
    (1433, "tcp"): Advisory(
        key="mssql",
        title="Microsoft SQL Server",
        summary="Do not expose the database port to the internet. Use a firewall and strong auth.",
    ),
    (2049, "tcp"): Advisory(
        key="nfs",
        title="NFS",
        summary="Export lists and auth are outside this scan. Restrict NFS to trusted networks.",
    ),
    (2375, "tcp"): Advisory(
        key="docker-tcp",
        title="Docker API without TLS",
        summary="Port 2375 is the unencrypted Docker socket. Bind it to localhost or use 2376 with TLS.",
        ids=("CWE-306",),
    ),
    (3306, "tcp"): Advisory(
        key="mysql",
        title="MySQL / MariaDB",
        summary="Keep the listener off public addresses. This scan does not try passwords.",
    ),
    (3389, "tcp"): Advisory(
        key="rdp",
        title="Remote Desktop",
        summary=(
            "Put RDP behind a VPN or gateway. CVE-2019-0708 (BlueKeep) is a historical "
            "RDP patch reference; this tool does not test it."
        ),
        ids=("CVE-2019-0708",),
    ),
    (5432, "tcp"): Advisory(
        key="postgres",
        title="PostgreSQL",
        summary="Do not expose the database port publicly. Check pg_hba.conf on hosts you own.",
    ),
    (5900, "tcp"): Advisory(
        key="vnc",
        title="VNC remote display",
        summary="Lab images often use a weak or empty VNC password. Prefer SSH tunnels. Not a brute-force check.",
        ids=("CWE-521",),
    ),
    (6379, "tcp"): Advisory(
        key="redis",
        title="Redis",
        summary="Default installs may have no AUTH and bind all interfaces. Restrict to localhost or require a password.",
        ids=("CWE-306",),
    ),
    (9200, "tcp"): Advisory(
        key="elasticsearch",
        title="Elasticsearch HTTP",
        summary="Older defaults had no auth. Enable security and do not publish 9200.",
        ids=("CWE-306",),
    ),
    (11211, "tcp"): Advisory(
        key="memcached",
        title="Memcached",
        summary="No application auth. Bind to localhost. UDP memcached was abused for amplification; this probe is not that.",
        ids=("CWE-306",),
    ),
    (27017, "tcp"): Advisory(
        key="mongodb",
        title="MongoDB",
        summary="Historical defaults had no auth. Enable authentication and bind to trusted addresses.",
        ids=("CWE-306",),
    ),
}

_SERVICE_ALIASES: dict[str, tuple[int, str]] = {
    "ftp": (21, "tcp"),
    "telnet": (23, "tcp"),
    "smtp": (25, "tcp"),
    "tftp": (69, "udp"),
    "sunrpc": (111, "tcp"),
    "rpcbind": (111, "tcp"),
    "epmap": (135, "tcp"),
    "netbios-ssn": (139, "tcp"),
    "snmp": (161, "udp"),
    "ldap": (389, "tcp"),
    "microsoft-ds": (445, "tcp"),
    "ms-wbt-server": (3389, "tcp"),
    "rdp": (3389, "tcp"),
    "mysql": (3306, "tcp"),
    "postgresql": (5432, "tcp"),
    "vnc": (5900, "tcp"),
    "redis": (6379, "tcp"),
    "docker": (2375, "tcp"),
    "elasticsearch": (9200, "tcp"),
    "memcached": (11211, "tcp"),
    "mongodb": (27017, "tcp"),
}

_SSH = Advisory(
    key="ssh-hardening",
    title="SSH remote login",
    summary="Encrypted admin access. Prefer keys over passwords and keep the daemon patched. An open 22 is expected, not a finding.",
)

_HTTP = Advisory(
    key="http-cleartext",
    title="HTTP without TLS",
    summary="Application data is cleartext unless the app redirects to HTTPS. This scan does not send GET or read certificates.",
    ids=("CWE-319",),
)


def lookup_advisories(result: PortScanResult) -> tuple[Advisory, ...]:
    """Return zero or more notes for an OPEN result. Closed/timeout stay silent."""
    if result.state is not PortState.OPEN:
        return ()
    notes: list[Advisory] = []
    seen: set[str] = set()

    def add(note: Advisory | None) -> None:
        if note is None or note.key in seen:
            return
        seen.add(note.key)
        notes.append(note)

    add(_version_note(result))
    add(_PORT_NOTES.get((result.port, result.protocol)))
    if result.service:
        alias = _SERVICE_ALIASES.get(result.service.lower())
        if alias:
            add(_PORT_NOTES.get(alias))
    if result.port == 22 and result.protocol == "tcp":
        add(_SSH)
    if result.port in {80, 8080} and result.protocol == "tcp":
        add(_HTTP)
    return tuple(notes)


def advisory_label(result: PortScanResult) -> str:
    """Compact GUI/CSV cell: first note title, or empty."""
    notes = lookup_advisories(result)
    if not notes:
        return ""
    if len(notes) == 1:
        return notes[0].short_label()
    return notes[0].short_label() + f" +{len(notes) - 1}"


def _version_note(result: PortScanResult) -> Advisory | None:
    product = (result.banner_product or "").strip().lower()
    version = (result.banner_version or "").strip()
    if not product or not version:
        return None
    return _VERSION_NOTES.get((product, version))

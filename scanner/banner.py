"""Passive banner capture and light parsing for open TCP ports.

Only data the server sends first is read. This module does not send HTTP,
SMTP, TLS, or other application probes. Many services (HTTP, TLS) send nothing
until the client speaks, so a missing banner is normal.

classify_banner() looks at raw bytes first (MySQL greeting, TLS record, AMQP,
Telnet IAC), then parse_banner() classifies ASCII greetings. A match is a hint
from the greeting, not proof of a specific daemon or a vulnerability.
"""

from __future__ import annotations

import re
import select
import socket
from dataclasses import dataclass

from scanner.constants import (
    DEFAULT_BANNER_TIMEOUT,
    MAX_BANNER_BYTES,
    MAX_BANNER_CHARS,
)

_SSH = re.compile(r"^SSH-(?P<proto>\d+\.\d+)-(?P<software>\S+)", re.IGNORECASE)
_GREETING_220 = re.compile(r"^220[\s-]")
_POP3 = re.compile(r"^\+OK\b", re.IGNORECASE)
_IMAP = re.compile(r"^\*\s+OK\b", re.IGNORECASE)
_HTTP = re.compile(r"^HTTP/\d", re.IGNORECASE)
_VSFTPD = re.compile(r"vsftpd\s+([\w.]+)", re.IGNORECASE)
_PROFTPD = re.compile(r"proftpd\s+([\w.]+)", re.IGNORECASE)
_FILEZILLA = re.compile(r"filezilla server(?:\s+([\w.]+))?", re.IGNORECASE)
_EXIM = re.compile(r"\bexim\s+([\w.]+)", re.IGNORECASE)
_POSTFIX = re.compile(r"\bpostfix\b", re.IGNORECASE)
_SENDMAIL = re.compile(r"\bsendmail\b", re.IGNORECASE)
_MS_ESMTP = re.compile(r"microsoft esmtp(?: mail service)?(?:,?\s*version:\s*([\w.]+))?", re.IGNORECASE)
_MS_FTP = re.compile(r"microsoft ftp service", re.IGNORECASE)
_DOVECOT = re.compile(r"\bdovecot\b", re.IGNORECASE)
_RFB = re.compile(r"^RFB (\d{3}\.\d{3})")
_HTTP_SERVER = re.compile(r"\bServer:\s*(\S+)", re.IGNORECASE)
_REDIS_ERR = re.compile(r"^-(?:ERR|NOAUTH)\b", re.IGNORECASE)
_MYSQL_VERSION = re.compile(r"^\d+\.\d+")
_VERSIONISH = re.compile(r"^\d")

_PRODUCT_NAMES = {
    "openssh": "OpenSSH",
    "dropbear": "Dropbear",
    "libssh": "libssh",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "postfix": "Postfix",
    "exim": "Exim",
    "dovecot": "Dovecot",
    "filezilla": "FileZilla",
    "sendmail": "Sendmail",
    "nginx": "nginx",
    "apache": "Apache",
    "microsoft-iis": "Microsoft-IIS",
}


@dataclass(frozen=True, slots=True)
class BannerHint:
    """Structured fields extracted from a sanitized banner line."""

    kind: str | None = None
    product: str | None = None
    version: str | None = None


def recv_banner(sock: socket.socket, timeout: float) -> bytes | None:
    """Read raw bytes if the peer sends data within the wait window."""
    wait = min(timeout, DEFAULT_BANNER_TIMEOUT)
    readable, _writable, _errors = select.select([sock], [], [], wait)
    if not readable:
        return None
    try:
        raw = sock.recv(MAX_BANNER_BYTES)
    except OSError:
        return None
    return raw or None


def grab_banner(sock: socket.socket, timeout: float) -> str | None:
    """Read a short banner if the peer sends data within the wait window."""
    return sanitize_banner(recv_banner(sock, timeout))


def classify_banner(raw: bytes | None) -> BannerHint:
    """Classify unsolicited bytes: binary signatures first, then text greetings."""
    if not raw:
        return BannerHint()
    binary = _parse_binary_banner(raw)
    if binary.kind:
        return binary
    return parse_banner(sanitize_banner(raw))


def visible_banner(raw: bytes | None, hint: BannerHint) -> str | None:
    """Prefer the ASCII greeting; use a short label for binary-only protocols."""
    if hint.kind in {"mysql", "tls", "amqp", "telnet"}:
        if hint.product and hint.version:
            return f"{hint.product} {hint.version}"
        return hint.product or hint.kind
    if not raw:
        return None
    return sanitize_banner(raw)


def sanitize_banner(raw: bytes) -> str | None:
    """Decode and trim banner bytes into a single printable line."""
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = " ".join(part.strip() for part in text.split("\n") if part.strip())
    text = "".join(char if char.isprintable() else " " for char in text)
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > MAX_BANNER_CHARS:
        return text[:MAX_BANNER_CHARS].rstrip() + "..."
    return text


def parse_banner(text: str | None) -> BannerHint:
    """Classify an already-sanitized banner. Unknown text yields empty fields."""
    if not text or not text.strip():
        return BannerHint()
    cleaned = text.strip()

    ssh = _parse_ssh(cleaned)
    if ssh.kind:
        return ssh
    if _HTTP.match(cleaned):
        return _parse_http(cleaned)
    if _POP3.match(cleaned):
        return BannerHint(kind="pop3", product=_product_if_dovecot(cleaned))
    if _IMAP.match(cleaned):
        return BannerHint(kind="imap", product=_product_if_dovecot(cleaned))
    rfb = _RFB.match(cleaned)
    if rfb:
        return BannerHint(kind="vnc", product="VNC", version=rfb.group(1))
    if _REDIS_ERR.match(cleaned):
        return BannerHint(kind="redis")
    if cleaned.startswith("AMQP"):
        return BannerHint(kind="amqp", product="AMQP")
    if _GREETING_220.match(cleaned):
        return _parse_220(cleaned)
    return BannerHint()


def _parse_binary_banner(raw: bytes) -> BannerHint:
    if raw.startswith(b"AMQP"):
        return BannerHint(kind="amqp", product="AMQP")
    if len(raw) >= 3 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] <= 0x04:
        return BannerHint(kind="tls", product="TLS")
    mysql = _parse_mysql_handshake(raw)
    if mysql.kind:
        return mysql
    if len(raw) >= 3 and raw[0] == 0xFF and raw[1] in {0xFA, 0xFB, 0xFC, 0xFD, 0xFE}:
        return BannerHint(kind="telnet")
    return BannerHint()


def _parse_mysql_handshake(raw: bytes) -> BannerHint:
    """MySQL/MariaDB protocol 10 greeting: 3-byte length, seq, 0x0a, version\\0."""
    if len(raw) < 8:
        return BannerHint()
    length = int.from_bytes(raw[0:3], "little")
    if length < 5 or length > MAX_BANNER_BYTES:
        return BannerHint()
    if raw[4] != 10:
        return BannerHint()
    rest = raw[5:]
    nul = rest.find(b"\x00")
    if nul < 3:
        return BannerHint()
    try:
        version = rest[:nul].decode("ascii")
    except UnicodeDecodeError:
        return BannerHint()
    if not _MYSQL_VERSION.match(version):
        return BannerHint()
    product, pretty = _mysql_product_version(version)
    return BannerHint(kind="mysql", product=product, version=pretty)


def _mysql_product_version(version: str) -> tuple[str, str]:
    if "mariadb" not in version.lower():
        return "MySQL", version
    for part in version.split("-"):
        if part.lower() == "mariadb":
            continue
        if _MYSQL_VERSION.match(part) and not part.startswith("5.5.5"):
            return "MariaDB", part
    return "MariaDB", version


def _parse_http(text: str) -> BannerHint:
    match = _HTTP_SERVER.search(text)
    if match is None:
        return BannerHint(kind="http")
    product, version = _split_product_version(match.group(1).rstrip(";,"))
    return BannerHint(kind="http", product=product, version=version)


def _parse_ssh(text: str) -> BannerHint:
    match = _SSH.match(text)
    if match is None:
        return BannerHint()
    product, version = _split_product_version(match.group("software"))
    return BannerHint(kind="ssh", product=product, version=version)


def _parse_220(text: str) -> BannerHint:
    lowered = text.lower()
    looks_smtp = "esmtp" in lowered or bool(re.search(r"\bsmtp\b", lowered))
    looks_ftp = (
        "ftp" in lowered
        or "vsftpd" in lowered
        or "proftpd" in lowered
        or "filezilla" in lowered
    )
    if looks_smtp and not looks_ftp:
        return _parse_smtp(text)
    if looks_ftp and not looks_smtp:
        return _parse_ftp(text)
    if looks_smtp:
        return _parse_smtp(text)
    if looks_ftp:
        return _parse_ftp(text)
    return BannerHint()


def _parse_ftp(text: str) -> BannerHint:
    match = _VSFTPD.search(text)
    if match:
        return BannerHint(kind="ftp", product="vsftpd", version=match.group(1))
    match = _PROFTPD.search(text)
    if match:
        return BannerHint(kind="ftp", product="ProFTPD", version=match.group(1))
    match = _FILEZILLA.search(text)
    if match:
        return BannerHint(kind="ftp", product="FileZilla", version=match.group(1))
    if _MS_FTP.search(text):
        return BannerHint(kind="ftp", product="Microsoft FTP")
    return BannerHint(kind="ftp")


def _parse_smtp(text: str) -> BannerHint:
    match = _EXIM.search(text)
    if match:
        return BannerHint(kind="smtp", product="Exim", version=match.group(1))
    if _POSTFIX.search(text):
        return BannerHint(kind="smtp", product="Postfix")
    if _SENDMAIL.search(text):
        return BannerHint(kind="smtp", product="Sendmail")
    match = _MS_ESMTP.search(text)
    if match:
        return BannerHint(kind="smtp", product="Microsoft ESMTP", version=match.group(1))
    return BannerHint(kind="smtp")


def _product_if_dovecot(text: str) -> str | None:
    if _DOVECOT.search(text):
        return "Dovecot"
    return None


def _split_product_version(software: str) -> tuple[str, str | None]:
    for separator in ("_", "/"):
        if separator in software:
            name, rest = software.split(separator, 1)
            if name and rest and _VERSIONISH.match(rest):
                return _pretty_product(name), rest
    if "-" in software:
        name, rest = software.split("-", 1)
        if name and rest and _VERSIONISH.match(rest):
            return _pretty_product(name), rest
    return _pretty_product(software), None


def _pretty_product(name: str) -> str:
    return _PRODUCT_NAMES.get(name.lower(), name)

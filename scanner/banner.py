"""Passive banner capture and light parsing for open TCP ports.

Only data the server sends first is read. This module does not send HTTP,
SMTP, or other application probes. Many services (HTTP, TLS) send nothing
until the client speaks, so a missing banner is normal.

parse_banner() classifies that unsolicited text. A match is a hint from the
greeting, not proof of a specific daemon or a vulnerability.
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
}


@dataclass(frozen=True, slots=True)
class BannerHint:
    """Structured fields extracted from a sanitized banner line."""

    kind: str | None = None
    product: str | None = None
    version: str | None = None


def grab_banner(sock: socket.socket, timeout: float) -> str | None:
    """Read a short banner if the peer sends data within the wait window."""
    wait = min(timeout, DEFAULT_BANNER_TIMEOUT)
    readable, _writable, _errors = select.select([sock], [], [], wait)
    if not readable:
        return None
    try:
        raw = sock.recv(MAX_BANNER_BYTES)
    except OSError:
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
        return BannerHint(kind="http")
    if _POP3.match(cleaned):
        return BannerHint(kind="pop3", product=_product_if_dovecot(cleaned))
    if _IMAP.match(cleaned):
        return BannerHint(kind="imap", product=_product_if_dovecot(cleaned))
    if _GREETING_220.match(cleaned):
        return _parse_220(cleaned)
    return BannerHint()


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

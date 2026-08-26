"""Passive banner sanitize and parse tests. No network I/O."""

from __future__ import annotations

from scanner.banner import parse_banner, sanitize_banner


def test_sanitize_banner() -> None:
    assert sanitize_banner(b"SSH-2.0-OpenSSH_9.2\r\n") == "SSH-2.0-OpenSSH_9.2"
    assert sanitize_banner(b"") is None
    assert sanitize_banner(b"\x00\x01") is None
    long_banner = ("A" * 250).encode("ascii")
    cleaned = sanitize_banner(long_banner)
    assert cleaned is not None
    assert cleaned.endswith("...")
    assert len(cleaned) <= 203


def test_parse_ssh_openssh() -> None:
    hint = parse_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2")
    assert hint.kind == "ssh"
    assert hint.product == "OpenSSH"
    assert hint.version == "9.2p1"


def test_parse_ssh_dropbear() -> None:
    hint = parse_banner("SSH-2.0-dropbear_2022.83")
    assert hint.kind == "ssh"
    assert hint.product == "Dropbear"
    assert hint.version == "2022.83"


def test_parse_ftp_vsftpd() -> None:
    hint = parse_banner("220 (vsFTPd 3.0.3)")
    assert hint.kind == "ftp"
    assert hint.product == "vsftpd"
    assert hint.version == "3.0.3"


def test_parse_smtp_postfix() -> None:
    hint = parse_banner("220 mail.example.com ESMTP Postfix")
    assert hint.kind == "smtp"
    assert hint.product == "Postfix"
    assert hint.version is None


def test_parse_smtp_exim() -> None:
    hint = parse_banner("220 host ESMTP Exim 4.96")
    assert hint.kind == "smtp"
    assert hint.product == "Exim"
    assert hint.version == "4.96"


def test_parse_pop3_and_imap() -> None:
    pop3 = parse_banner("+OK Dovecot ready")
    assert pop3.kind == "pop3"
    assert pop3.product == "Dovecot"
    imap = parse_banner("* OK IMAP4rev1 Dovecot ready")
    assert imap.kind == "imap"
    assert imap.product == "Dovecot"


def test_parse_unknown_and_empty() -> None:
    assert parse_banner(None).kind is None
    assert parse_banner("").kind is None
    assert parse_banner("random greeting from custom daemon").kind is None
    assert parse_banner("220 example.com ready").kind is None

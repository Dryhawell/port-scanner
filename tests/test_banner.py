"""Passive banner sanitize and parse tests. No network I/O."""

from __future__ import annotations

from scanner.banner import classify_banner, parse_banner, sanitize_banner, visible_banner


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


def test_parse_vnc_rfb() -> None:
    hint = parse_banner("RFB 003.008")
    assert hint.kind == "vnc"
    assert hint.product == "VNC"
    assert hint.version == "003.008"


def test_parse_http_server_header() -> None:
    hint = parse_banner("HTTP/1.1 400 Bad Request Server: nginx/1.24.0")
    assert hint.kind == "http"
    assert hint.product == "nginx"
    assert hint.version == "1.24.0"
    bare = parse_banner("HTTP/1.0 200 OK")
    assert bare.kind == "http"
    assert bare.product is None


def test_parse_redis_error() -> None:
    hint = parse_banner("-NOAUTH Authentication required.")
    assert hint.kind == "redis"


def _mysql_greeting(version: bytes) -> bytes:
    payload = bytes([10]) + version + b"\x00" + b"\x00" * 16
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


def test_classify_mysql_handshake() -> None:
    hint = classify_banner(_mysql_greeting(b"8.0.36"))
    assert hint.kind == "mysql"
    assert hint.product == "MySQL"
    assert hint.version == "8.0.36"
    assert visible_banner(_mysql_greeting(b"8.0.36"), hint) == "MySQL 8.0.36"


def test_classify_mariadb_handshake() -> None:
    hint = classify_banner(_mysql_greeting(b"5.5.5-10.11.6-MariaDB"))
    assert hint.kind == "mysql"
    assert hint.product == "MariaDB"
    assert hint.version == "10.11.6"


def test_classify_tls_amqp_telnet() -> None:
    tls = classify_banner(bytes([0x16, 0x03, 0x03, 0x00, 0x00]))
    assert tls.kind == "tls"
    assert tls.product == "TLS"
    amqp = classify_banner(b"AMQP\x00\x00\x09\x01")
    assert amqp.kind == "amqp"
    telnet = classify_banner(bytes([0xFF, 0xFD, 0x18]))
    assert telnet.kind == "telnet"
    assert classify_banner(None).kind is None
    assert classify_banner(b"SSH-2.0-OpenSSH_9.2\r\n").kind == "ssh"

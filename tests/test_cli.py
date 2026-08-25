"""CLI helper tests. No network I/O."""

from __future__ import annotations

from cli.interface import build_parser, render_progress_bar


def test_progress_bar_empty_and_full() -> None:
    assert render_progress_bar(0, 10, width=10) == "[..........]   0%"
    assert render_progress_bar(10, 10, width=10) == "[##########] 100%"


def test_progress_bar_midpoint() -> None:
    assert render_progress_bar(5, 10, width=10) == "[#####.....]  50%"


def test_progress_bar_zero_total() -> None:
    assert render_progress_bar(0, 0, width=4) == "[####] 100%"


def test_parser_accepts_profile_or_ports() -> None:
    parser = build_parser()
    profile_args = parser.parse_args(["--target", "127.0.0.1", "--profile", "quick"])
    assert profile_args.profile == "quick"
    assert profile_args.ports is None
    port_args = parser.parse_args(["--target", "127.0.0.1", "--ports", "22,80,443"])
    assert port_args.ports == "22,80,443"
    assert port_args.profile is None

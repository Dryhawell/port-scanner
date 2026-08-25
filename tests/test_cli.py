"""CLI helper tests. No network I/O."""

from __future__ import annotations

from cli.interface import render_progress_bar


def test_progress_bar_empty_and_full() -> None:
    assert render_progress_bar(0, 10, width=10) == "[..........]   0%"
    assert render_progress_bar(10, 10, width=10) == "[##########] 100%"


def test_progress_bar_midpoint() -> None:
    assert render_progress_bar(5, 10, width=10) == "[#####.....]  50%"


def test_progress_bar_zero_total() -> None:
    assert render_progress_bar(0, 0, width=4) == "[####] 100%"

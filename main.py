"""Entry point: CLI by default, or the Tkinter GUI with --gui."""

from __future__ import annotations

import sys

from cli.interface import run


def main(argv: list[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())

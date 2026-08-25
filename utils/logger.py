"""Application logging for the port scanner.

The log file records scan lifecycle events. Per-port detail stays at DEBUG so
a 65k-port scan does not flood INFO. Passwords and other secrets are never
requested by this tool and must not be added to log messages later.
"""

from __future__ import annotations

import logging
from pathlib import Path

LOGGER_NAME = "port_scanner"
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "scanner.log"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_logger = logging.getLogger(LOGGER_NAME)
if not _logger.handlers:
    _logger.addHandler(logging.NullHandler())


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def setup_logging(*, verbose: bool = False, log_file: Path | None = None) -> logging.Logger:
    """Configure a file handler plus a console handler.

    The file always stores DEBUG and above. The console is INFO by default,
    or DEBUG when verbose is True.
    """
    logger = get_logger()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    destination = Path(log_file) if log_file is not None else LOG_FILE
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(destination, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger

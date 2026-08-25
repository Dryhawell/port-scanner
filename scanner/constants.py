"""Shared numeric limits and application identity for the scanner.

Port ranges below are conventional IANA groupings, not proof of a service:
- 1-1023: well-known ports (HTTP 80, SSH 22, ...). Binding often needs admin rights.
- 1024-49151: registered ports (MySQL 3306, ...).
- 49152-65535: dynamic / private / ephemeral ports used by clients.
"""

APP_NAME = "port-scanner"
APP_VERSION = "1.0.0"

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_TIMEOUT = 0.5
DEFAULT_MAX_WORKERS = 50
MAX_WORKERS = 200
PROTOCOL_TCP = "tcp"
DEFAULT_BANNER_TIMEOUT = 0.3
MAX_BANNER_BYTES = 1024
MAX_BANNER_CHARS = 200

WELL_KNOWN_PORT_MAX = 1023
REGISTERED_PORT_MAX = 49151

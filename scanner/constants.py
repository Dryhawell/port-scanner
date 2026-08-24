"""Shared numeric limits for the scanner.

Port ranges below are conventional IANA groupings, not proof of a service:
- 1-1023: well-known ports (HTTP 80, SSH 22, ...). Binding often needs admin rights.
- 1024-49151: registered ports (MySQL 3306, ...).
- 49152-65535: dynamic / private / ephemeral ports used by clients.
"""

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_TIMEOUT = 0.5
DEFAULT_MAX_WORKERS = 50
MAX_WORKERS = 200
PROTOCOL_TCP = "tcp"

WELL_KNOWN_PORT_MAX = 1023
REGISTERED_PORT_MAX = 49151

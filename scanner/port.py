"""Port state labels used by the scanner.

TIMEOUT means the probe did not finish in time. For TCP that can be a dropped
packet, a filtering firewall, or a slow host. For UDP it is the usual
open|filtered case: no reply and no ICMP port-unreachable.
"""

from enum import Enum


class PortState(str, Enum):
    """Observed probe outcome.

    TIMEOUT means the probe did not finish in time. That can be a dropped
    packet, a filtering firewall, or a slow host — it is not a certain
    "filtered" verdict. On UDP, TIMEOUT is also what you get when a port
    is open but silent, or when ICMP is rate-limited.
    """

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"

"""Port state labels used by the TCP connect scanner."""

from enum import Enum


class PortState(str, Enum):
    """Observed TCP connect outcome.

    TIMEOUT means the probe did not finish in time. That can be a dropped
    packet, a filtering firewall, or a slow host — it is not a certain
    "filtered" verdict.
    """

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"

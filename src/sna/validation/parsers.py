"""Network device output parsers for routing protocol state.

Parses show command output into structured data for validators.
All parsers truncate input to 64KB before processing (security: prevents regex DoS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Maximum input size for parsing (security: prevents regex DoS)
_MAX_INPUT_BYTES = 65_536


@dataclass(frozen=True)
class BGPNeighborEntry:
    """Parsed BGP neighbor from show bgp summary output."""

    neighbor: str
    remote_as: str
    state: str  # "Established" or state like "Idle", "Active", "Connect"
    prefixes_received: int


@dataclass(frozen=True)
class OSPFNeighborEntry:
    """Parsed OSPF neighbor from show ip ospf neighbor output."""

    neighbor_id: str
    state: str  # "FULL", "2WAY", "INIT", etc.
    interface: str
    address: str = ""


@dataclass(frozen=True)
class RouteEntry:
    """Parsed route from show ip route output."""

    prefix: str
    next_hop: str
    protocol: str  # "C", "S", "O", "B", "D", etc.
    interface: str = ""


def parse_bgp_summary(output: str) -> list[BGPNeighborEntry]:
    """Parse 'show bgp summary' or 'show ip bgp summary' output.

    Handles IOS-XE and NX-OS formats. Extracts neighbor IP, remote AS,
    state/prefix count from the neighbor table.

    Args:
        output: Raw show command output (truncated to 64KB).

    Returns:
        List of BGPNeighborEntry objects.
    """
    text = output[:_MAX_INPUT_BYTES]
    entries: list[BGPNeighborEntry] = []

    # IOS-XE/IOS format: neighbor lines after the header
    # Example: 10.0.0.2   4   65001   0   0   0   0   0 00:05:30  5
    # Last field is PfxRcd (int) if Established, or state string if not
    neighbor_pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+"  # neighbor IP
        r"\d+\s+"  # version
        r"(\d+)\s+"  # remote AS
        r"(?:\d+\s+){5}"  # MsgRcvd, MsgSent, TblVer, InQ, OutQ
        r"\S+\s+"  # Up/Down time
        r"(\S+)\s*$",  # State/PfxRcd
        re.MULTILINE,
    )

    for match in neighbor_pattern.finditer(text):
        neighbor = match.group(1)
        remote_as = match.group(2)
        state_or_pfx = match.group(3)

        try:
            pfx_count = int(state_or_pfx)
            state = "Established"
            prefixes = pfx_count
        except ValueError:
            state = state_or_pfx
            prefixes = 0

        entries.append(BGPNeighborEntry(
            neighbor=neighbor,
            remote_as=remote_as,
            state=state,
            prefixes_received=prefixes,
        ))

    return entries


def parse_ospf_neighbors(output: str) -> list[OSPFNeighborEntry]:
    """Parse 'show ip ospf neighbor' output.

    Handles IOS-XE format.

    Args:
        output: Raw show command output (truncated to 64KB).

    Returns:
        List of OSPFNeighborEntry objects.
    """
    text = output[:_MAX_INPUT_BYTES]
    entries: list[OSPFNeighborEntry] = []

    # IOS-XE format:
    # Neighbor ID   Pri  State      Dead Time  Address       Interface
    # 10.0.0.2      1    FULL/DR    00:00:32   10.0.0.2      GigabitEthernet0/1
    neighbor_pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+"  # Neighbor ID
        r"\d+\s+"  # Priority
        r"(\S+)\s+"  # State (e.g., FULL/DR, 2WAY/DROTHER)
        r"\S+\s+"  # Dead Time
        r"(\d+\.\d+\.\d+\.\d+)\s+"  # Address
        r"(\S+)",  # Interface
        re.MULTILINE,
    )

    for match in neighbor_pattern.finditer(text):
        state_full = match.group(2)
        # Extract base state (before /)
        state = state_full.split("/")[0]

        entries.append(OSPFNeighborEntry(
            neighbor_id=match.group(1),
            state=state,
            address=match.group(3),
            interface=match.group(4),
        ))

    return entries


def parse_routing_table(output: str) -> list[RouteEntry]:
    """Parse 'show ip route' output.

    Handles IOS-XE format. Extracts prefix, next-hop, protocol code.

    Args:
        output: Raw show command output (truncated to 64KB).

    Returns:
        List of RouteEntry objects.
    """
    text = output[:_MAX_INPUT_BYTES]
    entries: list[RouteEntry] = []

    # IOS-XE format:
    # C    10.0.0.0/24 is directly connected, GigabitEthernet0/1
    # S    192.168.1.0/24 [1/0] via 10.0.0.1
    # O    172.16.0.0/16 [110/20] via 10.0.0.2, 00:05:30, GigabitEthernet0/1
    # B    10.1.0.0/16 [20/0] via 10.0.0.3, 00:10:00
    route_pattern = re.compile(
        r"^([CSOBDRL*>i\s]+?)\s+"  # protocol code(s)
        r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"  # prefix
        r"(?:"
        r"is directly connected,\s+(\S+)"  # directly connected
        r"|"
        r"(?:\[\d+/\d+\]\s+)?via\s+(\d+\.\d+\.\d+\.\d+)"  # via next-hop
        r"(?:.*?,\s*(\S+))?"  # optional interface
        r")",
        re.MULTILINE,
    )

    for match in route_pattern.finditer(text):
        protocol_code = match.group(1).strip()
        prefix = match.group(2)
        direct_iface = match.group(3)
        next_hop = match.group(4) or ""
        via_iface = match.group(5) or ""

        # Determine protocol from code
        proto = protocol_code.strip().rstrip("*> ")
        if not proto:
            proto = "?"

        if direct_iface:
            entries.append(RouteEntry(
                prefix=prefix,
                next_hop="directly connected",
                protocol=proto,
                interface=direct_iface,
            ))
        else:
            entries.append(RouteEntry(
                prefix=prefix,
                next_hop=next_hop,
                protocol=proto,
                interface=via_iface,
            ))

    return entries

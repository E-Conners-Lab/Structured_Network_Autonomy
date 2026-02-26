"""Baseline collector — gathers current network state from all lab devices.

Connects via scrapli to every inventory device and collects:
- Interface inventory (names, IPs, status)
- Routing table
- VLAN database (switches only)
- Running config snapshot

Parses raw CLI output into structured Python objects that scenario
generators use to make context-aware decisions.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import structlog
from scrapli import AsyncScrapli

logger = structlog.get_logger()


@dataclass
class Interface:
    """Parsed interface from 'show ip interface brief'."""
    name: str
    ip: str
    status: str       # "up" or "down"
    protocol: str     # "up" or "down"
    has_description: bool = False
    description: str = ""


@dataclass
class Route:
    """Parsed route from 'show ip route'."""
    prefix: str
    mask: str
    next_hop: str
    protocol: str     # "C", "S", "O", "B", etc.
    interface: str = ""


@dataclass
class Vlan:
    """Parsed VLAN from 'show vlan brief'."""
    vlan_id: int
    name: str
    status: str
    ports: list[str] = field(default_factory=list)


@dataclass
class DeviceState:
    """Complete parsed state for one device."""
    name: str
    host: str
    hostname: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    vlans: list[Vlan] = field(default_factory=list)
    running_config: str = ""
    is_switch: bool = False
    has_ospf: bool = False
    has_bgp: bool = False
    ospf_neighbors: list[str] = field(default_factory=list)


@dataclass
class NetworkBaseline:
    """Full network baseline — state of every device at a point in time."""
    devices: dict[str, DeviceState] = field(default_factory=dict)
    routers: list[str] = field(default_factory=list)
    switches: list[str] = field(default_factory=list)
    used_vlans: set[int] = field(default_factory=set)
    used_prefixes: set[str] = field(default_factory=set)

    @property
    def all_names(self) -> list[str]:
        return list(self.devices.keys())


# --- Parsers ---

def parse_ip_interface_brief(output: str) -> list[Interface]:
    """Parse 'show ip interface brief' into Interface objects."""
    interfaces = []
    for line in output.splitlines():
        # Match lines like: GigabitEthernet1  10.255.255.11  YES ... up  up
        m = re.match(
            r"^(\S+)\s+([\d.]+|unassigned)\s+\S+\s+\S+\s+(\S+)\s+(\S+)",
            line.strip(),
        )
        if m:
            interfaces.append(Interface(
                name=m.group(1),
                ip=m.group(2),
                status=m.group(3).lower(),
                protocol=m.group(4).lower(),
            ))
    return interfaces


def parse_ip_route(output: str) -> list[Route]:
    """Parse 'show ip route' into Route objects."""
    routes = []
    for line in output.splitlines():
        # Connected: C 10.0.0.0/24 is directly connected, GigabitEthernet1
        m = re.match(
            r"^([CSOBDRL\*])\S*\s+([\d.]+)(/(\d+))?\s.*?(?:via\s+([\d.]+))?.*?(?:,\s+(\S+))?$",
            line.strip(),
        )
        if m:
            prefix = m.group(2)
            mask = m.group(4) or "32"
            routes.append(Route(
                prefix=prefix,
                mask=mask,
                next_hop=m.group(5) or "direct",
                protocol=m.group(1),
                interface=m.group(6) or "",
            ))
    return routes


def parse_vlan_brief(output: str) -> list[Vlan]:
    """Parse 'show vlan brief' into Vlan objects."""
    vlans = []
    for line in output.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended)\s*(.*)", line.strip())
        if m:
            vlan_id = int(m.group(1))
            if vlan_id >= 1002:  # Skip reserved VLANs
                continue
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()] if m.group(4) else []
            vlans.append(Vlan(
                vlan_id=vlan_id,
                name=m.group(2),
                status=m.group(3),
                ports=ports,
            ))
    return vlans


def parse_interface_descriptions(output: str, interfaces: list[Interface]) -> None:
    """Enrich interfaces with description info from 'show interfaces description'."""
    desc_map: dict[str, str] = {}
    for line in output.splitlines():
        m = re.match(r"^(\S+)\s+(?:up|down|admin)\s+(?:up|down)\s+(.*)", line.strip())
        if m:
            desc_map[m.group(1)] = m.group(2).strip()

    for iface in interfaces:
        short = iface.name
        if short in desc_map and desc_map[short]:
            iface.has_description = True
            iface.description = desc_map[short]


# --- Collector ---

async def collect_device_state(
    name: str,
    host: str,
    username: str,
    password: str,
    is_switch: bool = False,
) -> DeviceState:
    """Connect to a single device and collect its full state."""
    state = DeviceState(name=name, host=host, is_switch=is_switch)

    driver_kwargs = {
        "host": host,
        "port": 22,
        "auth_username": username,
        "auth_password": password,
        "auth_strict_key": False,
        "timeout_socket": 10,
        "timeout_transport": 10,
        "timeout_ops": 30,
        "transport": "asyncssh",
        "platform": "cisco_iosxe",
    }

    try:
        async with AsyncScrapli(**driver_kwargs) as conn:
            # Gather all commands concurrently
            commands = [
                "show ip interface brief",
                "show ip route",
                "show interfaces description",
                "show running-config",
            ]
            if is_switch:
                commands.append("show vlan brief")

            responses = await conn.send_commands(commands, timeout_ops=30)

            # Parse results
            state.interfaces = parse_ip_interface_brief(responses[0].result)
            state.routes = parse_ip_route(responses[1].result)
            parse_interface_descriptions(responses[2].result, state.interfaces)
            state.running_config = responses[3].result

            if is_switch and len(responses) > 4:
                state.vlans = parse_vlan_brief(responses[4].result)

            # Detect routing protocols from config
            config_lower = state.running_config.lower()
            state.has_ospf = "router ospf" in config_lower
            state.has_bgp = "router bgp" in config_lower

            # Extract hostname
            m = re.search(r"^hostname\s+(\S+)", state.running_config, re.MULTILINE)
            if m:
                state.hostname = m.group(1)

            await logger.ainfo(
                "device_state_collected",
                device=name,
                interfaces=len(state.interfaces),
                routes=len(state.routes),
                vlans=len(state.vlans),
            )

    except Exception as exc:
        await logger.aerror("device_state_collection_failed", device=name, error=str(exc))

    return state


async def collect_baseline(
    inventory: dict[str, dict],
    username: str,
    password: str,
) -> NetworkBaseline:
    """Collect baseline state from all inventory devices concurrently.

    Args:
        inventory: Device name -> {host, platform} mapping.
        username: SSH username for all devices.
        password: SSH password for all devices.

    Returns:
        A NetworkBaseline with structured state from every reachable device.
    """
    baseline = NetworkBaseline()

    tasks = []
    for name, info in inventory.items():
        is_switch = name.lower().startswith("switch")
        tasks.append(collect_device_state(
            name=name,
            host=info["host"],
            username=username,
            password=password,
            is_switch=is_switch,
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            await logger.aerror("baseline_device_error", error=str(result))
            continue

        baseline.devices[result.name] = result
        if result.is_switch:
            baseline.switches.append(result.name)
        else:
            baseline.routers.append(result.name)

        # Track used VLANs and prefixes
        for vlan in result.vlans:
            baseline.used_vlans.add(vlan.vlan_id)
        for route in result.routes:
            baseline.used_prefixes.add(f"{route.prefix}/{route.mask}")

    await logger.ainfo(
        "baseline_collected",
        devices=len(baseline.devices),
        routers=len(baseline.routers),
        switches=len(baseline.switches),
        used_vlans=len(baseline.used_vlans),
    )

    return baseline

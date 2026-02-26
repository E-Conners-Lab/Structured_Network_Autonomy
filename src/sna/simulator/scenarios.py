"""Scenario generators — create realistic agent actions from network baseline.

Each generator returns a list of EvaluatePayload dicts ready to POST to /evaluate.
All decisions are context-aware: they reference actual interfaces, routes, VLANs,
and configs from the live baseline, so the simulator never proposes nonsensical changes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from sna.simulator.baseline import NetworkBaseline


@dataclass
class EvaluatePayload:
    """A single action for the agent to evaluate."""
    tool_name: str
    confidence_score: float
    device_targets: list[str]
    parameters: dict[str, str] = field(default_factory=dict)
    scenario_name: str = ""
    scenario_description: str = ""


def generate_interface_monitoring(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Agent monitors interfaces across all devices.

    - Runs show_interfaces on random devices (routine health check)
    - If a device has a down interface, confidence is lower (something is wrong)
    """
    payloads = []

    # Routine health checks on 2-3 random devices
    devices = random.sample(baseline.all_names, min(3, len(baseline.all_names)))
    for name in devices:
        payloads.append(EvaluatePayload(
            tool_name="show_interfaces",
            confidence_score=round(random.uniform(0.85, 0.99), 2),
            device_targets=[name],
            scenario_name="interface_health_check",
            scenario_description=f"Routine interface health check on {name}",
        ))

    # Check for devices with down interfaces — investigate with lower confidence
    for name, state in baseline.devices.items():
        down_ifaces = [i for i in state.interfaces if i.status == "down" and i.ip != "unassigned"]
        if down_ifaces:
            iface = random.choice(down_ifaces)
            payloads.append(EvaluatePayload(
                tool_name="show_interfaces",
                confidence_score=round(random.uniform(0.5, 0.75), 2),
                device_targets=[name],
                scenario_name="interface_down_investigation",
                scenario_description=f"Investigating down interface {iface.name} on {name}",
            ))

    return payloads


def generate_config_compliance(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Nightly compliance scan — pull configs and compare.

    - Runs show_running_config on all devices
    - Checks for missing logging/NTP in configs → proposes configure_logging
    """
    payloads = []

    # Pull configs from a subset
    devices = random.sample(baseline.all_names, min(4, len(baseline.all_names)))
    for name in devices:
        payloads.append(EvaluatePayload(
            tool_name="show_running_config",
            confidence_score=round(random.uniform(0.88, 0.98), 2),
            device_targets=[name],
            scenario_name="config_compliance_scan",
            scenario_description=f"Compliance config pull from {name}",
        ))

    # Check which devices are missing logging config
    for name, state in baseline.devices.items():
        if "logging host" not in state.running_config.lower() and state.running_config:
            payloads.append(EvaluatePayload(
                tool_name="configure_logging",
                confidence_score=round(random.uniform(0.7, 0.9), 2),
                device_targets=[name],
                parameters={"host": "10.255.255.100"},
                scenario_name="compliance_fix_logging",
                scenario_description=f"Add syslog server to {name} — missing logging config",
            ))

    return payloads


def generate_description_cleanup(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Agent finds interfaces without descriptions and proposes adding them.

    Only targets interfaces that are up and have an IP but no description.
    """
    payloads = []

    for name, state in baseline.devices.items():
        undescribed = [
            i for i in state.interfaces
            if i.status == "up" and i.ip != "unassigned" and not i.has_description
        ]
        if undescribed:
            iface = random.choice(undescribed)
            desc = f"Mgmt-{name}" if "management" in iface.name.lower() or "loopback" in iface.name.lower() else f"Link-{name}-{iface.name.split('/')[-1]}"
            payloads.append(EvaluatePayload(
                tool_name="set_interface_description",
                confidence_score=round(random.uniform(0.8, 0.95), 2),
                device_targets=[name],
                parameters={"interface": iface.name, "description": desc},
                scenario_name="description_cleanup",
                scenario_description=f"Add description '{desc}' to {iface.name} on {name}",
            ))

    return payloads


def generate_vlan_provisioning(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: New service needs a VLAN deployed across switches.

    Picks an unused VLAN ID and proposes it on 1-3 switches.
    """
    if not baseline.switches:
        return []

    # Find an unused VLAN in the 100-200 range
    candidate_vlans = [v for v in range(100, 201) if v not in baseline.used_vlans]
    if not candidate_vlans:
        return []

    vlan_id = random.choice(candidate_vlans[:10])  # Pick from first 10 unused
    vlan_names = ["ENGINEERING", "GUEST-WIFI", "VOIP", "SECURITY-CAMERAS", "IOT-DEVICES", "MANAGEMENT"]
    vlan_name = random.choice(vlan_names)

    targets = random.sample(baseline.switches, min(random.randint(1, 3), len(baseline.switches)))

    payloads = []
    for switch in targets:
        payloads.append(EvaluatePayload(
            tool_name="configure_vlan",
            confidence_score=round(random.uniform(0.6, 0.85), 2),
            device_targets=[switch],
            parameters={"vlan_id": str(vlan_id), "name": vlan_name},
            scenario_name="vlan_provisioning",
            scenario_description=f"Deploy VLAN {vlan_id} ({vlan_name}) on {switch}",
        ))

    return payloads


def generate_static_route(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: New subnet needs reachability — agent adds a static route.

    Uses a prefix not already in any routing table and a valid next-hop
    from an existing connected route.
    """
    if not baseline.routers:
        return []

    # Pick a router with routes
    router_name = random.choice(baseline.routers)
    state = baseline.devices.get(router_name)
    if not state or not state.routes:
        return []

    # Find a valid next-hop from connected routes
    connected = [r for r in state.routes if r.protocol == "C" and r.next_hop == "direct"]
    if not connected:
        return []

    # Generate a "new" /24 prefix
    new_subnets = [
        f"172.16.{random.randint(1, 254)}.0/24",
        f"192.168.{random.randint(100, 254)}.0/24",
        f"10.{random.randint(100, 200)}.{random.randint(1, 254)}.0/24",
    ]

    # Pick one not already in routing table
    prefix = random.choice(new_subnets)
    for p in new_subnets:
        if p not in baseline.used_prefixes:
            prefix = p
            break

    # Use a plausible next-hop from interfaces with IPs
    ifaces_with_ip = [i for i in state.interfaces if i.ip != "unassigned" and i.status == "up"]
    if not ifaces_with_ip:
        return []

    # Use the gateway on the same subnet as one of the interfaces
    ip_parts = ifaces_with_ip[0].ip.rsplit(".", 1)
    next_hop = f"{ip_parts[0]}.1" if ip_parts[0] != ifaces_with_ip[0].ip else "10.255.255.1"

    return [EvaluatePayload(
        tool_name="configure_static_route",
        confidence_score=round(random.uniform(0.6, 0.85), 2),
        device_targets=[router_name],
        parameters={"prefix": prefix, "next_hop": next_hop},
        scenario_name="static_route_addition",
        scenario_description=f"Add static route {prefix} via {next_hop} on {router_name}",
    )]


def generate_acl_creation(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Security team requests an ACL on edge routers.

    Proposes named ACLs for common security use cases.
    """
    acl_names = ["MGMT-ACCESS", "BLOCK-TELNET", "PERMIT-MONITORING", "DENY-RFC1918"]
    acl_name = random.choice(acl_names)

    # Target 1-2 routers
    targets = random.sample(baseline.routers, min(2, len(baseline.routers)))

    return [EvaluatePayload(
        tool_name="configure_acl",
        confidence_score=round(random.uniform(0.45, 0.7), 2),
        device_targets=targets,
        parameters={"name": acl_name},
        scenario_name="acl_security_request",
        scenario_description=f"Create ACL '{acl_name}' on {', '.join(targets)} per security team request",
    )]


def generate_bgp_peering(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: New BGP peering requested between two routers.

    Only proposes if neither router already has BGP configured.
    Uses realistic ASN ranges.
    """
    # Find routers without BGP
    no_bgp = [name for name in baseline.routers if not baseline.devices[name].has_bgp]
    if len(no_bgp) < 1:
        return []

    router = random.choice(no_bgp)
    state = baseline.devices[router]

    # Pick a neighbor IP from another router's interfaces
    other_routers = [n for n in baseline.routers if n != router]
    if not other_routers:
        return []

    neighbor_name = random.choice(other_routers)
    neighbor_state = baseline.devices[neighbor_name]
    neighbor_ips = [i.ip for i in neighbor_state.interfaces if i.ip != "unassigned" and i.status == "up"]
    if not neighbor_ips:
        return []

    neighbor_ip = random.choice(neighbor_ips)
    local_asn = str(random.choice([65001, 65010, 65100]))
    remote_asn = str(random.choice([65002, 65020, 65200]))

    return [EvaluatePayload(
        tool_name="configure_bgp_neighbor",
        confidence_score=round(random.uniform(0.3, 0.6), 2),
        device_targets=[router],
        parameters={
            "local_asn": local_asn,
            "neighbor_ip": neighbor_ip,
            "remote_asn": remote_asn,
        },
        scenario_name="bgp_peering_request",
        scenario_description=f"Establish BGP peering on {router} — AS{local_asn} to {neighbor_name} ({neighbor_ip}) AS{remote_asn}",
    )]


def generate_scope_violation(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Agent tries a bulk operation across too many devices.

    This tests the scope escalation — targeting >3 devices.
    Represents a mass change attempt that should be escalated.
    """
    if len(baseline.all_names) < 4:
        return []

    targets = random.sample(baseline.all_names, min(random.randint(4, 6), len(baseline.all_names)))

    return [EvaluatePayload(
        tool_name="show_running_config",
        confidence_score=round(random.uniform(0.85, 0.99), 2),
        device_targets=targets,
        scenario_name="bulk_config_pull",
        scenario_description=f"Bulk config collection from {len(targets)} devices — exceeds scope limit",
    )]


def generate_blocked_action(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Agent encounters a situation where it considers a dangerous action.

    These should always be BLOCK — tests the hard-block guardrail.
    """
    device = random.choice(baseline.all_names)

    blocked_tools = [
        ("write_erase", "Erase startup config — triggered by suspected config corruption"),
        ("factory_reset", "Factory reset — triggered by unrecoverable state"),
        ("delete_startup_config", "Delete startup — triggered by decommission workflow"),
    ]

    tool, description = random.choice(blocked_tools)

    return [EvaluatePayload(
        tool_name=tool,
        confidence_score=round(random.uniform(0.9, 1.0), 2),
        device_targets=[device],
        scenario_name="dangerous_action_attempt",
        scenario_description=f"{description} on {device}",
    )]


def generate_connectivity_test(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Scenario: Agent verifies reachability between devices.

    Uses ping/traceroute to known IPs from the baseline.
    """
    payloads = []

    if len(baseline.all_names) < 2:
        return payloads

    source = random.choice(baseline.all_names)
    others = [n for n in baseline.all_names if n != source]
    target_name = random.choice(others)
    target_state = baseline.devices[target_name]

    target_ips = [i.ip for i in target_state.interfaces if i.ip != "unassigned"]
    if not target_ips:
        return payloads

    target_ip = random.choice(target_ips)

    payloads.append(EvaluatePayload(
        tool_name="ping",
        confidence_score=round(random.uniform(0.8, 0.95), 2),
        device_targets=[source],
        parameters={"target": target_ip},
        scenario_name="connectivity_verification",
        scenario_description=f"Ping {target_name} ({target_ip}) from {source}",
    ))

    # 50% chance to also traceroute
    if random.random() > 0.5:
        payloads.append(EvaluatePayload(
            tool_name="traceroute",
            confidence_score=round(random.uniform(0.8, 0.95), 2),
            device_targets=[source],
            parameters={"target": target_ip},
            scenario_name="path_verification",
            scenario_description=f"Traceroute to {target_name} ({target_ip}) from {source}",
        ))

    return payloads


# All scenario generators in order of likelihood
ALL_SCENARIOS = [
    (0.25, generate_interface_monitoring),
    (0.15, generate_config_compliance),
    (0.12, generate_description_cleanup),
    (0.10, generate_connectivity_test),
    (0.10, generate_vlan_provisioning),
    (0.08, generate_static_route),
    (0.07, generate_acl_creation),
    (0.05, generate_bgp_peering),
    (0.04, generate_scope_violation),
    (0.04, generate_blocked_action),
]


def pick_scenario(baseline: NetworkBaseline) -> list[EvaluatePayload]:
    """Weighted random scenario selection based on real-world frequency."""
    weights = [w for w, _ in ALL_SCENARIOS]
    generators = [g for _, g in ALL_SCENARIOS]
    chosen = random.choices(generators, weights=weights, k=1)[0]
    return chosen(baseline)

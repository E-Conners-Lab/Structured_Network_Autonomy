"""MCP write tool definitions — Tier 2–4 tools.

Write tools modify device configuration. Pre-change config snapshots
are captured for rollback support.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SetInterfaceDescriptionInput(BaseModel):
    """Input schema for set_interface_description tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    interface: str = Field(description="Interface name (e.g., GigabitEthernet0/1)", max_length=255)
    description: str = Field(description="Interface description text", max_length=255)


class ConfigureStaticRouteInput(BaseModel):
    """Input schema for configure_static_route tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    prefix: str = Field(description="Destination prefix (e.g., 10.0.0.0/24)", max_length=20)
    next_hop: str = Field(description="Next-hop IP address", max_length=15)


class ConfigureVlanInput(BaseModel):
    """Input schema for configure_vlan tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    vlan_id: str = Field(description="VLAN ID (1-4094)", max_length=4)
    name: str = Field(description="VLAN name", max_length=255)


class ConfigureAclInput(BaseModel):
    """Input schema for configure_acl tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    name: str = Field(description="ACL name", max_length=255)


class ConfigureBgpNeighborInput(BaseModel):
    """Input schema for configure_bgp_neighbor tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    local_asn: str = Field(description="Local BGP ASN", max_length=10)
    neighbor_ip: str = Field(description="Neighbor IP address", max_length=15)
    remote_asn: str = Field(description="Remote BGP ASN", max_length=10)


class ConfigureLoggingInput(BaseModel):
    """Input schema for configure_logging tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    host: str = Field(description="Logging server IP address", max_length=15)


# Tool metadata for registration
WRITE_TOOLS = {
    "set_interface_description": {
        "description": "Set the description on a network interface",
        "input_schema": SetInterfaceDescriptionInput,
    },
    "configure_static_route": {
        "description": "Configure a static route on a device",
        "input_schema": ConfigureStaticRouteInput,
    },
    "configure_vlan": {
        "description": "Configure a VLAN on a device",
        "input_schema": ConfigureVlanInput,
    },
    "configure_acl": {
        "description": "Configure a named ACL on a device",
        "input_schema": ConfigureAclInput,
    },
    "configure_bgp_neighbor": {
        "description": "Configure a BGP neighbor on a device",
        "input_schema": ConfigureBgpNeighborInput,
    },
    "configure_logging": {
        "description": "Configure a logging host on a device",
        "input_schema": ConfigureLoggingInput,
    },
}

"""MCP read tool definitions — Tier 1 tools.

Each tool has a Pydantic input schema and maps to a CommandTemplate.
These tools only read device state — no configuration changes.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ShowRunningConfigInput(BaseModel):
    """Input schema for show_running_config tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)


class ShowInterfacesInput(BaseModel):
    """Input schema for show_interfaces tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)


class ShowBGPSummaryInput(BaseModel):
    """Input schema for show_bgp_summary tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)


class PingInput(BaseModel):
    """Input schema for ping tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    target: str = Field(description="IP address to ping", min_length=7, max_length=15)


class TracerouteInput(BaseModel):
    """Input schema for traceroute tool."""

    device: str = Field(description="Target device hostname", min_length=1, max_length=255)
    target: str = Field(description="IP address to traceroute", min_length=7, max_length=15)


# Tool metadata for registration
READ_TOOLS = {
    "show_running_config": {
        "description": "Show the running configuration of a network device",
        "input_schema": ShowRunningConfigInput,
    },
    "show_interfaces": {
        "description": "Show interface status and statistics",
        "input_schema": ShowInterfacesInput,
    },
    "show_bgp_summary": {
        "description": "Show BGP neighbor summary",
        "input_schema": ShowBGPSummaryInput,
    },
    "ping": {
        "description": "Ping an IP address from a network device",
        "input_schema": PingInput,
    },
    "traceroute": {
        "description": "Traceroute to an IP address from a network device",
        "input_schema": TracerouteInput,
    },
}

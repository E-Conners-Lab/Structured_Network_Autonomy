"""Command building with strict parameter sanitization.

SECURITY-CRITICAL: Never interpolates raw user strings into CLI commands.
Each tool has a registered CommandTemplate that maps typed params to safe CLI strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger()

# Characters that MUST NOT appear in any parameter value
FORBIDDEN_CHARS = re.compile(r"[\n\r|;!]")

# Validation patterns for common parameter types
INTERFACE_PATTERN = re.compile(
    r"^(GigabitEthernet|FastEthernet|Ethernet|Loopback|Vlan|Port-channel|"
    r"TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|"
    r"Management|Tunnel|BDI|mgmt)"
    r"[0-9]+(/[0-9]+)*(\.[0-9]+)?$",
    re.IGNORECASE,
)
VLAN_ID_RANGE = range(1, 4095)
IP_V4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
)
PREFIX_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"/(3[0-2]|[12]?\d)$"
)
ASN_RANGE = range(1, 4294967296)
HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,255}$")
DESCRIPTION_PATTERN = re.compile(r"^[a-zA-Z0-9 _.,-]{0,255}$")


class ParamType(str, Enum):
    """Parameter type for validation."""

    INTERFACE = "interface"
    VLAN_ID = "vlan_id"
    IP_ADDRESS = "ip_address"
    PREFIX = "prefix"
    ASN = "asn"
    HOSTNAME = "hostname"
    DESCRIPTION = "description"
    STRING = "string"
    INTEGER = "integer"


@dataclass(frozen=True)
class ParamSpec:
    """Specification for a command parameter."""

    name: str
    param_type: ParamType
    required: bool = True
    description: str = ""


@dataclass(frozen=True)
class CommandTemplate:
    """A template for building a safe CLI command from validated parameters.

    The template string uses {param_name} placeholders that are filled
    ONLY after all parameters pass type-specific validation.
    """

    tool_name: str
    template: str
    params: list[ParamSpec] = field(default_factory=list)
    timeout_ops: int = 30


class CommandValidationError(Exception):
    """Raised when command parameter validation fails."""


def validate_param(value: str, param_type: ParamType, param_name: str) -> str:
    """Validate a single parameter value against its type specification.

    Args:
        value: The raw parameter value.
        param_type: Expected type for validation.
        param_name: Name of the parameter (for error messages).

    Returns:
        The validated parameter value.

    Raises:
        CommandValidationError: If validation fails.
    """
    if FORBIDDEN_CHARS.search(str(value)):
        raise CommandValidationError(
            f"Parameter '{param_name}' contains forbidden characters"
        )

    if param_type == ParamType.INTERFACE:
        if not INTERFACE_PATTERN.match(value):
            raise CommandValidationError(
                f"Parameter '{param_name}' is not a valid interface name: {value}"
            )
    elif param_type == ParamType.VLAN_ID:
        try:
            vlan = int(value)
        except (ValueError, TypeError):
            raise CommandValidationError(
                f"Parameter '{param_name}' must be a valid VLAN ID (1-4094): {value}"
            )
        if vlan not in VLAN_ID_RANGE:
            raise CommandValidationError(
                f"Parameter '{param_name}' VLAN ID out of range (1-4094): {vlan}"
            )
        return str(vlan)
    elif param_type == ParamType.IP_ADDRESS:
        if not IP_V4_PATTERN.match(value):
            raise CommandValidationError(
                f"Parameter '{param_name}' is not a valid IPv4 address: {value}"
            )
    elif param_type == ParamType.PREFIX:
        if not PREFIX_PATTERN.match(value):
            raise CommandValidationError(
                f"Parameter '{param_name}' is not a valid prefix (x.x.x.x/y): {value}"
            )
    elif param_type == ParamType.ASN:
        try:
            asn = int(value)
        except (ValueError, TypeError):
            raise CommandValidationError(
                f"Parameter '{param_name}' must be a valid ASN: {value}"
            )
        if asn not in ASN_RANGE:
            raise CommandValidationError(
                f"Parameter '{param_name}' ASN out of range: {asn}"
            )
        return str(asn)
    elif param_type == ParamType.HOSTNAME:
        if not HOSTNAME_PATTERN.match(value):
            raise CommandValidationError(
                f"Parameter '{param_name}' is not a valid hostname: {value}"
            )
    elif param_type == ParamType.DESCRIPTION:
        if not DESCRIPTION_PATTERN.match(value):
            raise CommandValidationError(
                f"Parameter '{param_name}' contains invalid characters for a description"
            )
    elif param_type == ParamType.INTEGER:
        try:
            int(value)
        except (ValueError, TypeError):
            raise CommandValidationError(
                f"Parameter '{param_name}' must be an integer: {value}"
            )
        return str(int(value))
    elif param_type == ParamType.STRING:
        if len(value) > 255:
            raise CommandValidationError(
                f"Parameter '{param_name}' exceeds maximum length of 255"
            )

    return value


class CommandBuilder:
    """Builds validated device commands from registered templates.

    SECURITY: Never interpolates raw user strings. All parameters are
    validated against their type specifications before command construction.
    """

    def __init__(self) -> None:
        self._templates: dict[str, CommandTemplate] = {}

    def register(self, template: CommandTemplate) -> None:
        """Register a command template for a tool."""
        self._templates[template.tool_name] = template

    def get_template(self, tool_name: str) -> CommandTemplate | None:
        """Get the registered template for a tool."""
        return self._templates.get(tool_name)

    def build(self, tool_name: str, params: dict[str, str]) -> str:
        """Build a validated CLI command from a tool name and parameters.

        Args:
            tool_name: The MCP tool name.
            params: Parameter name-value pairs.

        Returns:
            The validated CLI command string.

        Raises:
            CommandValidationError: If the tool is unknown or params are invalid.
        """
        template = self._templates.get(tool_name)
        if template is None:
            raise CommandValidationError(f"Unknown tool: {tool_name}")

        # Validate all required params are present
        for spec in template.params:
            if spec.required and spec.name not in params:
                raise CommandValidationError(
                    f"Missing required parameter: {spec.name}"
                )

        # Validate all provided params
        validated: dict[str, str] = {}
        param_specs = {spec.name: spec for spec in template.params}

        for name, value in params.items():
            spec = param_specs.get(name)
            if spec is None:
                raise CommandValidationError(f"Unknown parameter: {name}")
            validated[name] = validate_param(str(value), spec.param_type, name)

        return template.template.format(**validated)

    def get_timeout(self, tool_name: str) -> int:
        """Get the configured timeout_ops for a tool."""
        template = self._templates.get(tool_name)
        return template.timeout_ops if template else 30


def create_default_command_builder() -> CommandBuilder:
    """Create a CommandBuilder with all standard SNA tool templates registered."""
    builder = CommandBuilder()

    # Tier 1: Read tools
    builder.register(CommandTemplate(
        tool_name="show_running_config",
        template="show running-config",
        timeout_ops=60,
    ))
    builder.register(CommandTemplate(
        tool_name="show_interfaces",
        template="show interfaces",
        timeout_ops=30,
    ))
    builder.register(CommandTemplate(
        tool_name="show_bgp_summary",
        template="show bgp summary",
        timeout_ops=30,
    ))
    builder.register(CommandTemplate(
        tool_name="ping",
        template="ping {target}",
        params=[ParamSpec("target", ParamType.IP_ADDRESS)],
        timeout_ops=30,
    ))
    builder.register(CommandTemplate(
        tool_name="traceroute",
        template="traceroute {target}",
        params=[ParamSpec("target", ParamType.IP_ADDRESS)],
        timeout_ops=60,
    ))

    # Tier 2: Low-risk write tools
    builder.register(CommandTemplate(
        tool_name="set_interface_description",
        template="interface {interface}\n description {description}",
        params=[
            ParamSpec("interface", ParamType.INTERFACE),
            ParamSpec("description", ParamType.DESCRIPTION),
        ],
    ))
    builder.register(CommandTemplate(
        tool_name="configure_logging",
        template="logging host {host}",
        params=[ParamSpec("host", ParamType.IP_ADDRESS)],
    ))

    # Tier 3: Medium-risk write tools
    builder.register(CommandTemplate(
        tool_name="configure_static_route",
        template="ip route {prefix} {next_hop}",
        params=[
            ParamSpec("prefix", ParamType.PREFIX),
            ParamSpec("next_hop", ParamType.IP_ADDRESS),
        ],
    ))
    builder.register(CommandTemplate(
        tool_name="configure_vlan",
        template="vlan {vlan_id}\n name {name}",
        params=[
            ParamSpec("vlan_id", ParamType.VLAN_ID),
            ParamSpec("name", ParamType.DESCRIPTION),
        ],
    ))
    builder.register(CommandTemplate(
        tool_name="configure_acl",
        template="ip access-list extended {name}",
        params=[ParamSpec("name", ParamType.HOSTNAME)],
    ))

    # Tier 4: High-risk write tools
    builder.register(CommandTemplate(
        tool_name="configure_bgp_neighbor",
        template="router bgp {local_asn}\n neighbor {neighbor_ip} remote-as {remote_asn}",
        params=[
            ParamSpec("local_asn", ParamType.ASN),
            ParamSpec("neighbor_ip", ParamType.IP_ADDRESS),
            ParamSpec("remote_asn", ParamType.ASN),
        ],
    ))

    return builder

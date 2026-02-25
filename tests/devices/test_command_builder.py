"""Tests for command builder and parameter sanitization.

Includes explicit command injection test cases.
"""

from __future__ import annotations

import pytest

from sna.devices.command_builder import (
    CommandBuilder,
    CommandTemplate,
    CommandValidationError,
    ParamSpec,
    ParamType,
    create_default_command_builder,
    validate_param,
)


class TestParamValidation:
    """Parameter type validation tests."""

    def test_valid_interface(self) -> None:
        result = validate_param("GigabitEthernet0/1", ParamType.INTERFACE, "iface")
        assert result == "GigabitEthernet0/1"

    def test_valid_loopback(self) -> None:
        result = validate_param("Loopback0", ParamType.INTERFACE, "iface")
        assert result == "Loopback0"

    def test_invalid_interface(self) -> None:
        with pytest.raises(CommandValidationError, match="not a valid interface"):
            validate_param("../etc/passwd", ParamType.INTERFACE, "iface")

    def test_valid_vlan_id(self) -> None:
        result = validate_param("100", ParamType.VLAN_ID, "vlan")
        assert result == "100"

    def test_vlan_id_min(self) -> None:
        result = validate_param("1", ParamType.VLAN_ID, "vlan")
        assert result == "1"

    def test_vlan_id_max(self) -> None:
        result = validate_param("4094", ParamType.VLAN_ID, "vlan")
        assert result == "4094"

    def test_vlan_id_out_of_range(self) -> None:
        with pytest.raises(CommandValidationError, match="VLAN ID out of range"):
            validate_param("4095", ParamType.VLAN_ID, "vlan")

    def test_vlan_id_zero(self) -> None:
        with pytest.raises(CommandValidationError, match="VLAN ID out of range"):
            validate_param("0", ParamType.VLAN_ID, "vlan")

    def test_vlan_id_not_number(self) -> None:
        with pytest.raises(CommandValidationError, match="valid VLAN ID"):
            validate_param("abc", ParamType.VLAN_ID, "vlan")

    def test_valid_ip(self) -> None:
        result = validate_param("10.0.0.1", ParamType.IP_ADDRESS, "ip")
        assert result == "10.0.0.1"

    def test_invalid_ip(self) -> None:
        with pytest.raises(CommandValidationError, match="not a valid IPv4"):
            validate_param("999.999.999.999", ParamType.IP_ADDRESS, "ip")

    def test_valid_prefix(self) -> None:
        result = validate_param("10.0.0.0/24", ParamType.PREFIX, "pfx")
        assert result == "10.0.0.0/24"

    def test_invalid_prefix(self) -> None:
        with pytest.raises(CommandValidationError, match="not a valid prefix"):
            validate_param("10.0.0.0/33", ParamType.PREFIX, "pfx")

    def test_valid_asn(self) -> None:
        result = validate_param("65000", ParamType.ASN, "asn")
        assert result == "65000"

    def test_asn_out_of_range(self) -> None:
        with pytest.raises(CommandValidationError, match="ASN out of range"):
            validate_param("0", ParamType.ASN, "asn")

    def test_valid_hostname(self) -> None:
        result = validate_param("switch-01.lab", ParamType.HOSTNAME, "host")
        assert result == "switch-01.lab"

    def test_invalid_hostname(self) -> None:
        with pytest.raises(CommandValidationError, match="not a valid hostname"):
            validate_param("host name with spaces", ParamType.HOSTNAME, "host")

    def test_valid_description(self) -> None:
        result = validate_param("Uplink to core", ParamType.DESCRIPTION, "desc")
        assert result == "Uplink to core"

    def test_string_max_length(self) -> None:
        with pytest.raises(CommandValidationError, match="exceeds maximum length"):
            validate_param("x" * 256, ParamType.STRING, "s")

    def test_integer_valid(self) -> None:
        result = validate_param("42", ParamType.INTEGER, "num")
        assert result == "42"

    def test_integer_invalid(self) -> None:
        with pytest.raises(CommandValidationError, match="must be an integer"):
            validate_param("abc", ParamType.INTEGER, "num")


class TestForbiddenCharacters:
    """Command injection prevention — forbidden character tests."""

    @pytest.mark.parametrize("char,name", [
        ("\n", "newline"),
        ("\r", "carriage return"),
        ("|", "pipe"),
        (";", "semicolon"),
        ("!", "exclamation"),
    ])
    def test_forbidden_chars_rejected(self, char: str, name: str) -> None:
        with pytest.raises(CommandValidationError, match="forbidden characters"):
            validate_param(f"value{char}malicious", ParamType.STRING, "test")

    def test_pipe_injection(self) -> None:
        """Pipe injection: show interfaces | include password."""
        with pytest.raises(CommandValidationError):
            validate_param("Gig0/1 | show password", ParamType.INTERFACE, "iface")

    def test_newline_injection(self) -> None:
        """Newline injection: description\nwrite erase."""
        with pytest.raises(CommandValidationError):
            validate_param("normal\nwrite erase", ParamType.DESCRIPTION, "desc")

    def test_semicolon_chaining(self) -> None:
        """Semicolon chaining: value; write erase."""
        with pytest.raises(CommandValidationError):
            validate_param("value; write erase", ParamType.STRING, "param")

    def test_shell_metacharacters_in_hostname(self) -> None:
        """Shell metacharacters in device target."""
        with pytest.raises(CommandValidationError):
            validate_param("host$(whoami)", ParamType.HOSTNAME, "device")


class TestCommandBuilder:
    """CommandBuilder registration and build tests."""

    def test_build_simple_command(self) -> None:
        builder = CommandBuilder()
        builder.register(CommandTemplate(
            tool_name="test_tool",
            template="show {thing}",
            params=[ParamSpec("thing", ParamType.HOSTNAME)],
        ))
        result = builder.build("test_tool", {"thing": "interfaces"})
        assert result == "show interfaces"

    def test_build_unknown_tool(self) -> None:
        builder = CommandBuilder()
        with pytest.raises(CommandValidationError, match="Unknown tool"):
            builder.build("nonexistent", {})

    def test_build_missing_required_param(self) -> None:
        builder = CommandBuilder()
        builder.register(CommandTemplate(
            tool_name="test",
            template="show {iface}",
            params=[ParamSpec("iface", ParamType.INTERFACE, required=True)],
        ))
        with pytest.raises(CommandValidationError, match="Missing required"):
            builder.build("test", {})

    def test_build_unknown_param(self) -> None:
        builder = CommandBuilder()
        builder.register(CommandTemplate(
            tool_name="test",
            template="show stuff",
        ))
        with pytest.raises(CommandValidationError, match="Unknown parameter"):
            builder.build("test", {"bad_param": "value"})

    def test_get_timeout(self) -> None:
        builder = CommandBuilder()
        builder.register(CommandTemplate(
            tool_name="test", template="show ver", timeout_ops=120,
        ))
        assert builder.get_timeout("test") == 120
        assert builder.get_timeout("unknown") == 30

    def test_get_template(self) -> None:
        builder = CommandBuilder()
        tpl = CommandTemplate(tool_name="test", template="show ver")
        builder.register(tpl)
        assert builder.get_template("test") is tpl
        assert builder.get_template("unknown") is None


class TestDefaultCommandBuilder:
    """Tests for the default command builder with all standard tools."""

    def test_show_running_config(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("show_running_config", {})
        assert result == "show running-config"

    def test_show_interfaces(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("show_interfaces", {})
        assert result == "show interfaces"

    def test_ping(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("ping", {"target": "10.0.0.1"})
        assert result == "ping 10.0.0.1"

    def test_set_interface_description(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("set_interface_description", {
            "interface": "GigabitEthernet0/1",
            "description": "Uplink to core",
        })
        assert "interface GigabitEthernet0/1" in result
        assert "description Uplink to core" in result

    def test_configure_static_route(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("configure_static_route", {
            "prefix": "10.0.0.0/24",
            "next_hop": "192.168.1.1",
        })
        assert result == "ip route 10.0.0.0/24 192.168.1.1"

    def test_configure_vlan(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("configure_vlan", {
            "vlan_id": "100",
            "name": "USERS",
        })
        assert "vlan 100" in result
        assert "name USERS" in result

    def test_configure_bgp_neighbor(self) -> None:
        builder = create_default_command_builder()
        result = builder.build("configure_bgp_neighbor", {
            "local_asn": "65000",
            "neighbor_ip": "10.0.0.2",
            "remote_asn": "65001",
        })
        assert "router bgp 65000" in result
        assert "neighbor 10.0.0.2 remote-as 65001" in result

    def test_injection_via_ping_target(self) -> None:
        """Verify injection via IP address field is blocked."""
        builder = create_default_command_builder()
        with pytest.raises(CommandValidationError):
            builder.build("ping", {"target": "10.0.0.1; show password"})

    def test_injection_via_description(self) -> None:
        """Verify injection via description field is blocked."""
        builder = create_default_command_builder()
        with pytest.raises(CommandValidationError):
            builder.build("set_interface_description", {
                "interface": "GigabitEthernet0/1",
                "description": "normal\nwrite erase",
            })

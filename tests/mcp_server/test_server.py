"""Tests for MCP server and tool registration."""

from __future__ import annotations

from sna.mcp_server.tools.read import READ_TOOLS
from sna.mcp_server.tools.write import WRITE_TOOLS


class TestToolRegistration:
    """Verify tool definitions are well-formed."""

    def test_read_tools_defined(self) -> None:
        assert len(READ_TOOLS) == 5
        assert "show_running_config" in READ_TOOLS
        assert "show_interfaces" in READ_TOOLS
        assert "show_bgp_summary" in READ_TOOLS
        assert "ping" in READ_TOOLS
        assert "traceroute" in READ_TOOLS

    def test_write_tools_defined(self) -> None:
        assert len(WRITE_TOOLS) == 6
        assert "set_interface_description" in WRITE_TOOLS
        assert "configure_static_route" in WRITE_TOOLS
        assert "configure_vlan" in WRITE_TOOLS
        assert "configure_acl" in WRITE_TOOLS
        assert "configure_bgp_neighbor" in WRITE_TOOLS
        assert "configure_logging" in WRITE_TOOLS

    def test_all_tools_have_description(self) -> None:
        for name, meta in {**READ_TOOLS, **WRITE_TOOLS}.items():
            assert "description" in meta, f"Tool {name} missing description"
            assert len(meta["description"]) > 0

    def test_all_tools_have_input_schema(self) -> None:
        for name, meta in {**READ_TOOLS, **WRITE_TOOLS}.items():
            assert "input_schema" in meta, f"Tool {name} missing input_schema"

    def test_no_overlapping_tool_names(self) -> None:
        overlap = set(READ_TOOLS.keys()) & set(WRITE_TOOLS.keys())
        assert len(overlap) == 0, f"Overlapping tool names: {overlap}"

    def test_input_schemas_have_device_field(self) -> None:
        """All tools must have a 'device' field for targeting."""
        for name, meta in {**READ_TOOLS, **WRITE_TOOLS}.items():
            schema = meta["input_schema"]
            fields = schema.model_fields
            assert "device" in fields, f"Tool {name} missing 'device' field"

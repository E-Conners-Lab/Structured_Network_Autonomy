"""Tests for SemanticDiffValidator."""

from __future__ import annotations

import pytest

from sna.validation.config_diff_validator import SemanticDiffValidator
from sna.validation.validator import ValidationStatus


class TestSemanticDiffValidator:
    """SemanticDiffValidator tests."""

    async def test_pass_when_config_changed(self) -> None:
        v = SemanticDiffValidator()
        before = "interface GigabitEthernet0/1\n description OLD\n!\n"
        after = "interface GigabitEthernet0/1\n description NEW\n!\n"
        result = await v.validate(
            "set_interface_description", "sw1",
            before_state={"running_config": before},
            after_state={"running_config": after},
        )
        assert result.status == ValidationStatus.PASS
        assert result.testcase_name == "semantic_diff"
        assert "changes" in result.details

    async def test_fail_when_no_changes(self) -> None:
        v = SemanticDiffValidator()
        config = "interface GigabitEthernet0/1\n description Test\n!\n"
        result = await v.validate(
            "set_interface_description", "sw1",
            before_state={"running_config": config},
            after_state={"running_config": config},
        )
        assert result.status == ValidationStatus.FAIL

    async def test_skip_when_no_state(self) -> None:
        v = SemanticDiffValidator()
        result = await v.validate("configure_vlan", "sw1", None, None)
        assert result.status == ValidationStatus.SKIP

    async def test_skip_when_empty_config(self) -> None:
        v = SemanticDiffValidator()
        result = await v.validate(
            "configure_vlan", "sw1",
            before_state={"running_config": ""},
            after_state={"running_config": ""},
        )
        assert result.status == ValidationStatus.SKIP

    async def test_details_include_structured_diff(self) -> None:
        v = SemanticDiffValidator()
        before = "hostname R1\n"
        after = "hostname R1\n!\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255\n!\n"
        result = await v.validate(
            "configure_vlan", "sw1",
            before_state={"running_config": before},
            after_state={"running_config": after},
        )
        assert result.status == ValidationStatus.PASS
        changes = result.details["changes"]
        assert len(changes) >= 1
        assert changes[0]["change_type"] in ("ADDED", "MODIFIED", "REMOVED")

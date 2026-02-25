"""Tests for validation rules engine."""

from __future__ import annotations

import pytest

from sna.validation.rules import (
    ConfigChangedValidator,
    InterfaceUpValidator,
    ReachabilityValidator,
    ValidationEngine,
    ValidationRule,
    TESTCASE_REGISTRY,
)
from sna.validation.validator import ValidationStatus


class TestConfigChangedValidator:
    """Config change detection."""

    async def test_config_changed(self) -> None:
        v = ConfigChangedValidator()
        result = await v.validate(
            "configure_vlan", "sw1",
            before_state={"running_config": "old config"},
            after_state={"running_config": "new config"},
        )
        assert result.status == ValidationStatus.PASS

    async def test_config_unchanged(self) -> None:
        v = ConfigChangedValidator()
        result = await v.validate(
            "configure_vlan", "sw1",
            before_state={"running_config": "same"},
            after_state={"running_config": "same"},
        )
        assert result.status == ValidationStatus.FAIL

    async def test_no_state_skips(self) -> None:
        v = ConfigChangedValidator()
        result = await v.validate("configure_vlan", "sw1", None, None)
        assert result.status == ValidationStatus.SKIP

    async def test_missing_before_skips(self) -> None:
        v = ConfigChangedValidator()
        result = await v.validate(
            "configure_vlan", "sw1",
            before_state=None,
            after_state={"running_config": "config"},
        )
        assert result.status == ValidationStatus.SKIP


class TestInterfaceUpValidator:
    """Interface status validation."""

    async def test_interface_up(self) -> None:
        v = InterfaceUpValidator()
        result = await v.validate(
            "set_interface_description", "sw1",
            before_state=None,
            after_state={"interface_status": "up/up"},
        )
        assert result.status == ValidationStatus.PASS

    async def test_interface_down(self) -> None:
        v = InterfaceUpValidator()
        result = await v.validate(
            "set_interface_description", "sw1",
            before_state=None,
            after_state={"interface_status": "down/down"},
        )
        assert result.status == ValidationStatus.FAIL

    async def test_no_after_state(self) -> None:
        v = InterfaceUpValidator()
        result = await v.validate("set_interface_description", "sw1", None, None)
        assert result.status == ValidationStatus.SKIP


class TestReachabilityValidator:
    """Reachability validation."""

    async def test_reachable(self) -> None:
        v = ReachabilityValidator()
        result = await v.validate(
            "configure_static_route", "sw1",
            before_state=None,
            after_state={"reachable": True},
        )
        assert result.status == ValidationStatus.PASS

    async def test_unreachable(self) -> None:
        v = ReachabilityValidator()
        result = await v.validate(
            "configure_static_route", "sw1",
            before_state=None,
            after_state={"reachable": False},
        )
        assert result.status == ValidationStatus.FAIL

    async def test_no_data(self) -> None:
        v = ReachabilityValidator()
        result = await v.validate(
            "configure_static_route", "sw1",
            before_state=None,
            after_state={},
        )
        assert result.status == ValidationStatus.SKIP


class TestTestcaseRegistry:
    """Testcase registry."""

    def test_all_built_in_registered(self) -> None:
        assert "config_changed" in TESTCASE_REGISTRY
        assert "interface_up" in TESTCASE_REGISTRY
        assert "reachability" in TESTCASE_REGISTRY


class TestValidationEngine:
    """Validation engine orchestration."""

    async def test_no_rules_for_tool(self) -> None:
        engine = ValidationEngine(rules=[])
        results = await engine.run_validations("unknown_tool", "sw1", None, None)
        assert results == []

    async def test_runs_matching_rules(self) -> None:
        rules = [
            ValidationRule(
                tool_pattern="configure_vlan",
                testcase_name="config_changed",
            ),
        ]
        engine = ValidationEngine(rules=rules)
        results = await engine.run_validations(
            "configure_vlan", "sw1",
            before_state={"running_config": "old"},
            after_state={"running_config": "new"},
        )
        assert len(results) == 1
        assert results[0].status == ValidationStatus.PASS

    async def test_missing_testcase(self) -> None:
        rules = [
            ValidationRule(
                tool_pattern="test_tool",
                testcase_name="nonexistent",
            ),
        ]
        engine = ValidationEngine(rules=rules)
        results = await engine.run_validations("test_tool", "sw1", None, None)
        assert len(results) == 1
        assert results[0].status == ValidationStatus.ERROR

    async def test_has_failures(self) -> None:
        rules = [
            ValidationRule(
                tool_pattern="configure_vlan",
                testcase_name="config_changed",
                required=True,
            ),
        ]
        engine = ValidationEngine(rules=rules)
        results = await engine.run_validations(
            "configure_vlan", "sw1",
            before_state={"running_config": "same"},
            after_state={"running_config": "same"},
        )
        assert engine.has_failures(results)

    async def test_no_failures_when_pass(self) -> None:
        rules = [
            ValidationRule(
                tool_pattern="configure_vlan",
                testcase_name="config_changed",
                required=True,
            ),
        ]
        engine = ValidationEngine(rules=rules)
        results = await engine.run_validations(
            "configure_vlan", "sw1",
            before_state={"running_config": "old"},
            after_state={"running_config": "new"},
        )
        assert not engine.has_failures(results)

    def test_get_rules_for_tool(self) -> None:
        rules = [
            ValidationRule(tool_pattern="a", testcase_name="config_changed"),
            ValidationRule(tool_pattern="b", testcase_name="config_changed"),
            ValidationRule(tool_pattern="a", testcase_name="interface_up"),
        ]
        engine = ValidationEngine(rules=rules)
        assert len(engine.get_rules_for_tool("a")) == 2
        assert len(engine.get_rules_for_tool("b")) == 1
        assert len(engine.get_rules_for_tool("c")) == 0

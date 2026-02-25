"""Tests for pyATS adapter — wrapping SNA validators into pyATS test cases."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sna.validation.pyats_adapter import (
    PyATSNotAvailable,
    SNATestcase,
    create_pyats_job,
    run_pyats_validation,
)
from sna.validation.rules import ConfigChangedValidator
from sna.validation.validator import ValidationResult, ValidationStatus, Validator


class TestSNATestcase:
    """SNATestcase wraps validators correctly."""

    async def test_wraps_validator(self) -> None:
        validator = ConfigChangedValidator()
        tc = SNATestcase(
            name="test_config_changed",
            validator=validator,
            tool_name="configure_vlan",
            device_target="sw1",
        )
        tc.setup(before_state={"running_config": "old"})
        result = await tc.test(after_state={"running_config": "new"})

        assert result.status == ValidationStatus.PASS
        assert result.testcase_name == "config_changed"

    async def test_cleanup_is_noop(self) -> None:
        validator = ConfigChangedValidator()
        tc = SNATestcase(
            name="test",
            validator=validator,
            tool_name="configure_vlan",
            device_target="sw1",
        )
        tc.cleanup()  # Should not raise


class TestCreatePyatsJob:
    """create_pyats_job produces correct testcase list."""

    def test_creates_testcases(self) -> None:
        v1 = ConfigChangedValidator()
        v2 = ConfigChangedValidator()
        testcases = create_pyats_job("configure_vlan", "sw1", [v1, v2])

        assert len(testcases) == 2
        assert all(isinstance(tc, SNATestcase) for tc in testcases)
        assert all(tc.tool_name == "configure_vlan" for tc in testcases)
        assert all(tc.device_target == "sw1" for tc in testcases)

    def test_empty_validators(self) -> None:
        testcases = create_pyats_job("configure_vlan", "sw1", [])
        assert testcases == []


class TestRunPyatsValidation:
    """run_pyats_validation returns ValidationResults."""

    async def test_raises_when_pyats_not_available(self) -> None:
        """pyATS not installed → raises PyATSNotAvailable."""
        v = ConfigChangedValidator()
        testcases = create_pyats_job("configure_vlan", "sw1", [v])

        # pyATS should not be installed in test env
        with pytest.raises(PyATSNotAvailable):
            await run_pyats_validation(
                testcases,
                before_state={"running_config": "old"},
                after_state={"running_config": "new"},
            )

    async def test_returns_results_with_mock_pyats(self) -> None:
        """With pyATS mocked as available, returns results."""
        v = ConfigChangedValidator()
        testcases = create_pyats_job("configure_vlan", "sw1", [v])

        with patch("sna.validation.pyats_adapter._check_pyats_available", return_value=True):
            results = await run_pyats_validation(
                testcases,
                before_state={"running_config": "old"},
                after_state={"running_config": "new"},
            )

        assert len(results) == 1
        assert results[0].status == ValidationStatus.PASS


class TestValidationEnginePyatsIntegration:
    """ValidationEngine with pyats_enabled falls back correctly."""

    async def test_pyats_fallback_to_native(self) -> None:
        """When pyATS is not available, falls back to native validation."""
        from sna.validation.rules import ValidationEngine, ValidationRule

        rules = [ValidationRule(
            tool_pattern="configure_vlan",
            testcase_name="config_changed",
        )]
        engine = ValidationEngine(rules=rules, pyats_enabled=True)

        results = await engine.run_validations(
            "configure_vlan", "sw1",
            before_state={"running_config": "old"},
            after_state={"running_config": "new"},
        )
        assert len(results) == 1
        assert results[0].status == ValidationStatus.PASS

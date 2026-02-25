"""Tests for the validation framework."""

from __future__ import annotations

import pytest

from sna.validation.validator import ValidationResult, ValidationStatus, Validator


class DummyPassValidator(Validator):
    async def validate(self, tool_name, device_target, before_state, after_state):
        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="dummy_pass",
            message="Always passes",
        )


class DummyFailValidator(Validator):
    async def validate(self, tool_name, device_target, before_state, after_state):
        return ValidationResult(
            status=ValidationStatus.FAIL,
            testcase_name="dummy_fail",
            message="Always fails",
        )


class TestValidationResult:
    """ValidationResult dataclass."""

    def test_pass_result(self) -> None:
        r = ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="test",
            message="ok",
        )
        assert r.status == ValidationStatus.PASS
        assert r.testcase_name == "test"

    def test_fail_result(self) -> None:
        r = ValidationResult(
            status=ValidationStatus.FAIL,
            testcase_name="test",
            message="bad",
            details={"error": "something"},
        )
        assert r.status == ValidationStatus.FAIL
        assert r.details["error"] == "something"

    def test_status_enum(self) -> None:
        assert ValidationStatus.PASS.value == "PASS"
        assert ValidationStatus.FAIL.value == "FAIL"
        assert ValidationStatus.SKIP.value == "SKIP"
        assert ValidationStatus.ERROR.value == "ERROR"


class TestValidatorABC:
    """Validator abstract base class."""

    async def test_pass_validator(self) -> None:
        v = DummyPassValidator()
        result = await v.validate("test", "sw1", None, None)
        assert result.status == ValidationStatus.PASS

    async def test_fail_validator(self) -> None:
        v = DummyFailValidator()
        result = await v.validate("test", "sw1", None, None)
        assert result.status == ValidationStatus.FAIL

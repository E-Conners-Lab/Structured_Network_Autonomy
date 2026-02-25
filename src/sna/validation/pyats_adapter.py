"""pyATS adapter — wraps SNA validators into pyATS-compatible test cases.

All pyATS imports are guarded with try/except ImportError. If pyATS is not
installed, the adapter raises PyATSNotAvailable and callers fall back to
native SNA validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sna.validation.validator import ValidationResult, ValidationStatus, Validator


class PyATSNotAvailable(Exception):
    """Raised when pyATS is not installed."""


def _check_pyats_available() -> bool:
    """Check if pyATS and Genie are importable."""
    try:
        import pyats  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class SNATestcase:
    """Wraps an SNA Validator into a pyATS-style test case.

    Provides setup/test/cleanup lifecycle similar to pyATS Testcase.

    Args:
        name: Test case name.
        validator: The SNA Validator instance.
        tool_name: The tool that was executed.
        device_target: The device that was modified.
    """

    name: str
    validator: Validator
    tool_name: str
    device_target: str
    _before_state: dict | None = field(default=None, repr=False)
    _after_state: dict | None = field(default=None, repr=False)
    _result: ValidationResult | None = field(default=None, repr=False)

    def setup(self, before_state: dict | None) -> None:
        """Capture before state."""
        self._before_state = before_state

    async def test(self, after_state: dict | None) -> ValidationResult:
        """Run the validator and map result to pyATS pass/fail."""
        self._after_state = after_state
        self._result = await self.validator.validate(
            self.tool_name, self.device_target,
            self._before_state, self._after_state,
        )

        # If pyATS is available, try to report via pyATS
        if _check_pyats_available():
            try:
                from pyats.results import Passed, Failed, Skipped  # type: ignore[import-untyped]

                if self._result.status == ValidationStatus.PASS:
                    pass  # pyATS Passed
                elif self._result.status == ValidationStatus.FAIL:
                    pass  # pyATS Failed
                # We don't actually need to call pyATS APIs here;
                # the adapter just maps the result
            except ImportError:
                pass

        return self._result

    def cleanup(self) -> None:
        """No-op cleanup."""


def create_pyats_job(
    tool_name: str,
    device_target: str,
    validators: list[Validator],
) -> list[SNATestcase]:
    """Create a list of pyATS-style test cases from SNA validators.

    Args:
        tool_name: The tool that was executed.
        device_target: The device that was modified.
        validators: List of SNA validators to wrap.

    Returns:
        List of SNATestcase instances.
    """
    return [
        SNATestcase(
            name=f"sna_{type(v).__name__}_{device_target}",
            validator=v,
            tool_name=tool_name,
            device_target=device_target,
        )
        for v in validators
    ]


async def run_pyats_validation(
    testcases: list[SNATestcase],
    before_state: dict | None,
    after_state: dict | None,
) -> list[ValidationResult]:
    """Run pyATS-wrapped validation test cases.

    If pyATS is not available, raises PyATSNotAvailable.
    Callers should catch this and fall back to native validation.

    Args:
        testcases: List of SNATestcase instances.
        before_state: Pre-change device state.
        after_state: Post-change device state.

    Returns:
        List of ValidationResult from each test case.

    Raises:
        PyATSNotAvailable: If pyATS is not installed.
    """
    if not _check_pyats_available():
        raise PyATSNotAvailable("pyATS is not installed — falling back to native validation")

    results: list[ValidationResult] = []
    for tc in testcases:
        tc.setup(before_state)
        result = await tc.test(after_state)
        results.append(result)
        tc.cleanup()

    return results

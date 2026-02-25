"""Post-change validation framework.

Defines the Validator ABC and ValidationResult dataclass.
Validators run after successful device execution, before marking an action complete.
Failed validation triggers automatic rollback.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime


class ValidationStatus(str, enum.Enum):
    """Validation result status."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ValidationResult:
    """Result from a single validation check."""

    status: ValidationStatus
    testcase_name: str
    message: str = ""
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_seconds: float = 0.0


class Validator(abc.ABC):
    """Abstract base class for post-change validators.

    Subclasses implement validate() to check that a change was successful.
    The framework calls validate() after device execution and triggers
    rollback if validation fails.
    """

    @abc.abstractmethod
    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        """Run validation checks after a device change.

        Args:
            tool_name: The tool that was executed.
            device_target: The device that was modified.
            before_state: Pre-change state (e.g., show running-config output).
            after_state: Post-change state for comparison.

        Returns:
            ValidationResult indicating pass, fail, skip, or error.
        """
        ...

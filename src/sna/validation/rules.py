"""Configurable validation rules engine.

Maps tool names and tiers to pre-registered validation testcases.
Testcases are loaded from a fixed registry — no dynamic Python imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from sna.validation.config_diff_validator import SemanticDiffValidator
from sna.validation.protocol_validators import (
    BGPNeighborUpValidator,
    OSPFNeighborValidator,
    PrefixCountValidator,
    RouteConvergenceValidator,
)
from sna.validation.validator import ValidationResult, ValidationStatus, Validator

logger = structlog.get_logger()


@dataclass(frozen=True)
class ValidationRule:
    """A validation rule mapping a tool (or tier) to a testcase name."""

    tool_pattern: str  # exact tool name, or "tier_*" pattern
    testcase_name: str
    description: str = ""
    required: bool = True  # If True, failure triggers rollback


# --- Built-in testcases (pre-registered) ---


class ConfigChangedValidator(Validator):
    """Validates that the running config actually changed after a write operation."""

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if before_state is None or after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="config_changed",
                message="Before/after state not available — skipping",
            )

        before_config = before_state.get("running_config", "")
        after_config = after_state.get("running_config", "")

        if before_config == after_config:
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="config_changed",
                message="Running config unchanged after write operation",
            )

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="config_changed",
            message="Running config changed successfully",
        )


class InterfaceUpValidator(Validator):
    """Validates that an interface is up after configuration."""

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="interface_up",
                message="After state not available",
            )

        interface_status = after_state.get("interface_status", "")
        if "up" in str(interface_status).lower():
            return ValidationResult(
                status=ValidationStatus.PASS,
                testcase_name="interface_up",
                message=f"Interface is up on {device_target}",
            )

        return ValidationResult(
            status=ValidationStatus.FAIL,
            testcase_name="interface_up",
            message=f"Interface is not up on {device_target}",
            details={"status": str(interface_status)},
        )


class ReachabilityValidator(Validator):
    """Validates basic reachability (ping) after a change."""

    async def validate(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> ValidationResult:
        if after_state is None:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="reachability",
                message="After state not available",
            )

        reachable = after_state.get("reachable", None)
        if reachable is True:
            return ValidationResult(
                status=ValidationStatus.PASS,
                testcase_name="reachability",
                message=f"Device {device_target} is reachable",
            )
        elif reachable is False:
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="reachability",
                message=f"Device {device_target} is NOT reachable",
            )

        return ValidationResult(
            status=ValidationStatus.SKIP,
            testcase_name="reachability",
            message="Reachability data not available",
        )


# --- Testcase registry ---

TESTCASE_REGISTRY: dict[str, Validator] = {
    "config_changed": ConfigChangedValidator(),
    "interface_up": InterfaceUpValidator(),
    "reachability": ReachabilityValidator(),
    "semantic_diff": SemanticDiffValidator(),
    "bgp_neighbor_up": BGPNeighborUpValidator(),
    "ospf_neighbor_full": OSPFNeighborValidator(),
    "prefix_count": PrefixCountValidator(),
    "route_convergence": RouteConvergenceValidator(),
}


# --- Default validation rules ---

DEFAULT_RULES: list[ValidationRule] = [
    ValidationRule(
        tool_pattern="set_interface_description",
        testcase_name="config_changed",
        description="Verify config changed after interface description update",
    ),
    ValidationRule(
        tool_pattern="configure_static_route",
        testcase_name="config_changed",
        description="Verify config changed after static route",
    ),
    ValidationRule(
        tool_pattern="configure_vlan",
        testcase_name="config_changed",
        description="Verify config changed after VLAN configuration",
    ),
    ValidationRule(
        tool_pattern="configure_acl",
        testcase_name="config_changed",
        description="Verify config changed after ACL configuration",
    ),
    ValidationRule(
        tool_pattern="configure_bgp_neighbor",
        testcase_name="config_changed",
        description="Verify config changed after BGP neighbor configuration",
    ),
    ValidationRule(
        tool_pattern="configure_bgp_neighbor",
        testcase_name="bgp_neighbor_up",
        description="Verify BGP neighbor reaches Established state",
    ),
    ValidationRule(
        tool_pattern="configure_bgp_neighbor",
        testcase_name="prefix_count",
        description="Verify BGP prefix count is healthy",
    ),
    ValidationRule(
        tool_pattern="configure_ospf_area",
        testcase_name="config_changed",
        description="Verify config changed after OSPF configuration",
    ),
    ValidationRule(
        tool_pattern="configure_ospf_area",
        testcase_name="ospf_neighbor_full",
        description="Verify OSPF neighbor reaches FULL state",
    ),
]


class ValidationEngine:
    """Runs validation rules against post-change state.

    Args:
        rules: List of validation rules. Defaults to DEFAULT_RULES.
        pyats_enabled: If True and pyATS available, run through pyATS adapter.
    """

    def __init__(
        self,
        rules: list[ValidationRule] | None = None,
        pyats_enabled: bool = False,
    ) -> None:
        self._rules = rules or DEFAULT_RULES
        self._pyats_enabled = pyats_enabled

    def get_rules_for_tool(self, tool_name: str) -> list[ValidationRule]:
        """Return all validation rules that apply to a tool."""
        return [r for r in self._rules if r.tool_pattern == tool_name]

    async def run_validations(
        self,
        tool_name: str,
        device_target: str,
        before_state: dict | None,
        after_state: dict | None,
    ) -> list[ValidationResult]:
        """Run all applicable validations for a tool execution.

        If pyats_enabled and pyATS is available, runs through the pyATS adapter.
        Otherwise runs validators natively.

        Args:
            tool_name: The tool that was executed.
            device_target: The device that was modified.
            before_state: Pre-change state.
            after_state: Post-change state.

        Returns:
            List of ValidationResults. Empty if no rules apply.
        """
        rules = self.get_rules_for_tool(tool_name)
        if not rules:
            return []

        # Collect validators for matching rules
        validators_for_pyats: list[Validator] = []
        results: list[ValidationResult] = []

        for rule in rules:
            validator = TESTCASE_REGISTRY.get(rule.testcase_name)
            if validator is None:
                await logger.awarning(
                    "validation_testcase_not_found",
                    testcase=rule.testcase_name,
                    tool=tool_name,
                )
                results.append(ValidationResult(
                    status=ValidationStatus.ERROR,
                    testcase_name=rule.testcase_name,
                    message=f"Testcase '{rule.testcase_name}' not found in registry",
                ))
                continue

            if self._pyats_enabled:
                validators_for_pyats.append(validator)
            else:
                try:
                    result = await validator.validate(tool_name, device_target, before_state, after_state)
                    results.append(result)
                except Exception as exc:
                    await logger.aerror(
                        "validation_error",
                        testcase=rule.testcase_name,
                        tool=tool_name,
                        error=str(exc),
                    )
                    results.append(ValidationResult(
                        status=ValidationStatus.ERROR,
                        testcase_name=rule.testcase_name,
                        message=f"Validation error: {exc}",
                    ))

        # Run through pyATS adapter if enabled
        if self._pyats_enabled and validators_for_pyats:
            try:
                from sna.validation.pyats_adapter import (
                    PyATSNotAvailable,
                    create_pyats_job,
                    run_pyats_validation,
                )

                testcases = create_pyats_job(tool_name, device_target, validators_for_pyats)
                pyats_results = await run_pyats_validation(testcases, before_state, after_state)
                results.extend(pyats_results)
            except PyATSNotAvailable:
                await logger.awarning("pyats_not_available_fallback_native")
                # Fallback to native validation
                for validator in validators_for_pyats:
                    try:
                        result = await validator.validate(tool_name, device_target, before_state, after_state)
                        results.append(result)
                    except Exception as exc:
                        results.append(ValidationResult(
                            status=ValidationStatus.ERROR,
                            testcase_name=type(validator).__name__,
                            message=f"Validation error: {exc}",
                        ))
            except Exception as exc:
                await logger.aerror("pyats_validation_error", error=str(exc))
                # Fallback to native
                for validator in validators_for_pyats:
                    try:
                        result = await validator.validate(tool_name, device_target, before_state, after_state)
                        results.append(result)
                    except Exception as val_exc:
                        results.append(ValidationResult(
                            status=ValidationStatus.ERROR,
                            testcase_name=type(validator).__name__,
                            message=f"Validation error: {val_exc}",
                        ))

        return results

    def has_failures(self, results: list[ValidationResult]) -> bool:
        """Check if any required validation failed."""
        for result in results:
            if result.status == ValidationStatus.FAIL:
                # Check if the rule is required
                for rule in self._rules:
                    if rule.testcase_name == result.testcase_name and rule.required:
                        return True
        return False

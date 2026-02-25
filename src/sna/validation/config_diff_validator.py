"""Semantic diff validator — validates config changes using section-aware diffing."""

from __future__ import annotations

from sna.validation.config_diff import compute_semantic_diff, summarize_diff
from sna.validation.validator import ValidationResult, ValidationStatus, Validator


class SemanticDiffValidator(Validator):
    """Validates that config changes are detected via semantic (section-aware) diff.

    Reports changes grouped by config section. PASS if changes detected in
    expected sections, FAIL if no changes detected for a write operation.
    """

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
                testcase_name="semantic_diff",
                message="Before/after state not available — skipping semantic diff",
            )

        before_config = before_state.get("running_config", "")
        after_config = after_state.get("running_config", "")

        if not before_config or not after_config:
            return ValidationResult(
                status=ValidationStatus.SKIP,
                testcase_name="semantic_diff",
                message="Running config not available in state",
            )

        diff_entries = compute_semantic_diff(before_config, after_config)

        if not diff_entries:
            return ValidationResult(
                status=ValidationStatus.FAIL,
                testcase_name="semantic_diff",
                message=f"No semantic config changes detected after {tool_name}",
            )

        summary = summarize_diff(diff_entries)
        details = {
            "changes": [
                {
                    "section": e.section,
                    "change_type": e.change_type.value,
                    "before_lines": list(e.before_lines),
                    "after_lines": list(e.after_lines),
                }
                for e in diff_entries
            ],
        }

        return ValidationResult(
            status=ValidationStatus.PASS,
            testcase_name="semantic_diff",
            message=summary,
            details=details,
        )

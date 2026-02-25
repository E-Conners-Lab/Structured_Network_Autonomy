"""Configuration compliance checking.

Validates device configurations against a set of compliance rules
that specify required and forbidden configuration lines per section.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from sna.validation.config_diff import parse_config_sections


class ViolationType(str, enum.Enum):
    """Type of compliance violation."""

    MISSING_REQUIRED = "MISSING_REQUIRED"
    HAS_FORBIDDEN = "HAS_FORBIDDEN"


@dataclass(frozen=True)
class ComplianceRule:
    """A compliance rule that checks config sections for required/forbidden lines."""

    name: str
    section_pattern: str  # regex pattern matching section names
    required_lines: tuple[str, ...] = ()  # lines that must exist in matching sections
    forbidden_lines: tuple[str, ...] = ()  # lines that must NOT exist
    description: str = ""


@dataclass(frozen=True)
class ComplianceViolation:
    """A single compliance violation found during checking."""

    rule_name: str
    section: str
    violation_type: ViolationType
    details: str


def check_compliance(
    config_text: str,
    rules: list[ComplianceRule],
) -> list[ComplianceViolation]:
    """Check a configuration against compliance rules.

    Args:
        config_text: Raw configuration text.
        rules: List of compliance rules to check.

    Returns:
        List of violations found. Empty list means fully compliant.
    """
    sections = parse_config_sections(config_text)
    violations: list[ComplianceViolation] = []

    for rule in rules:
        pattern = re.compile(rule.section_pattern, re.IGNORECASE)
        matching_sections = [s for s in sections if pattern.search(s.name)]

        if not matching_sections and rule.required_lines:
            violations.append(ComplianceViolation(
                rule_name=rule.name,
                section="(no matching section)",
                violation_type=ViolationType.MISSING_REQUIRED,
                details=f"No section matching '{rule.section_pattern}' found",
            ))
            continue

        for section in matching_sections:
            all_lines = " ".join([section.name] + section.lines)

            # Check required lines
            for req in rule.required_lines:
                if req not in all_lines:
                    violations.append(ComplianceViolation(
                        rule_name=rule.name,
                        section=section.name,
                        violation_type=ViolationType.MISSING_REQUIRED,
                        details=f"Required line missing: '{req}'",
                    ))

            # Check forbidden lines
            for forbidden in rule.forbidden_lines:
                if forbidden in all_lines:
                    violations.append(ComplianceViolation(
                        rule_name=rule.name,
                        section=section.name,
                        violation_type=ViolationType.HAS_FORBIDDEN,
                        details=f"Forbidden line present: '{forbidden}'",
                    ))

    return violations

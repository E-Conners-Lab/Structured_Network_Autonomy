"""Pydantic models for policy YAML schema validation.

Defines the complete type system for the Policy Engine:
- Enums: Verdict (PERMIT/ESCALATE/BLOCK), RiskTier (5 tiers)
- Policy schema: mirrors the YAML structure with strict validation
- Evaluation models: request/result types for the engine interface
"""

from __future__ import annotations

import enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Verdict(str, enum.Enum):
    """Policy engine decision for an action."""

    PERMIT = "PERMIT"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class RiskTier(str, enum.Enum):
    """Action risk classification tiers, ordered by severity."""

    TIER_1_READ = "tier_1_read"
    TIER_2_LOW_RISK_WRITE = "tier_2_low_risk_write"
    TIER_3_MEDIUM_RISK_WRITE = "tier_3_medium_risk_write"
    TIER_4_HIGH_RISK_WRITE = "tier_4_high_risk_write"
    TIER_5_CRITICAL = "tier_5_critical"


# --- Policy YAML schema models ---


class ActionTierConfig(BaseModel):
    """Configuration for a single action tier in the policy YAML."""

    model_config = ConfigDict(extra="forbid")

    description: str
    default_verdict: Verdict
    requires_audit: bool = False
    requires_senior_approval: bool = False
    examples: list[str] = Field(default_factory=list)

    @field_validator("examples")
    @classmethod
    def examples_are_non_empty_strings(cls, v: list[str]) -> list[str]:
        """Ensure example tool names are non-empty and stripped."""
        cleaned = [name.strip() for name in v]
        if any(not name for name in cleaned):
            raise ValueError("Tool name examples must be non-empty strings")
        return cleaned


class ConfidenceThresholds(BaseModel):
    """Minimum confidence scores per risk tier. All values must be 0.0–1.0."""

    model_config = ConfigDict(extra="forbid")

    tier_1_read: float = Field(ge=0.0, le=1.0)
    tier_2_low_risk_write: float = Field(ge=0.0, le=1.0)
    tier_3_medium_risk_write: float = Field(ge=0.0, le=1.0)
    tier_4_high_risk_write: float = Field(ge=0.0, le=1.0)
    tier_5_critical: float = Field(ge=0.0, le=1.0)

    def get_threshold(self, tier: RiskTier) -> float:
        """Return the confidence threshold for a given risk tier."""
        return getattr(self, tier.value)


class EASModulation(BaseModel):
    """Earned Autonomy Score modulation settings."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_threshold_reduction: float = Field(ge=0.0, le=0.5)
    min_eas_for_modulation: float = Field(ge=0.0, le=1.0)


class ScopeLimits(BaseModel):
    """Device scope limits — triggers escalation above threshold."""

    model_config = ConfigDict(extra="forbid")

    max_devices_per_action: int = Field(gt=0)
    escalate_above: int = Field(gt=0)


class HardRules(BaseModel):
    """Actions that are always BLOCK. Cannot be overridden at runtime."""

    model_config = ConfigDict(extra="forbid")

    always_block: list[str] = Field(default_factory=list)
    description: str = ""

    @field_validator("always_block")
    @classmethod
    def block_list_entries_non_empty(cls, v: list[str]) -> list[str]:
        """Ensure hard-block tool names are non-empty and stripped."""
        cleaned = [name.strip() for name in v]
        if any(not name for name in cleaned):
            raise ValueError("Hard rule tool names must be non-empty strings")
        return cleaned


class SiteRule(BaseModel):
    """Context-aware policy rule based on device site."""

    model_config = ConfigDict(extra="forbid")

    site: str
    verdict: Verdict
    applies_to: str = "write"  # "write", "all", or specific tool name
    reason: str = ""


class RoleRule(BaseModel):
    """Context-aware policy rule based on device role."""

    model_config = ConfigDict(extra="forbid")

    role: str
    verdict: Verdict
    applies_to: str = "write"  # "write", "all", or specific tool name
    reason: str = ""


class TagRule(BaseModel):
    """Context-aware policy rule based on device tags."""

    model_config = ConfigDict(extra="forbid")

    tag: str
    verdict: Verdict
    applies_to: str = "write"
    reason: str = ""


class MaintenanceWindowConfig(BaseModel):
    """Maintenance window definition in policy YAML."""

    model_config = ConfigDict(extra="forbid")

    name: str
    sites: list[str] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)
    start: str | None = None  # ISO format datetime string
    end: str | None = None
    relax_thresholds: bool = True


class PolicyConfig(BaseModel):
    """Top-level policy configuration — validated against the YAML file.

    Extra fields are forbidden. Invalid policy fails loudly.
    """

    model_config = ConfigDict(extra="forbid")

    version: str
    action_tiers: dict[RiskTier, ActionTierConfig]
    confidence_thresholds: ConfidenceThresholds
    eas_modulation: EASModulation
    scope_limits: ScopeLimits
    default_tier_for_unknown: RiskTier = RiskTier.TIER_3_MEDIUM_RISK_WRITE
    hard_rules: HardRules

    # Phase 6 — optional context-aware rules (defaults allow old YAML to load)
    site_rules: list[SiteRule] = Field(default_factory=list)
    role_rules: list[RoleRule] = Field(default_factory=list)
    tag_rules: list[TagRule] = Field(default_factory=list)
    maintenance_windows: list[MaintenanceWindowConfig] = Field(default_factory=list)

    @field_validator("action_tiers")
    @classmethod
    def all_tiers_present(cls, v: dict[RiskTier, ActionTierConfig]) -> dict[RiskTier, ActionTierConfig]:
        """Ensure all five risk tiers are defined in the policy."""
        missing = set(RiskTier) - set(v.keys())
        if missing:
            missing_names = ", ".join(t.value for t in sorted(missing, key=lambda t: t.value))
            raise ValueError(f"Policy must define all 5 risk tiers. Missing: {missing_names}")
        return v


# --- Evaluation models (engine interface) ---


class EvaluationRequest(BaseModel):
    """Input to the Policy Engine evaluate() method."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1)
    parameters: dict[str, object] = Field(default_factory=dict)
    device_targets: list[str] = Field(default_factory=list)
    confidence_score: float = Field(ge=0.0, le=1.0)
    context: dict[str, object] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def tool_name_stripped(cls, v: str) -> str:
        """Strip whitespace from tool name."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("tool_name must be a non-empty string")
        return stripped

    @field_validator("device_targets")
    @classmethod
    def device_targets_non_empty_entries(cls, v: list[str]) -> list[str]:
        """Ensure device target names are non-empty when provided."""
        cleaned = [d.strip() for d in v]
        if any(not d for d in cleaned):
            raise ValueError("Device target names must be non-empty strings")
        return cleaned


class EvaluationResult(BaseModel):
    """Output from the Policy Engine evaluate() method."""

    verdict: Verdict
    risk_tier: RiskTier
    tool_name: str
    reason: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_threshold: float = Field(ge=0.0, le=1.0)
    device_count: int = Field(ge=0)
    requires_audit: bool = False
    requires_senior_approval: bool = False
    escalation_id: UUID | None = None

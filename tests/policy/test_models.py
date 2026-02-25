"""Tests for sna.policy.models — Pydantic policy schema validation.

Covers:
- Enum values and serialization
- Valid policy YAML parsing
- Validation rejection of invalid inputs
- Evaluation request/result models
- Edge cases: boundary values, missing fields, extra fields
"""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    EASModulation,
    EvaluationRequest,
    EvaluationResult,
    HardRules,
    PolicyConfig,
    RiskTier,
    ScopeLimits,
    Verdict,
)


# --- Enum tests ---


class TestVerdict:
    def test_values(self):
        assert Verdict.PERMIT == "PERMIT"
        assert Verdict.ESCALATE == "ESCALATE"
        assert Verdict.BLOCK == "BLOCK"

    def test_all_values_present(self):
        assert len(Verdict) == 3


class TestRiskTier:
    def test_values(self):
        assert RiskTier.TIER_1_READ == "tier_1_read"
        assert RiskTier.TIER_5_CRITICAL == "tier_5_critical"

    def test_all_tiers_present(self):
        assert len(RiskTier) == 5

    def test_ordering_by_value(self):
        tiers = sorted(RiskTier, key=lambda t: t.value)
        assert tiers[0] == RiskTier.TIER_1_READ
        assert tiers[-1] == RiskTier.TIER_5_CRITICAL


# --- ActionTierConfig tests ---


class TestActionTierConfig:
    def test_valid_minimal(self):
        config = ActionTierConfig(
            description="Test tier",
            default_verdict=Verdict.PERMIT,
        )
        assert config.requires_audit is False
        assert config.requires_senior_approval is False
        assert config.examples == []

    def test_valid_full(self):
        config = ActionTierConfig(
            description="Read operations",
            default_verdict=Verdict.PERMIT,
            requires_audit=True,
            requires_senior_approval=True,
            examples=["show_running_config", "show_interfaces"],
        )
        assert len(config.examples) == 2
        assert config.requires_audit is True

    def test_examples_stripped(self):
        config = ActionTierConfig(
            description="Test",
            default_verdict=Verdict.PERMIT,
            examples=["  show_config  ", "show_ip  "],
        )
        assert config.examples == ["show_config", "show_ip"]

    def test_empty_example_rejected(self):
        with pytest.raises(ValidationError, match="non-empty"):
            ActionTierConfig(
                description="Test",
                default_verdict=Verdict.PERMIT,
                examples=["valid", ""],
            )

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            ActionTierConfig(
                description="Test",
                default_verdict=Verdict.PERMIT,
                unknown_field="bad",  # type: ignore[call-arg]
            )

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValidationError):
            ActionTierConfig(
                description="Test",
                default_verdict="ALLOW",  # type: ignore[arg-type]
            )


# --- ConfidenceThresholds tests ---


class TestConfidenceThresholds:
    def test_valid(self):
        ct = ConfidenceThresholds(
            tier_1_read=0.1,
            tier_2_low_risk_write=0.3,
            tier_3_medium_risk_write=0.6,
            tier_4_high_risk_write=0.8,
            tier_5_critical=1.0,
        )
        assert ct.tier_1_read == 0.1
        assert ct.tier_5_critical == 1.0

    def test_get_threshold(self):
        ct = ConfidenceThresholds(
            tier_1_read=0.1,
            tier_2_low_risk_write=0.3,
            tier_3_medium_risk_write=0.6,
            tier_4_high_risk_write=0.8,
            tier_5_critical=1.0,
        )
        assert ct.get_threshold(RiskTier.TIER_1_READ) == 0.1
        assert ct.get_threshold(RiskTier.TIER_5_CRITICAL) == 1.0

    def test_boundary_zero(self):
        ct = ConfidenceThresholds(
            tier_1_read=0.0,
            tier_2_low_risk_write=0.0,
            tier_3_medium_risk_write=0.0,
            tier_4_high_risk_write=0.0,
            tier_5_critical=0.0,
        )
        assert ct.tier_1_read == 0.0

    def test_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            ConfidenceThresholds(
                tier_1_read=-0.1,
                tier_2_low_risk_write=0.3,
                tier_3_medium_risk_write=0.6,
                tier_4_high_risk_write=0.8,
                tier_5_critical=1.0,
            )

    def test_above_one_rejected(self):
        with pytest.raises(ValidationError):
            ConfidenceThresholds(
                tier_1_read=0.1,
                tier_2_low_risk_write=0.3,
                tier_3_medium_risk_write=0.6,
                tier_4_high_risk_write=0.8,
                tier_5_critical=1.1,
            )


# --- EASModulation tests ---


class TestEASModulation:
    def test_valid(self):
        eas = EASModulation(
            enabled=True,
            max_threshold_reduction=0.1,
            min_eas_for_modulation=0.3,
        )
        assert eas.enabled is True

    def test_disabled(self):
        eas = EASModulation(
            enabled=False,
            max_threshold_reduction=0.0,
            min_eas_for_modulation=0.0,
        )
        assert eas.enabled is False

    def test_reduction_above_half_rejected(self):
        with pytest.raises(ValidationError):
            EASModulation(
                enabled=True,
                max_threshold_reduction=0.6,
                min_eas_for_modulation=0.3,
            )


# --- ScopeLimits tests ---


class TestScopeLimits:
    def test_valid(self):
        sl = ScopeLimits(max_devices_per_action=3, escalate_above=3)
        assert sl.max_devices_per_action == 3

    def test_zero_devices_rejected(self):
        with pytest.raises(ValidationError):
            ScopeLimits(max_devices_per_action=0, escalate_above=3)

    def test_negative_rejected(self):
        with pytest.raises(ValidationError):
            ScopeLimits(max_devices_per_action=-1, escalate_above=3)


# --- HardRules tests ---


class TestHardRules:
    def test_valid(self):
        hr = HardRules(
            always_block=["write_erase", "factory_reset"],
            description="Critical actions",
        )
        assert len(hr.always_block) == 2

    def test_empty_list_valid(self):
        hr = HardRules(always_block=[], description="No hard blocks")
        assert hr.always_block == []

    def test_entries_stripped(self):
        hr = HardRules(always_block=["  write_erase  "])
        assert hr.always_block == ["write_erase"]

    def test_empty_entry_rejected(self):
        with pytest.raises(ValidationError, match="non-empty"):
            HardRules(always_block=["write_erase", ""])


# --- PolicyConfig tests ---


@pytest.fixture
def valid_policy_dict() -> dict:
    """A valid policy configuration as a dictionary (mirrors default.yaml)."""
    return {
        "version": "1.0",
        "action_tiers": {
            "tier_1_read": {
                "description": "Show commands",
                "default_verdict": "PERMIT",
                "examples": ["show_running_config"],
            },
            "tier_2_low_risk_write": {
                "description": "Low risk writes",
                "default_verdict": "PERMIT",
                "requires_audit": True,
                "examples": ["set_interface_description"],
            },
            "tier_3_medium_risk_write": {
                "description": "Medium risk writes",
                "default_verdict": "ESCALATE",
                "examples": ["configure_static_route"],
            },
            "tier_4_high_risk_write": {
                "description": "High risk writes",
                "default_verdict": "ESCALATE",
                "requires_senior_approval": True,
                "examples": ["configure_bgp_neighbor"],
            },
            "tier_5_critical": {
                "description": "Critical actions",
                "default_verdict": "BLOCK",
                "examples": ["write_erase"],
            },
        },
        "confidence_thresholds": {
            "tier_1_read": 0.1,
            "tier_2_low_risk_write": 0.3,
            "tier_3_medium_risk_write": 0.6,
            "tier_4_high_risk_write": 0.8,
            "tier_5_critical": 1.0,
        },
        "eas_modulation": {
            "enabled": True,
            "max_threshold_reduction": 0.1,
            "min_eas_for_modulation": 0.3,
        },
        "scope_limits": {
            "max_devices_per_action": 3,
            "escalate_above": 3,
        },
        "default_tier_for_unknown": "tier_3_medium_risk_write",
        "hard_rules": {
            "always_block": ["write_erase", "factory_reset"],
            "description": "Always blocked",
        },
    }


class TestPolicyConfig:
    def test_valid_policy(self, valid_policy_dict):
        policy = PolicyConfig(**valid_policy_dict)
        assert policy.version == "1.0"
        assert len(policy.action_tiers) == 5

    def test_missing_tier_rejected(self, valid_policy_dict):
        del valid_policy_dict["action_tiers"]["tier_5_critical"]
        with pytest.raises(ValidationError, match="Missing"):
            PolicyConfig(**valid_policy_dict)

    def test_extra_field_rejected(self, valid_policy_dict):
        valid_policy_dict["unexpected_key"] = "bad"
        with pytest.raises(ValidationError):
            PolicyConfig(**valid_policy_dict)

    def test_default_tier_for_unknown(self, valid_policy_dict):
        policy = PolicyConfig(**valid_policy_dict)
        assert policy.default_tier_for_unknown == RiskTier.TIER_3_MEDIUM_RISK_WRITE

    def test_invalid_default_tier_rejected(self, valid_policy_dict):
        valid_policy_dict["default_tier_for_unknown"] = "tier_99_nonexistent"
        with pytest.raises(ValidationError):
            PolicyConfig(**valid_policy_dict)

    def test_hard_rules_present(self, valid_policy_dict):
        policy = PolicyConfig(**valid_policy_dict)
        assert "write_erase" in policy.hard_rules.always_block


# --- EvaluationRequest tests ---


class TestEvaluationRequest:
    def test_valid_minimal(self):
        req = EvaluationRequest(
            tool_name="show_interfaces",
            confidence_score=0.9,
        )
        assert req.parameters == {}
        assert req.device_targets == []

    def test_valid_full(self):
        req = EvaluationRequest(
            tool_name="configure_bgp_neighbor",
            parameters={"neighbor": "10.0.0.1", "as_number": 65001},
            device_targets=["router1", "router2"],
            confidence_score=0.85,
            context={"session_id": "abc123"},
        )
        assert len(req.device_targets) == 2

    def test_tool_name_stripped(self):
        req = EvaluationRequest(
            tool_name="  show_config  ",
            confidence_score=0.5,
        )
        assert req.tool_name == "show_config"

    def test_empty_tool_name_rejected(self):
        with pytest.raises(ValidationError):
            EvaluationRequest(tool_name="", confidence_score=0.5)

    def test_whitespace_tool_name_rejected(self):
        with pytest.raises(ValidationError):
            EvaluationRequest(tool_name="   ", confidence_score=0.5)

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            EvaluationRequest(tool_name="test", confidence_score=-0.1)

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            EvaluationRequest(tool_name="test", confidence_score=1.1)

    def test_confidence_boundary_zero(self):
        req = EvaluationRequest(tool_name="test", confidence_score=0.0)
        assert req.confidence_score == 0.0

    def test_confidence_boundary_one(self):
        req = EvaluationRequest(tool_name="test", confidence_score=1.0)
        assert req.confidence_score == 1.0

    def test_empty_device_target_rejected(self):
        with pytest.raises(ValidationError, match="non-empty"):
            EvaluationRequest(
                tool_name="test",
                confidence_score=0.5,
                device_targets=["router1", ""],
            )

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            EvaluationRequest(
                tool_name="test",
                confidence_score=0.5,
                bad_field="nope",  # type: ignore[call-arg]
            )


# --- EvaluationResult tests ---


class TestEvaluationResult:
    def test_permit_result(self):
        result = EvaluationResult(
            verdict=Verdict.PERMIT,
            risk_tier=RiskTier.TIER_1_READ,
            tool_name="show_interfaces",
            reason="Tier 1 read action — confidence above threshold",
            confidence_score=0.9,
            confidence_threshold=0.1,
            device_count=1,
        )
        assert result.escalation_id is None
        assert result.requires_senior_approval is False

    def test_escalate_result_with_id(self):
        esc_id = uuid4()
        result = EvaluationResult(
            verdict=Verdict.ESCALATE,
            risk_tier=RiskTier.TIER_4_HIGH_RISK_WRITE,
            tool_name="configure_bgp_neighbor",
            reason="High risk write requires approval",
            confidence_score=0.85,
            confidence_threshold=0.8,
            device_count=2,
            requires_senior_approval=True,
            escalation_id=esc_id,
        )
        assert result.escalation_id == esc_id
        assert result.requires_senior_approval is True

    def test_block_result(self):
        result = EvaluationResult(
            verdict=Verdict.BLOCK,
            risk_tier=RiskTier.TIER_5_CRITICAL,
            tool_name="write_erase",
            reason="Hard-blocked action",
            confidence_score=1.0,
            confidence_threshold=1.0,
            device_count=1,
        )
        assert result.verdict == Verdict.BLOCK

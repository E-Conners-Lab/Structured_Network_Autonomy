"""Tests for dynamic confidence adjustment — C27.

Covers:
- compute_history_factor
- Criticality raises threshold
- History lowers threshold
- Clamping to [0.0, 1.0]
- Backward compat (no new args = same result)
- Edge cases
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sna.policy.confidence import compute_history_factor
from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    DynamicConfidenceConfig,
    EASModulation,
    HardRules,
    PolicyConfig,
    RiskTier,
    ScopeLimits,
    Verdict,
)
from sna.policy.taxonomy import get_effective_threshold


@pytest.fixture
def base_policy() -> PolicyConfig:
    """Policy with dynamic confidence enabled."""
    return PolicyConfig(
        version="1.0",
        action_tiers={
            RiskTier.TIER_1_READ: ActionTierConfig(
                description="Read ops", default_verdict=Verdict.PERMIT,
                examples=["show_running_config"],
            ),
            RiskTier.TIER_2_LOW_RISK_WRITE: ActionTierConfig(
                description="Low risk", default_verdict=Verdict.PERMIT,
                examples=["set_interface_description"],
            ),
            RiskTier.TIER_3_MEDIUM_RISK_WRITE: ActionTierConfig(
                description="Med risk", default_verdict=Verdict.ESCALATE,
                examples=["configure_vlan"],
            ),
            RiskTier.TIER_4_HIGH_RISK_WRITE: ActionTierConfig(
                description="High risk", default_verdict=Verdict.ESCALATE,
                examples=["configure_bgp_neighbor"],
            ),
            RiskTier.TIER_5_CRITICAL: ActionTierConfig(
                description="Critical", default_verdict=Verdict.BLOCK,
                examples=["reload_device"],
            ),
        },
        confidence_thresholds=ConfidenceThresholds(
            tier_1_read=0.1, tier_2_low_risk_write=0.3,
            tier_3_medium_risk_write=0.6, tier_4_high_risk_write=0.8,
            tier_5_critical=1.0,
        ),
        eas_modulation=EASModulation(
            enabled=True, max_threshold_reduction=0.1, min_eas_for_modulation=0.3,
        ),
        scope_limits=ScopeLimits(max_devices_per_action=3, escalate_above=3),
        hard_rules=HardRules(always_block=[]),
        dynamic_confidence=DynamicConfidenceConfig(
            max_criticality_increase=0.2,
            max_history_bonus=0.15,
            history_window_days=30,
        ),
    )


class TestComputeHistoryFactor:
    def test_empty_history(self) -> None:
        assert compute_history_factor([], window_days=30) == 0.0

    def test_all_permits(self) -> None:
        now = datetime.now(UTC)
        verdicts = [("PERMIT", now - timedelta(hours=i)) for i in range(10)]
        assert compute_history_factor(verdicts, window_days=30, now=now) == 1.0

    def test_all_blocks(self) -> None:
        now = datetime.now(UTC)
        verdicts = [("BLOCK", now - timedelta(hours=i)) for i in range(10)]
        assert compute_history_factor(verdicts, window_days=30, now=now) == 0.0

    def test_mixed_verdicts(self) -> None:
        now = datetime.now(UTC)
        verdicts = [
            ("PERMIT", now - timedelta(hours=1)),
            ("PERMIT", now - timedelta(hours=2)),
            ("BLOCK", now - timedelta(hours=3)),
            ("ESCALATE", now - timedelta(hours=4)),
        ]
        factor = compute_history_factor(verdicts, window_days=30, now=now)
        assert factor == pytest.approx(0.5)  # 2 PERMIT / 4 total

    def test_outside_window_excluded(self) -> None:
        now = datetime.now(UTC)
        verdicts = [
            ("PERMIT", now - timedelta(hours=1)),
            ("BLOCK", now - timedelta(days=40)),  # Outside 30-day window
        ]
        factor = compute_history_factor(verdicts, window_days=30, now=now)
        assert factor == 1.0  # Only the PERMIT is in window


class TestGetEffectiveThresholdDynamic:
    def test_backward_compat_no_args(self, base_policy) -> None:
        """Without device_criticality/history_factor, behaves like before."""
        # EAS = 0.5, enabled, above min_eas (0.3)
        # base=0.6, reduction = 0.1 * 0.5 = 0.05, effective = 0.55
        result = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
        )
        assert result == pytest.approx(0.55)

    def test_backward_compat_explicit_zero(self, base_policy) -> None:
        result_default = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
        )
        result_explicit = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
            device_criticality=0.0, history_factor=0.0,
        )
        assert result_default == result_explicit

    def test_criticality_raises_threshold(self, base_policy) -> None:
        """Higher device_criticality raises the effective threshold."""
        base = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
        )
        raised = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
            device_criticality=1.0,
        )
        assert raised > base
        # criticality_increase = 1.0 * 0.2 = 0.2
        assert raised == pytest.approx(base + 0.2)

    def test_history_lowers_threshold(self, base_policy) -> None:
        """Higher history_factor lowers the effective threshold."""
        base = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
        )
        lowered = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
            history_factor=1.0,
        )
        assert lowered < base
        # history_bonus = 1.0 * 0.15 = 0.15
        assert lowered == pytest.approx(base - 0.15)

    def test_both_adjustments(self, base_policy) -> None:
        """Criticality and history can be used together."""
        # base=0.6, eas_reduction=0.05, crit_increase=0.1, history_bonus=0.075
        result = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, base_policy, 0.5,
            device_criticality=0.5, history_factor=0.5,
        )
        expected = 0.6 - 0.05 + 0.1 - 0.075
        assert result == pytest.approx(expected)

    def test_clamped_at_zero(self, base_policy) -> None:
        """Threshold cannot go below 0.0."""
        result = get_effective_threshold(
            RiskTier.TIER_1_READ, base_policy, 0.5,
            history_factor=1.0,
        )
        assert result >= 0.0

    def test_clamped_at_one(self, base_policy) -> None:
        """Threshold cannot go above 1.0."""
        result = get_effective_threshold(
            RiskTier.TIER_5_CRITICAL, base_policy, 0.0,
            device_criticality=1.0,
        )
        assert result <= 1.0

    def test_no_dynamic_config_defaults(self) -> None:
        """Policy without dynamic_confidence uses defaults (all 0.0)."""
        policy = PolicyConfig(
            version="1.0",
            action_tiers={
                RiskTier.TIER_1_READ: ActionTierConfig(description="r", default_verdict=Verdict.PERMIT, examples=["ping"]),
                RiskTier.TIER_2_LOW_RISK_WRITE: ActionTierConfig(description="w", default_verdict=Verdict.PERMIT, examples=["set_desc"]),
                RiskTier.TIER_3_MEDIUM_RISK_WRITE: ActionTierConfig(description="m", default_verdict=Verdict.ESCALATE, examples=["configure_vlan"]),
                RiskTier.TIER_4_HIGH_RISK_WRITE: ActionTierConfig(description="h", default_verdict=Verdict.ESCALATE, examples=["configure_bgp"]),
                RiskTier.TIER_5_CRITICAL: ActionTierConfig(description="c", default_verdict=Verdict.BLOCK, examples=["reload"]),
            },
            confidence_thresholds=ConfidenceThresholds(
                tier_1_read=0.1, tier_2_low_risk_write=0.3, tier_3_medium_risk_write=0.6,
                tier_4_high_risk_write=0.8, tier_5_critical=1.0,
            ),
            eas_modulation=EASModulation(enabled=False, max_threshold_reduction=0.0, min_eas_for_modulation=0.0),
            scope_limits=ScopeLimits(max_devices_per_action=3, escalate_above=3),
            hard_rules=HardRules(always_block=[]),
        )
        # No dynamic_confidence → defaults to all 0.0 → criticality/history have no effect
        result = get_effective_threshold(
            RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy, 0.5,
            device_criticality=1.0, history_factor=1.0,
        )
        assert result == 0.6  # Just the base threshold

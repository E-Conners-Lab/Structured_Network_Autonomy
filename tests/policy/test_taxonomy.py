"""Tests for sna.policy.taxonomy — tool classification, thresholds, hard rules, scope.

Covers:
- Tool classification: known tools, unknown tools, case insensitivity
- Effective threshold computation with and without EAS modulation
- Hard block checks
- Scope escalation checks
"""

import pytest

from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    EASModulation,
    HardRules,
    PolicyConfig,
    RiskTier,
    ScopeLimits,
    Verdict,
)
from sna.policy.taxonomy import (
    check_scope_escalation,
    classify_tool,
    get_effective_threshold,
    is_hard_blocked,
)


@pytest.fixture
def policy() -> PolicyConfig:
    """A standard test policy."""
    return PolicyConfig(
        version="1.0",
        action_tiers={
            RiskTier.TIER_1_READ: ActionTierConfig(
                description="Read ops",
                default_verdict=Verdict.PERMIT,
                examples=["show_running_config", "show_interfaces", "ping"],
            ),
            RiskTier.TIER_2_LOW_RISK_WRITE: ActionTierConfig(
                description="Low risk",
                default_verdict=Verdict.PERMIT,
                requires_audit=True,
                examples=["set_interface_description"],
            ),
            RiskTier.TIER_3_MEDIUM_RISK_WRITE: ActionTierConfig(
                description="Medium risk",
                default_verdict=Verdict.ESCALATE,
                examples=["configure_static_route", "configure_vlan"],
            ),
            RiskTier.TIER_4_HIGH_RISK_WRITE: ActionTierConfig(
                description="High risk",
                default_verdict=Verdict.ESCALATE,
                requires_senior_approval=True,
                examples=["configure_bgp_neighbor"],
            ),
            RiskTier.TIER_5_CRITICAL: ActionTierConfig(
                description="Critical",
                default_verdict=Verdict.BLOCK,
                examples=["write_erase", "reload_device"],
            ),
        },
        confidence_thresholds=ConfidenceThresholds(
            tier_1_read=0.1,
            tier_2_low_risk_write=0.3,
            tier_3_medium_risk_write=0.6,
            tier_4_high_risk_write=0.8,
            tier_5_critical=1.0,
        ),
        eas_modulation=EASModulation(
            enabled=True,
            max_threshold_reduction=0.1,
            min_eas_for_modulation=0.3,
        ),
        scope_limits=ScopeLimits(
            max_devices_per_action=3,
            escalate_above=3,
        ),
        default_tier_for_unknown=RiskTier.TIER_3_MEDIUM_RISK_WRITE,
        hard_rules=HardRules(
            always_block=["write_erase", "factory_reset", "delete_startup_config"],
            description="Always blocked",
        ),
    )


# --- classify_tool tests ---


class TestClassifyTool:
    def test_known_tier_1(self, policy):
        assert classify_tool("show_running_config", policy) == RiskTier.TIER_1_READ

    def test_known_tier_2(self, policy):
        assert classify_tool("set_interface_description", policy) == RiskTier.TIER_2_LOW_RISK_WRITE

    def test_known_tier_3(self, policy):
        assert classify_tool("configure_static_route", policy) == RiskTier.TIER_3_MEDIUM_RISK_WRITE

    def test_known_tier_4(self, policy):
        assert classify_tool("configure_bgp_neighbor", policy) == RiskTier.TIER_4_HIGH_RISK_WRITE

    def test_known_tier_5(self, policy):
        assert classify_tool("write_erase", policy) == RiskTier.TIER_5_CRITICAL

    def test_unknown_tool_defaults(self, policy):
        assert classify_tool("completely_unknown_tool", policy) == RiskTier.TIER_3_MEDIUM_RISK_WRITE

    def test_case_insensitive(self, policy):
        assert classify_tool("SHOW_RUNNING_CONFIG", policy) == RiskTier.TIER_1_READ
        assert classify_tool("Show_Interfaces", policy) == RiskTier.TIER_1_READ

    def test_whitespace_stripped(self, policy):
        assert classify_tool("  show_running_config  ", policy) == RiskTier.TIER_1_READ

    def test_each_tier_has_at_least_one_match(self, policy):
        """Every tier in the test policy should have at least one classifiable tool."""
        for tier, config in policy.action_tiers.items():
            if config.examples:
                result = classify_tool(config.examples[0], policy)
                assert result == tier


# --- get_effective_threshold tests ---


class TestGetEffectiveThreshold:
    def test_base_threshold_when_modulation_disabled(self, policy):
        policy.eas_modulation.enabled = False
        threshold = get_effective_threshold(RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy, 0.9)
        assert threshold == 0.6

    def test_base_threshold_when_eas_below_minimum(self, policy):
        threshold = get_effective_threshold(RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy, 0.1)
        assert threshold == 0.6

    def test_modulated_threshold_at_eas_boundary(self, policy):
        # EAS = 0.3 (exactly at min_eas_for_modulation)
        # reduction = 0.1 * 0.3 = 0.03
        # effective = 0.6 - 0.03 = 0.57
        threshold = get_effective_threshold(RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy, 0.3)
        assert threshold == pytest.approx(0.57)

    def test_modulated_threshold_high_eas(self, policy):
        # EAS = 1.0
        # reduction = 0.1 * 1.0 = 0.1
        # effective = 0.6 - 0.1 = 0.5
        threshold = get_effective_threshold(RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy, 1.0)
        assert threshold == pytest.approx(0.5)

    def test_modulated_threshold_tier_1(self, policy):
        # base = 0.1, EAS = 1.0, reduction = 0.1
        # effective = 0.1 - 0.1 = 0.0 (clamped to 0.0)
        threshold = get_effective_threshold(RiskTier.TIER_1_READ, policy, 1.0)
        assert threshold == pytest.approx(0.0)

    def test_threshold_never_negative(self, policy):
        threshold = get_effective_threshold(RiskTier.TIER_1_READ, policy, 1.0)
        assert threshold >= 0.0

    def test_threshold_never_above_one(self, policy):
        for tier in RiskTier:
            threshold = get_effective_threshold(tier, policy, 0.0)
            assert 0.0 <= threshold <= 1.0

    def test_all_tiers_base_values(self, policy):
        # EAS = 0.0, below min_eas_for_modulation — no reduction
        expected = {
            RiskTier.TIER_1_READ: 0.1,
            RiskTier.TIER_2_LOW_RISK_WRITE: 0.3,
            RiskTier.TIER_3_MEDIUM_RISK_WRITE: 0.6,
            RiskTier.TIER_4_HIGH_RISK_WRITE: 0.8,
            RiskTier.TIER_5_CRITICAL: 1.0,
        }
        for tier, expected_val in expected.items():
            assert get_effective_threshold(tier, policy, 0.0) == expected_val


# --- is_hard_blocked tests ---


class TestIsHardBlocked:
    def test_blocked_tool(self, policy):
        assert is_hard_blocked("write_erase", policy) is True

    def test_blocked_tool_case_insensitive(self, policy):
        assert is_hard_blocked("FACTORY_RESET", policy) is True

    def test_blocked_tool_whitespace(self, policy):
        assert is_hard_blocked("  delete_startup_config  ", policy) is True

    def test_non_blocked_tool(self, policy):
        assert is_hard_blocked("show_running_config", policy) is False

    def test_unknown_tool_not_blocked(self, policy):
        assert is_hard_blocked("some_random_tool", policy) is False


# --- check_scope_escalation tests ---


class TestCheckScopeEscalation:
    def test_within_limit(self, policy):
        assert check_scope_escalation(1, policy) is False
        assert check_scope_escalation(3, policy) is False

    def test_at_boundary(self, policy):
        # escalate_above = 3, so 3 devices is NOT over the limit
        assert check_scope_escalation(3, policy) is False

    def test_above_limit(self, policy):
        assert check_scope_escalation(4, policy) is True
        assert check_scope_escalation(10, policy) is True

    def test_zero_devices(self, policy):
        assert check_scope_escalation(0, policy) is False

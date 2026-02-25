"""Tests for context-aware policy rules (site, role, tag rules) and YAML backward compatibility.

Covers:
- Site/role/tag matching
- Priority resolution (tag > role > site)
- applies_to filtering
- Fail-closed on malformed context
- Engine integration (end-to-end with audit verification)
- Backward compat (empty context = unchanged behavior)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.policy.context_rules import (
    MatchedRule,
    evaluate_context_rules,
    evaluate_role_rules,
    evaluate_site_rules,
    evaluate_tag_rules,
    resolve_context_verdict,
)
from sna.policy.engine import PolicyEngine
from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    EASModulation,
    EvaluationRequest,
    HardRules,
    MaintenanceWindowConfig,
    PolicyConfig,
    RiskTier,
    RoleRule,
    ScopeLimits,
    SiteRule,
    TagRule,
    Verdict,
)


# --- Fixtures ---


@pytest.fixture
def policy_with_context_rules() -> PolicyConfig:
    """Policy with site, role, and tag rules for context testing."""
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
                examples=["reload_device"],
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
        scope_limits=ScopeLimits(max_devices_per_action=3, escalate_above=3),
        default_tier_for_unknown=RiskTier.TIER_3_MEDIUM_RISK_WRITE,
        hard_rules=HardRules(
            always_block=["write_erase", "factory_reset"],
            description="Always blocked",
        ),
        site_rules=[
            SiteRule(site="production", verdict=Verdict.BLOCK, applies_to="write", reason="No writes to production"),
            SiteRule(site="staging", verdict=Verdict.ESCALATE, applies_to="all", reason="Staging requires review"),
        ],
        role_rules=[
            RoleRule(role="core-router", verdict=Verdict.ESCALATE, applies_to="all", reason="Core router needs review"),
            RoleRule(role="access-switch", verdict=Verdict.PERMIT, applies_to="write", reason="Access switch OK"),
        ],
        tag_rules=[
            TagRule(tag="critical", verdict=Verdict.BLOCK, applies_to="write", reason="Critical devices blocked for writes"),
            TagRule(tag="monitored", verdict=Verdict.ESCALATE, applies_to="all", reason="Monitored device escalation"),
        ],
    )


@pytest.fixture
def session_factory(async_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(async_engine, expire_on_commit=False)


@pytest.fixture
def engine_with_context(policy_with_context_rules, session_factory) -> PolicyEngine:
    return PolicyEngine(
        policy=policy_with_context_rules,
        session_factory=session_factory,
        initial_eas=0.5,
    )


# --- Backward Compatibility ---


class TestBackwardCompatibility:
    """Old YAML without Phase 6 fields still validates."""

    def test_old_yaml_loads(self, sample_policy_path: Path) -> None:
        with open(sample_policy_path) as f:
            data = yaml.safe_load(f)
        policy = PolicyConfig(**data)
        assert policy.site_rules == []
        assert policy.role_rules == []
        assert policy.tag_rules == []
        assert policy.maintenance_windows == []

    def test_yaml_with_new_fields(self, sample_policy_path: Path) -> None:
        with open(sample_policy_path) as f:
            data = yaml.safe_load(f)
        data["site_rules"] = [
            {"site": "production", "verdict": "BLOCK", "applies_to": "write", "reason": "No writes"},
        ]
        data["role_rules"] = [
            {"role": "core-router", "verdict": "ESCALATE", "applies_to": "all", "reason": "Core review"},
        ]
        data["tag_rules"] = [
            {"tag": "production-core", "verdict": "BLOCK", "applies_to": "write", "reason": "Tagged"},
        ]
        data["maintenance_windows"] = [
            {"name": "weekly", "sites": ["hq"], "devices": [], "start": "2026-02-24T00:00:00Z", "end": "2026-02-24T06:00:00Z"},
        ]
        policy = PolicyConfig(**data)
        assert len(policy.site_rules) == 1
        assert policy.site_rules[0].verdict == Verdict.BLOCK
        assert len(policy.role_rules) == 1
        assert len(policy.tag_rules) == 1
        assert len(policy.maintenance_windows) == 1


# --- Site Rule Matching ---


class TestSiteRules:
    def test_site_match_blocks_writes(self) -> None:
        rules = [SiteRule(site="production", verdict=Verdict.BLOCK, applies_to="write", reason="No writes")]
        matches = evaluate_site_rules("production", "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 1
        assert matches[0].verdict == Verdict.BLOCK

    def test_site_match_case_insensitive(self) -> None:
        rules = [SiteRule(site="Production", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_site_rules("PRODUCTION", "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 1

    def test_site_no_match(self) -> None:
        rules = [SiteRule(site="production", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_site_rules("staging", "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 0

    def test_site_write_rule_skips_reads(self) -> None:
        rules = [SiteRule(site="production", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_site_rules("production", "show_running_config", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 0

    def test_site_all_applies_to_reads(self) -> None:
        rules = [SiteRule(site="staging", verdict=Verdict.ESCALATE, applies_to="all")]
        matches = evaluate_site_rules("staging", "show_running_config", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 1

    def test_site_applies_to_specific_tool(self) -> None:
        rules = [SiteRule(site="production", verdict=Verdict.BLOCK, applies_to="configure_vlan")]
        matches = evaluate_site_rules("production", "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 1
        matches2 = evaluate_site_rules("production", "configure_bgp", RiskTier.TIER_4_HIGH_RISK_WRITE, rules)
        assert len(matches2) == 0


# --- Role Rule Matching ---


class TestRoleRules:
    def test_role_match(self) -> None:
        rules = [RoleRule(role="core-router", verdict=Verdict.ESCALATE, applies_to="all")]
        matches = evaluate_role_rules("core-router", "show_running_config", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 1
        assert matches[0].verdict == Verdict.ESCALATE

    def test_role_case_insensitive(self) -> None:
        rules = [RoleRule(role="Core-Router", verdict=Verdict.ESCALATE, applies_to="all")]
        matches = evaluate_role_rules("core-router", "ping", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 1

    def test_role_no_match(self) -> None:
        rules = [RoleRule(role="core-router", verdict=Verdict.ESCALATE, applies_to="all")]
        matches = evaluate_role_rules("access-switch", "ping", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 0


# --- Tag Rule Matching ---


class TestTagRules:
    def test_tag_match(self) -> None:
        rules = [TagRule(tag="critical", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_tag_rules(["critical", "monitored"], "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 1
        assert matches[0].verdict == Verdict.BLOCK

    def test_tag_case_insensitive(self) -> None:
        rules = [TagRule(tag="Critical", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_tag_rules(["CRITICAL"], "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 1

    def test_multiple_tag_matches(self) -> None:
        rules = [
            TagRule(tag="critical", verdict=Verdict.BLOCK, applies_to="write"),
            TagRule(tag="monitored", verdict=Verdict.ESCALATE, applies_to="all"),
        ]
        matches = evaluate_tag_rules(["critical", "monitored"], "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 2

    def test_tag_no_match(self) -> None:
        rules = [TagRule(tag="critical", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_tag_rules(["normal"], "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, rules)
        assert len(matches) == 0

    def test_tag_write_rule_skips_reads(self) -> None:
        rules = [TagRule(tag="critical", verdict=Verdict.BLOCK, applies_to="write")]
        matches = evaluate_tag_rules(["critical"], "show_running_config", RiskTier.TIER_1_READ, rules)
        assert len(matches) == 0


# --- Priority Resolution ---


class TestResolveContextVerdict:
    def test_empty_matches(self) -> None:
        verdict, reason = resolve_context_verdict([])
        assert verdict is None
        assert reason == ""

    def test_single_match(self) -> None:
        matches = [MatchedRule(rule_type="site", match_value="prod", verdict=Verdict.BLOCK, reason="blocked", priority=0)]
        verdict, reason = resolve_context_verdict(matches)
        assert verdict == Verdict.BLOCK
        assert reason == "blocked"

    def test_tag_overrides_site(self) -> None:
        matches = [
            MatchedRule(rule_type="site", match_value="prod", verdict=Verdict.BLOCK, reason="site block", priority=0),
            MatchedRule(rule_type="tag", match_value="ok", verdict=Verdict.ESCALATE, reason="tag escalate", priority=2),
        ]
        verdict, reason = resolve_context_verdict(matches)
        # Tag has higher priority
        assert verdict == Verdict.ESCALATE
        assert reason == "tag escalate"

    def test_tag_overrides_role(self) -> None:
        matches = [
            MatchedRule(rule_type="role", match_value="core", verdict=Verdict.PERMIT, reason="role permit", priority=1),
            MatchedRule(rule_type="tag", match_value="crit", verdict=Verdict.BLOCK, reason="tag block", priority=2),
        ]
        verdict, reason = resolve_context_verdict(matches)
        assert verdict == Verdict.BLOCK

    def test_role_overrides_site(self) -> None:
        matches = [
            MatchedRule(rule_type="site", match_value="prod", verdict=Verdict.BLOCK, reason="site block", priority=0),
            MatchedRule(rule_type="role", match_value="core", verdict=Verdict.ESCALATE, reason="role escalate", priority=1),
        ]
        verdict, reason = resolve_context_verdict(matches)
        assert verdict == Verdict.ESCALATE

    def test_same_priority_most_restrictive_wins(self) -> None:
        matches = [
            MatchedRule(rule_type="tag", match_value="t1", verdict=Verdict.PERMIT, reason="permit", priority=2),
            MatchedRule(rule_type="tag", match_value="t2", verdict=Verdict.BLOCK, reason="block", priority=2),
        ]
        verdict, reason = resolve_context_verdict(matches)
        assert verdict == Verdict.BLOCK


# --- Top-level evaluate_context_rules ---


class TestEvaluateContextRules:
    def test_no_context(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {}, "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy_with_context_rules,
        )
        assert verdict is None
        assert matches == []

    def test_site_context_blocks(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"site": "production"},
            "configure_vlan",
            RiskTier.TIER_3_MEDIUM_RISK_WRITE,
            policy_with_context_rules,
        )
        assert verdict == Verdict.BLOCK
        assert len(matches) > 0

    def test_role_context_escalates(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"device_role": "core-router"},
            "show_running_config",
            RiskTier.TIER_1_READ,
            policy_with_context_rules,
        )
        assert verdict == Verdict.ESCALATE

    def test_tag_context_blocks(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"device_tags": ["critical"]},
            "configure_vlan",
            RiskTier.TIER_3_MEDIUM_RISK_WRITE,
            policy_with_context_rules,
        )
        assert verdict == Verdict.BLOCK

    def test_combined_context_tag_wins(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"site": "staging", "device_role": "core-router", "device_tags": ["critical"]},
            "configure_vlan",
            RiskTier.TIER_3_MEDIUM_RISK_WRITE,
            policy_with_context_rules,
        )
        # Tag "critical" → BLOCK wins over site/role escalations
        assert verdict == Verdict.BLOCK

    def test_empty_string_context_values_ignored(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"site": "", "device_role": "  ", "device_tags": []},
            "configure_vlan",
            RiskTier.TIER_3_MEDIUM_RISK_WRITE,
            policy_with_context_rules,
        )
        assert verdict is None

    def test_non_string_context_values_ignored(self, policy_with_context_rules) -> None:
        verdict, matches = evaluate_context_rules(
            {"site": 123, "device_role": None, "device_tags": "not-a-list"},
            "configure_vlan",
            RiskTier.TIER_3_MEDIUM_RISK_WRITE,
            policy_with_context_rules,
        )
        assert verdict is None

    def test_policy_with_no_rules(self) -> None:
        """Empty rules list means no context rules fire."""
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
        verdict, matches = evaluate_context_rules(
            {"site": "production"}, "configure_vlan", RiskTier.TIER_3_MEDIUM_RISK_WRITE, policy,
        )
        assert verdict is None
        assert matches == []


# --- Engine Integration ---


class TestEngineContextIntegration:
    async def test_context_block_overrides_permit(self, engine_with_context) -> None:
        """A read that would normally PERMIT gets BLOCKED by site rule."""
        request = EvaluationRequest(
            tool_name="set_interface_description",
            confidence_score=0.9,
            device_targets=["router1"],
            context={"site": "production"},
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.BLOCK
        assert len(result.matched_rules) > 0

    async def test_context_escalate_overrides_permit(self, engine_with_context) -> None:
        """A read that would normally PERMIT gets ESCALATED by role rule."""
        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
            context={"device_role": "core-router"},
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.ESCALATE

    async def test_no_context_unchanged_behavior(self, engine_with_context) -> None:
        """Empty context does not change normal evaluation flow."""
        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.PERMIT
        assert result.matched_rules == []

    async def test_context_permit_is_advisory_only(self, engine_with_context) -> None:
        """Context PERMIT does not bypass confidence/scope checks."""
        request = EvaluationRequest(
            tool_name="configure_vlan",
            confidence_score=0.3,
            device_targets=["switch1"],
            context={"device_role": "access-switch"},
        )
        result = await engine_with_context.evaluate(request)
        # access-switch role returns PERMIT, but confidence is below threshold
        # so the normal flow should still ESCALATE
        assert result.verdict == Verdict.ESCALATE

    async def test_hard_block_still_blocks_with_context(self, engine_with_context) -> None:
        """Hard block check happens before context rules."""
        request = EvaluationRequest(
            tool_name="write_erase",
            confidence_score=1.0,
            context={"device_role": "access-switch"},
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.BLOCK
        assert "Hard" in result.reason

    async def test_matched_rules_in_result(self, engine_with_context) -> None:
        """matched_rules populated when context rules fire."""
        request = EvaluationRequest(
            tool_name="configure_vlan",
            confidence_score=0.9,
            device_targets=["switch1"],
            context={"site": "production"},
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.BLOCK
        assert any("site:" in r for r in result.matched_rules)

    async def test_tag_context_block_in_engine(self, engine_with_context) -> None:
        """Tag rule BLOCK applies through engine."""
        request = EvaluationRequest(
            tool_name="configure_vlan",
            confidence_score=0.9,
            device_targets=["switch1"],
            context={"device_tags": ["critical"]},
        )
        result = await engine_with_context.evaluate(request)
        assert result.verdict == Verdict.BLOCK


# --- Model Validation ---


class TestSiteRuleModel:
    def test_valid_site_rule(self) -> None:
        rule = SiteRule(site="hq", verdict=Verdict.BLOCK, reason="No writes to HQ")
        assert rule.site == "hq"
        assert rule.verdict == Verdict.BLOCK

    def test_default_applies_to(self) -> None:
        rule = SiteRule(site="dc1", verdict=Verdict.ESCALATE)
        assert rule.applies_to == "write"


class TestRoleRuleModel:
    def test_valid_role_rule(self) -> None:
        rule = RoleRule(role="core-router", verdict=Verdict.ESCALATE, reason="Core needs review")
        assert rule.role == "core-router"

    def test_default_applies_to(self) -> None:
        rule = RoleRule(role="switch", verdict=Verdict.PERMIT)
        assert rule.applies_to == "write"


class TestTagRuleModel:
    def test_valid_tag_rule(self) -> None:
        rule = TagRule(tag="production-core", verdict=Verdict.BLOCK, reason="Prod core blocked")
        assert rule.tag == "production-core"

    def test_forbids_extra(self) -> None:
        with pytest.raises(Exception):
            TagRule(tag="x", verdict=Verdict.BLOCK, extra_field="bad")


class TestMaintenanceWindowConfig:
    def test_valid_window(self) -> None:
        w = MaintenanceWindowConfig(
            name="weekly", sites=["hq"], devices=["sw1"],
            start="2026-02-24T00:00:00Z", end="2026-02-24T06:00:00Z",
        )
        assert w.name == "weekly"

    def test_minimal_window(self) -> None:
        w = MaintenanceWindowConfig(name="empty")
        assert w.sites == []
        assert w.start is None

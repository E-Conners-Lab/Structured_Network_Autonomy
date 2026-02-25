"""Tests for per-agent policy overrides — C26.

Covers:
- evaluate_agent_overrides matching
- merge_verdicts restrictiveness guarantee
- Engine integration with agent overrides
- Inactive overrides skipped
- No agent = no overrides
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import Agent, AgentPolicyOverride
from sna.policy.context_rules import (
    MatchedRule,
    evaluate_agent_overrides,
    merge_verdicts,
)
from sna.policy.engine import PolicyEngine
from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    EASModulation,
    EvaluationRequest,
    HardRules,
    PolicyConfig,
    RiskTier,
    RoleRule,
    ScopeLimits,
    SiteRule,
    TagRule,
    Verdict,
)


@pytest.fixture
def policy_with_rules() -> PolicyConfig:
    return PolicyConfig(
        version="1.0",
        action_tiers={
            RiskTier.TIER_1_READ: ActionTierConfig(
                description="Read ops", default_verdict=Verdict.PERMIT,
                examples=["show_running_config", "show_interfaces", "ping"],
            ),
            RiskTier.TIER_2_LOW_RISK_WRITE: ActionTierConfig(
                description="Low risk", default_verdict=Verdict.PERMIT, requires_audit=True,
                examples=["set_interface_description"],
            ),
            RiskTier.TIER_3_MEDIUM_RISK_WRITE: ActionTierConfig(
                description="Med risk", default_verdict=Verdict.ESCALATE,
                examples=["configure_static_route", "configure_vlan"],
            ),
            RiskTier.TIER_4_HIGH_RISK_WRITE: ActionTierConfig(
                description="High risk", default_verdict=Verdict.ESCALATE,
                requires_senior_approval=True, examples=["configure_bgp_neighbor"],
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
        default_tier_for_unknown=RiskTier.TIER_3_MEDIUM_RISK_WRITE,
        hard_rules=HardRules(always_block=["write_erase"], description="Always blocked"),
        site_rules=[
            SiteRule(site="staging", verdict=Verdict.ESCALATE, applies_to="all", reason="Staging review"),
        ],
    )


@pytest.fixture
def session_factory(async_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(async_engine, expire_on_commit=False)


class TestMergeVerdicts:
    def test_both_none(self) -> None:
        assert merge_verdicts(None, None) is None

    def test_global_none_agent_block(self) -> None:
        assert merge_verdicts(None, Verdict.BLOCK) == Verdict.BLOCK

    def test_global_block_agent_none(self) -> None:
        assert merge_verdicts(Verdict.BLOCK, None) == Verdict.BLOCK

    def test_agent_cannot_relax_block(self) -> None:
        result = merge_verdicts(Verdict.BLOCK, Verdict.PERMIT)
        assert result == Verdict.BLOCK

    def test_agent_can_escalate_to_block(self) -> None:
        result = merge_verdicts(Verdict.ESCALATE, Verdict.BLOCK)
        assert result == Verdict.BLOCK

    def test_agent_escalate_keeps_escalate(self) -> None:
        result = merge_verdicts(Verdict.ESCALATE, Verdict.ESCALATE)
        assert result == Verdict.ESCALATE

    def test_global_permit_agent_escalate(self) -> None:
        result = merge_verdicts(Verdict.PERMIT, Verdict.ESCALATE)
        assert result == Verdict.ESCALATE

    def test_global_permit_agent_permit(self) -> None:
        result = merge_verdicts(Verdict.PERMIT, Verdict.PERMIT)
        assert result == Verdict.PERMIT


class TestEvaluateAgentOverrides:
    def test_tool_override_matches(self) -> None:
        overrides = [
            {
                "rule_type": "tool",
                "rule_json": {"tool_name": "ping", "verdict": "BLOCK", "reason": "Agent blocked"},
                "priority": 0,
            }
        ]
        verdict, matches = evaluate_agent_overrides(
            overrides, {}, "ping", RiskTier.TIER_1_READ,
        )
        assert verdict == Verdict.BLOCK
        assert len(matches) == 1

    def test_tool_override_no_match(self) -> None:
        overrides = [
            {
                "rule_type": "tool",
                "rule_json": {"tool_name": "ping", "verdict": "BLOCK", "reason": "Agent blocked"},
                "priority": 0,
            }
        ]
        verdict, matches = evaluate_agent_overrides(
            overrides, {}, "show_running_config", RiskTier.TIER_1_READ,
        )
        assert verdict is None

    def test_site_override_matches(self) -> None:
        overrides = [
            {
                "rule_type": "site",
                "rule_json": {"site": "production", "verdict": "BLOCK", "applies_to": "all", "reason": "Agent site block"},
                "priority": 0,
            }
        ]
        verdict, matches = evaluate_agent_overrides(
            overrides, {"site": "production"}, "ping", RiskTier.TIER_1_READ,
        )
        assert verdict == Verdict.BLOCK

    def test_empty_overrides(self) -> None:
        verdict, matches = evaluate_agent_overrides(
            [], {}, "ping", RiskTier.TIER_1_READ,
        )
        assert verdict is None
        assert matches == []


class TestEngineAgentOverrides:
    async def test_agent_override_blocks_permit(self, policy_with_rules, session_factory) -> None:
        """Agent-specific tool override blocks what would normally be PERMIT."""
        engine = PolicyEngine(
            policy=policy_with_rules, session_factory=session_factory, initial_eas=0.5,
        )

        # Create an agent and override in the DB
        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-agent-override",
                    api_key_hash="test_hash",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()

                override = AgentPolicyOverride(
                    agent_id=agent.id,
                    rule_type="tool",
                    rule_json={"tool_name": "show_running_config", "verdict": "BLOCK", "reason": "Agent blocked"},
                    priority=0,
                )
                session.add(override)
                await session.flush()
                agent_db_id = agent.id

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
            agent_id=agent_db_id,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.BLOCK

    async def test_no_agent_id_no_overrides(self, policy_with_rules, session_factory) -> None:
        """Request without agent_id skips override logic."""
        engine = PolicyEngine(
            policy=policy_with_rules, session_factory=session_factory, initial_eas=0.5,
        )

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.PERMIT

    async def test_inactive_override_skipped(self, policy_with_rules, session_factory) -> None:
        """Inactive overrides are not applied."""
        engine = PolicyEngine(
            policy=policy_with_rules, session_factory=session_factory, initial_eas=0.5,
        )

        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-agent-inactive",
                    api_key_hash="test_hash2",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()

                override = AgentPolicyOverride(
                    agent_id=agent.id,
                    rule_type="tool",
                    rule_json={"tool_name": "show_running_config", "verdict": "BLOCK", "reason": "blocked"},
                    priority=0,
                    is_active=False,
                )
                session.add(override)
                await session.flush()
                agent_db_id = agent.id

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
            agent_id=agent_db_id,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.PERMIT

    async def test_agent_override_cannot_relax_global_block(self, policy_with_rules, session_factory) -> None:
        """Agent override returning PERMIT cannot override a global context BLOCK."""
        # The global policy has site_rules for staging → ESCALATE
        engine = PolicyEngine(
            policy=policy_with_rules, session_factory=session_factory, initial_eas=0.5,
        )

        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-agent-relax",
                    api_key_hash="test_hash3",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()

                # Agent override tries to PERMIT reads
                override = AgentPolicyOverride(
                    agent_id=agent.id,
                    rule_type="site",
                    rule_json={"site": "staging", "verdict": "PERMIT", "applies_to": "all", "reason": "agent permit"},
                    priority=0,
                )
                session.add(override)
                await session.flush()
                agent_db_id = agent.id

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
            context={"site": "staging"},
            agent_id=agent_db_id,
        )
        result = await engine.evaluate(request)
        # Global says ESCALATE, agent says PERMIT — ESCALATE wins (more restrictive)
        assert result.verdict == Verdict.ESCALATE

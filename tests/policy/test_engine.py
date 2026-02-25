"""Tests for sna.policy.engine — PolicyEngine evaluate(), reload(), get_eas().

Covers:
- PERMIT verdict for read actions above threshold
- PERMIT verdict for low-risk writes above threshold (with audit flag)
- ESCALATE verdict when confidence below threshold
- ESCALATE verdict for tier default escalation
- ESCALATE verdict when scope limit exceeded
- BLOCK verdict for hard-blocked actions
- BLOCK verdict for tier 5 critical actions
- BLOCK verdict when audit write fails (fail closed)
- Escalation record creation on ESCALATE
- Audit log written for every decision
- EAS get/set
- Policy reload via engine
- Factory method from_config
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import AuditLog, EscalationRecord
from sna.policy.engine import PolicyEngine
from sna.policy.models import (
    ActionTierConfig,
    ConfidenceThresholds,
    EASModulation,
    EvaluationRequest,
    HardRules,
    PolicyConfig,
    RiskTier,
    ScopeLimits,
    Verdict,
)


@pytest.fixture
def policy() -> PolicyConfig:
    """Standard test policy."""
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


@pytest.fixture
def session_factory(async_engine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to the test engine."""
    return async_sessionmaker(async_engine, expire_on_commit=False)


@pytest.fixture
def engine(policy, session_factory) -> PolicyEngine:
    """Create a PolicyEngine with the test policy and session factory."""
    return PolicyEngine(
        policy=policy,
        session_factory=session_factory,
        initial_eas=0.5,
    )


async def _get_latest_audit(
    session_factory: async_sessionmaker[AsyncSession],
    tool_name: str,
) -> AuditLog:
    """Helper: get the most recent audit log entry for a tool name."""
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.tool_name == tool_name)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        entry = result.scalar_one()
        return entry


# --- EAS tests ---


class TestEAS:
    def test_get_eas(self, engine):
        assert engine.get_eas() == 0.5

    def test_set_eas(self, engine):
        engine.set_eas(0.8)
        assert engine.get_eas() == 0.8

    def test_set_eas_boundary_zero(self, engine):
        engine.set_eas(0.0)
        assert engine.get_eas() == 0.0

    def test_set_eas_boundary_one(self, engine):
        engine.set_eas(1.0)
        assert engine.get_eas() == 1.0

    def test_set_eas_below_zero_rejected(self, engine):
        with pytest.raises(ValueError, match="0.0 and 1.0"):
            engine.set_eas(-0.1)

    def test_set_eas_above_one_rejected(self, engine):
        with pytest.raises(ValueError, match="0.0 and 1.0"):
            engine.set_eas(1.1)

    def test_policy_property(self, engine, policy):
        assert engine.policy is policy


# --- PERMIT tests ---


class TestPermitVerdict:
    @pytest.mark.asyncio
    async def test_tier_1_read_permitted(self, engine):
        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.PERMIT
        assert result.risk_tier == RiskTier.TIER_1_READ
        assert result.escalation_id is None

    @pytest.mark.asyncio
    async def test_tier_2_write_permitted_with_audit_flag(self, engine):
        request = EvaluationRequest(
            tool_name="set_interface_description",
            confidence_score=0.9,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.PERMIT
        assert result.requires_audit is True

    @pytest.mark.asyncio
    async def test_permit_at_exact_threshold(self, engine):
        # Tier 1 threshold is 0.1, EAS=0.5 with modulation reduces it
        # Base 0.1 - (0.1 * 0.5) = 0.05
        request = EvaluationRequest(
            tool_name="ping",
            confidence_score=0.05,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.PERMIT


# --- ESCALATE tests ---


class TestEscalateVerdict:
    @pytest.mark.asyncio
    async def test_confidence_below_threshold(self, engine):
        request = EvaluationRequest(
            tool_name="configure_static_route",
            confidence_score=0.3,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.ESCALATE
        assert "Confidence" in result.reason
        assert result.escalation_id is not None

    @pytest.mark.asyncio
    async def test_tier_default_escalation(self, engine):
        request = EvaluationRequest(
            tool_name="configure_static_route",
            confidence_score=0.95,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.ESCALATE
        assert result.escalation_id is not None

    @pytest.mark.asyncio
    async def test_scope_escalation(self, engine):
        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.95,
            device_targets=["r1", "r2", "r3", "r4"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.ESCALATE
        assert "Device count" in result.reason

    @pytest.mark.asyncio
    async def test_tier_4_requires_senior_approval(self, engine):
        request = EvaluationRequest(
            tool_name="configure_bgp_neighbor",
            confidence_score=0.95,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.ESCALATE
        assert result.requires_senior_approval is True

    @pytest.mark.asyncio
    async def test_escalation_record_created(self, engine, session_factory):
        request = EvaluationRequest(
            tool_name="configure_vlan",
            confidence_score=0.3,
            device_targets=["switch1"],
        )
        result = await engine.evaluate(request)
        assert result.escalation_id is not None

        async with session_factory() as session:
            esc = await session.execute(
                select(EscalationRecord).where(
                    EscalationRecord.external_id == str(result.escalation_id)
                )
            )
            record = esc.scalar_one()
            assert record.tool_name == "configure_vlan"
            assert record.status == "PENDING"


# --- BLOCK tests ---


class TestBlockVerdict:
    @pytest.mark.asyncio
    async def test_hard_blocked_action(self, engine):
        request = EvaluationRequest(
            tool_name="write_erase",
            confidence_score=1.0,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.BLOCK
        assert "Hard" in result.reason

    @pytest.mark.asyncio
    async def test_hard_block_case_insensitive(self, engine):
        request = EvaluationRequest(
            tool_name="FACTORY_RESET",
            confidence_score=1.0,
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_tier_5_default_block(self, engine):
        request = EvaluationRequest(
            tool_name="reload_device",
            confidence_score=1.0,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_block_has_no_escalation_id(self, engine):
        request = EvaluationRequest(
            tool_name="write_erase",
            confidence_score=1.0,
        )
        result = await engine.evaluate(request)
        assert result.escalation_id is None


# --- Audit log tests ---


class TestAuditLogging:
    @pytest.mark.asyncio
    async def test_permit_creates_audit_entry(self, engine, session_factory):
        request = EvaluationRequest(
            tool_name="show_interfaces",
            confidence_score=0.9,
        )
        await engine.evaluate(request)

        entry = await _get_latest_audit(session_factory, "show_interfaces")
        assert entry.verdict == "PERMIT"
        assert entry.eas_at_time == 0.5

    @pytest.mark.asyncio
    async def test_block_creates_audit_entry(self, engine, session_factory):
        request = EvaluationRequest(
            tool_name="write_erase",
            confidence_score=1.0,
        )
        await engine.evaluate(request)

        entry = await _get_latest_audit(session_factory, "write_erase")
        assert entry.verdict == "BLOCK"

    @pytest.mark.asyncio
    async def test_escalate_creates_audit_entry(self, engine, session_factory):
        request = EvaluationRequest(
            tool_name="configure_static_route",
            confidence_score=0.3,
            device_targets=["router1"],
        )
        await engine.evaluate(request)

        entry = await _get_latest_audit(session_factory, "configure_static_route")
        assert entry.verdict == "ESCALATE"

    @pytest.mark.asyncio
    async def test_audit_records_eas(self, engine, session_factory):
        engine.set_eas(0.75)
        request = EvaluationRequest(
            tool_name="ping",
            confidence_score=0.9,
        )
        await engine.evaluate(request)

        entry = await _get_latest_audit(session_factory, "ping")
        assert entry.eas_at_time == 0.75

    @pytest.mark.asyncio
    async def test_audit_count_increases(self, engine, session_factory):
        async with session_factory() as session:
            before = await session.execute(select(func.count(AuditLog.id)))
            count_before = before.scalar()

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
        )
        await engine.evaluate(request)

        async with session_factory() as session:
            after = await session.execute(select(func.count(AuditLog.id)))
            count_after = after.scalar()

        assert count_after == count_before + 1


# --- Fail closed tests ---


class TestFailClosed:
    @pytest.mark.asyncio
    async def test_audit_write_failure_blocks(self, policy):
        """If the database is unreachable, the engine must BLOCK."""
        from sqlalchemy.ext.asyncio import create_async_engine

        # Create an engine pointing to a non-existent path to force failures
        bad_engine = create_async_engine(
            "sqlite+aiosqlite:////:invalid_path_that_will_fail:",
            echo=False,
        )
        bad_factory = async_sessionmaker(bad_engine, expire_on_commit=False)

        engine = PolicyEngine(
            policy=policy,
            session_factory=bad_factory,
            initial_eas=0.5,
        )

        request = EvaluationRequest(
            tool_name="show_running_config",
            confidence_score=0.9,
        )
        result = await engine.evaluate(request)

        # Would normally be PERMIT, but audit failure forces BLOCK
        assert result.verdict == Verdict.BLOCK
        assert "audit" in result.reason.lower() or "fail" in result.reason.lower()

        await bad_engine.dispose()


# --- Unknown tool tests ---


class TestUnknownTool:
    @pytest.mark.asyncio
    async def test_unknown_tool_uses_default_tier(self, engine):
        request = EvaluationRequest(
            tool_name="completely_unknown_tool",
            confidence_score=0.95,
            device_targets=["router1"],
        )
        result = await engine.evaluate(request)
        assert result.risk_tier == RiskTier.TIER_3_MEDIUM_RISK_WRITE
        assert result.verdict == Verdict.ESCALATE


# --- Reload tests ---


class TestReload:
    @pytest.mark.asyncio
    async def test_reload_updates_policy(self, engine, sample_policy_path):
        new_policy, diff = await engine.reload(str(sample_policy_path))
        assert engine.policy is new_policy

    @pytest.mark.asyncio
    async def test_reload_file_not_found(self, engine):
        with pytest.raises(FileNotFoundError):
            await engine.reload("/nonexistent/path.yaml")


# --- Factory method tests ---


class TestFromConfig:
    @pytest.mark.asyncio
    async def test_from_config(self, session_factory, sample_policy_path):
        engine = await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )
        assert engine.get_eas() == 0.1
        assert engine.policy.version == "1.0"
        assert len(engine.policy.action_tiers) == 5

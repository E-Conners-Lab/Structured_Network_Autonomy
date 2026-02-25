"""End-to-end integration tests — full stack from MCP tool call to audit log.

These tests exercise the complete flow:
  MCPToolCall → MCPGateway → PolicyEngine → DB audit write → notification dispatch

No mocks for core components — real engine, real DB, real policy.
Only external HTTP (notifications) uses stubs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import AuditLog, Base, EscalationRecord, EscalationStatus
from sna.integrations.mcp import MCPGateway, MCPToolCall
from sna.integrations.notifier import CompositeNotifier, Notifier
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy
from sna.policy.models import EvaluationResult, RiskTier, Verdict

SAMPLE_POLICY = "policies/default.yaml"


class _RecordingNotifier(Notifier):
    """Records all notification calls with timestamps."""

    def __init__(self) -> None:
        self.escalations: list[EvaluationResult] = []
        self.blocks: list[EvaluationResult] = []

    async def send_escalation(self, result: EvaluationResult) -> bool:
        self.escalations.append(result)
        return True

    async def send_block(self, result: EvaluationResult) -> bool:
        self.blocks.append(result)
        return True


@pytest.fixture
async def db_engine():
    """In-memory SQLite engine with tables created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session_factory(db_engine):
    """Session factory bound to the test engine."""
    return async_sessionmaker(db_engine, expire_on_commit=False)


@pytest.fixture
async def policy_engine(session_factory):
    """Real PolicyEngine with default policy and low EAS."""
    policy = await load_policy(SAMPLE_POLICY)
    return PolicyEngine(
        policy=policy,
        session_factory=session_factory,
        initial_eas=0.1,
    )


@pytest.fixture
def recorder() -> _RecordingNotifier:
    """A recording notifier for assertions."""
    return _RecordingNotifier()


@pytest.fixture
def gateway(policy_engine, recorder) -> MCPGateway:
    """Full-stack gateway with real engine and recording notifier."""
    composite = CompositeNotifier([recorder])
    return MCPGateway(engine=policy_engine, notifier=composite)


class TestFullStackPermit:
    """End-to-end: tool call → PERMIT → audit log, no notification."""

    async def test_permit_flow(self, gateway, recorder, session_factory) -> None:
        """A high-confidence tier 1 read should be permitted end-to-end."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            parameters={"detail": True},
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="e2e-test-agent",
        )
        result = await gateway.intercept(call)

        # Verdict
        assert result.permitted is True
        assert result.evaluation.verdict == Verdict.PERMIT
        assert result.evaluation.risk_tier == RiskTier.TIER_1_READ
        assert result.evaluation.tool_name == "show_interfaces"
        assert result.evaluation.device_count == 1

        # No notifications
        assert result.notifications_sent == 0
        assert len(recorder.escalations) == 0
        assert len(recorder.blocks) == 0

        # Audit log written
        async with session_factory() as session:
            count = await session.execute(select(func.count(AuditLog.id)))
            assert count.scalar() >= 1

            log = await session.execute(
                select(AuditLog)
                .where(AuditLog.tool_name == "show_interfaces")
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
            entry = log.scalar_one()
            assert entry.verdict == "PERMIT"
            assert entry.risk_tier == "tier_1_read"
            assert entry.confidence_score == 0.99
            assert entry.eas_at_time == 0.1
            assert UUID(entry.external_id)  # Valid UUID


class TestFullStackEscalate:
    """End-to-end: tool call → ESCALATE → audit + escalation record + notification."""

    async def test_low_confidence_escalation(
        self, gateway, recorder, session_factory
    ) -> None:
        """Low confidence on a tier 1 read should escalate."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
            caller_id="e2e-low-confidence",
        )
        result = await gateway.intercept(call)

        # Verdict
        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE
        assert result.evaluation.escalation_id is not None

        # Notification sent
        assert result.notifications_sent == 1
        assert len(recorder.escalations) == 1
        assert recorder.escalations[0].tool_name == "show_interfaces"

        # Escalation record in DB
        async with session_factory() as session:
            esc = await session.execute(
                select(EscalationRecord)
                .where(EscalationRecord.tool_name == "show_interfaces")
                .order_by(EscalationRecord.id.desc())
                .limit(1)
            )
            record = esc.scalar_one()
            assert record.status == EscalationStatus.PENDING.value
            assert record.confidence_score == 0.01
            assert UUID(record.external_id)

    async def test_scope_escalation(
        self, gateway, recorder, session_factory
    ) -> None:
        """Exceeding device scope should escalate even with high confidence."""
        targets = [f"switch-{i:03d}" for i in range(60)]
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=targets,
            confidence_score=0.99,
            caller_id="e2e-scope-test",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE
        assert result.evaluation.device_count == 60
        assert "scope" in result.evaluation.reason.lower() or "device" in result.evaluation.reason.lower()
        assert result.notifications_sent == 1

    async def test_tier4_always_escalates(
        self, gateway, recorder, session_factory
    ) -> None:
        """Tier 4 high-risk actions default to ESCALATE with senior approval."""
        call = MCPToolCall(
            tool_name="configure_bgp_neighbor",
            device_targets=["router-01"],
            confidence_score=0.99,
            caller_id="e2e-tier4",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE
        assert result.evaluation.risk_tier == RiskTier.TIER_4_HIGH_RISK_WRITE
        assert result.evaluation.requires_senior_approval is True
        assert result.notifications_sent == 1


class TestFullStackBlock:
    """End-to-end: tool call → BLOCK → audit log + notification, no escalation."""

    async def test_hard_block(self, gateway, recorder, session_factory) -> None:
        """Hard-blocked action should BLOCK regardless of confidence."""
        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="e2e-hard-block",
        )
        result = await gateway.intercept(call)

        # Verdict
        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.BLOCK
        assert result.evaluation.escalation_id is None

        # Block notification sent
        assert result.notifications_sent == 1
        assert len(recorder.blocks) == 1

        # Audit log records the BLOCK
        async with session_factory() as session:
            log = await session.execute(
                select(AuditLog)
                .where(AuditLog.tool_name == "factory_reset")
                .order_by(AuditLog.id.desc())
                .limit(1)
            )
            entry = log.scalar_one()
            assert entry.verdict == "BLOCK"

    async def test_tier5_critical_blocks(
        self, gateway, recorder, session_factory
    ) -> None:
        """Tier 5 critical actions should default to BLOCK even at max confidence."""
        call = MCPToolCall(
            tool_name="reload_device",
            device_targets=["core-router-01"],
            confidence_score=1.0,  # Must be 1.0 — tier 5 threshold is 1.0
            caller_id="e2e-tier5",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.BLOCK
        assert result.evaluation.risk_tier == RiskTier.TIER_5_CRITICAL


class TestFullStackMultiAction:
    """End-to-end: multiple sequential tool calls verify independent evaluation."""

    async def test_sequential_actions(
        self, gateway, recorder, session_factory
    ) -> None:
        """Multiple actions should each be evaluated independently."""
        # Action 1: PERMIT
        r1 = await gateway.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.99,
        ))

        # Action 2: ESCALATE
        r2 = await gateway.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
        ))

        # Action 3: BLOCK
        r3 = await gateway.intercept(MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
        ))

        assert r1.permitted is True
        assert r2.permitted is False
        assert r3.permitted is False

        assert r1.evaluation.verdict == Verdict.PERMIT
        assert r2.evaluation.verdict == Verdict.ESCALATE
        assert r3.evaluation.verdict == Verdict.BLOCK

        # All three should have audit entries
        async with session_factory() as session:
            count = await session.execute(select(func.count(AuditLog.id)))
            assert count.scalar() >= 3

        # Notifications: 1 escalation + 1 block
        assert len(recorder.escalations) == 1
        assert len(recorder.blocks) == 1


class TestFullStackEASEffect:
    """End-to-end: EAS modulation affects confidence thresholds."""

    async def test_high_eas_lowers_threshold(
        self, policy_engine, session_factory, recorder
    ) -> None:
        """Higher EAS should lower the effective threshold, permitting more."""
        composite = CompositeNotifier([recorder])

        # With low EAS (0.1), a moderate confidence may escalate
        low_eas_gw = MCPGateway(engine=policy_engine, notifier=composite)
        r_low = await low_eas_gw.intercept(MCPToolCall(
            tool_name="set_interface_description",
            device_targets=["switch-01"],
            confidence_score=0.65,
        ))

        # Raise EAS
        policy_engine.set_eas(0.9)
        r_high = await low_eas_gw.intercept(MCPToolCall(
            tool_name="set_interface_description",
            device_targets=["switch-01"],
            confidence_score=0.65,
        ))

        # With higher EAS, the effective threshold should be lower
        assert r_high.evaluation.confidence_threshold <= r_low.evaluation.confidence_threshold

        # Reset for other tests
        policy_engine.set_eas(0.1)


class TestFullStackAuditIntegrity:
    """End-to-end: verify audit log integrity across operations."""

    async def test_audit_entries_have_unique_external_ids(
        self, gateway, session_factory
    ) -> None:
        """Every audit entry should have a unique UUID external_id."""
        for i in range(5):
            await gateway.intercept(MCPToolCall(
                tool_name="show_interfaces",
                device_targets=[f"switch-{i:02d}"],
                confidence_score=0.99,
            ))

        async with session_factory() as session:
            result = await session.execute(select(AuditLog.external_id))
            ids = [row[0] for row in result.all()]
            # All should be valid UUIDs
            for ext_id in ids:
                UUID(ext_id)
            # All should be unique
            assert len(ids) == len(set(ids))

    async def test_audit_records_eas_at_decision_time(
        self, policy_engine, session_factory, recorder
    ) -> None:
        """Audit log should capture the EAS at the time of decision."""
        composite = CompositeNotifier([recorder])
        gw = MCPGateway(engine=policy_engine, notifier=composite)

        policy_engine.set_eas(0.3)
        await gw.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.99,
        ))

        policy_engine.set_eas(0.7)
        await gw.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-02"],
            confidence_score=0.99,
        ))

        async with session_factory() as session:
            result = await session.execute(
                select(AuditLog.eas_at_time)
                .order_by(AuditLog.id.desc())
                .limit(2)
            )
            scores = [row[0] for row in result.all()]
            # Most recent first
            assert scores[0] == pytest.approx(0.7)
            assert scores[1] == pytest.approx(0.3)

        policy_engine.set_eas(0.1)

    async def test_audit_timestamps_are_chronological(
        self, gateway, session_factory
    ) -> None:
        """Audit timestamps should be in chronological order."""
        for i in range(3):
            await gateway.intercept(MCPToolCall(
                tool_name="show_interfaces",
                device_targets=[f"switch-{i:02d}"],
                confidence_score=0.99,
            ))

        async with session_factory() as session:
            result = await session.execute(
                select(AuditLog.timestamp).order_by(AuditLog.id.asc())
            )
            timestamps = [row[0] for row in result.all()]
            for i in range(len(timestamps) - 1):
                assert timestamps[i] <= timestamps[i + 1]


class TestFullStackEscalationLifecycle:
    """End-to-end: escalation creation → decision flow."""

    async def test_escalation_approve_lifecycle(
        self, gateway, session_factory
    ) -> None:
        """Create an escalation, then approve it via DB."""
        # Create escalation
        result = await gateway.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
        ))
        assert result.evaluation.verdict == Verdict.ESCALATE
        esc_ext_id = str(result.evaluation.escalation_id)

        # Verify PENDING
        async with session_factory() as session:
            esc = await session.execute(
                select(EscalationRecord)
                .where(EscalationRecord.external_id == esc_ext_id)
            )
            record = esc.scalar_one()
            assert record.status == EscalationStatus.PENDING.value

        # Approve via direct DB update (simulating API decision endpoint)
        async with session_factory() as session:
            async with session.begin():
                esc = await session.execute(
                    select(EscalationRecord)
                    .where(EscalationRecord.external_id == esc_ext_id)
                )
                record = esc.scalar_one()
                record.status = EscalationStatus.APPROVED.value
                record.decided_by = "senior-admin"
                record.decided_at = datetime.now(UTC)
                record.decision_reason = "Integration test approval"

        # Verify APPROVED
        async with session_factory() as session:
            esc = await session.execute(
                select(EscalationRecord)
                .where(EscalationRecord.external_id == esc_ext_id)
            )
            record = esc.scalar_one()
            assert record.status == EscalationStatus.APPROVED.value
            assert record.decided_by == "senior-admin"

    async def test_escalation_linked_to_audit(
        self, gateway, session_factory
    ) -> None:
        """Escalation record should reference the correct audit log entry."""
        result = await gateway.intercept(MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
        ))

        async with session_factory() as session:
            esc = await session.execute(
                select(EscalationRecord)
                .order_by(EscalationRecord.id.desc())
                .limit(1)
            )
            record = esc.scalar_one()
            assert record.audit_log_id is not None

            # Fetch the linked audit log
            audit = await session.execute(
                select(AuditLog).where(AuditLog.id == record.audit_log_id)
            )
            audit_entry = audit.scalar_one()
            assert audit_entry.verdict == "ESCALATE"
            assert audit_entry.tool_name == "show_interfaces"


class TestFullStackUnknownTools:
    """End-to-end: unknown tools fall to default tier classification."""

    async def test_unknown_tool_uses_default_tier(
        self, gateway, session_factory
    ) -> None:
        """An unrecognized tool should use the configured default tier."""
        call = MCPToolCall(
            tool_name="totally_unknown_tool_xyz",
            device_targets=["device-01"],
            confidence_score=0.99,
        )
        result = await gateway.intercept(call)

        # Default tier is tier_3_medium_risk_write (ESCALATE by default)
        assert result.evaluation.risk_tier == RiskTier.TIER_3_MEDIUM_RISK_WRITE

        # Audit entry should record the tier
        async with session_factory() as session:
            log = await session.execute(
                select(AuditLog)
                .where(AuditLog.tool_name == "totally_unknown_tool_xyz")
                .limit(1)
            )
            entry = log.scalar_one()
            assert entry.risk_tier == "tier_3_medium_risk_write"

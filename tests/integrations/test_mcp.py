"""Tests for sna.integrations.mcp — MCP tool call interception."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import Base
from sna.integrations.mcp import MCPGateway, MCPInterceptResult, MCPToolCall
from sna.integrations.notifier import CompositeNotifier, Notifier
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy
from sna.policy.models import EvaluationResult, Verdict

SAMPLE_POLICY = "policies/default.yaml"


class _StubNotifier(Notifier):
    """Records calls and returns configurable success."""

    def __init__(self, success: bool = True) -> None:
        self.escalation_calls: list[EvaluationResult] = []
        self.block_calls: list[EvaluationResult] = []
        self._success = success

    async def send_escalation(self, result: EvaluationResult) -> bool:
        self.escalation_calls.append(result)
        return self._success

    async def send_block(self, result: EvaluationResult) -> bool:
        self.block_calls.append(result)
        return self._success


class _FailingNotifier(Notifier):
    """Always raises on send."""

    async def send_escalation(self, result: EvaluationResult) -> bool:
        raise ConnectionError("Simulated failure")

    async def send_block(self, result: EvaluationResult) -> bool:
        raise ConnectionError("Simulated failure")


@pytest.fixture
async def engine():
    """Create a real PolicyEngine with in-memory SQLite."""
    db_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    policy = await load_policy(SAMPLE_POLICY)
    pe = PolicyEngine(
        policy=policy,
        session_factory=session_factory,
        initial_eas=0.1,
    )
    yield pe
    await db_engine.dispose()


@pytest.fixture
def stub_notifier() -> _StubNotifier:
    """A stub notifier that records calls."""
    return _StubNotifier()


@pytest.fixture
def composite(stub_notifier: _StubNotifier) -> CompositeNotifier:
    """CompositeNotifier with a single stub backend."""
    return CompositeNotifier([stub_notifier])


@pytest.fixture
def gateway(engine: PolicyEngine, composite: CompositeNotifier) -> MCPGateway:
    """MCPGateway with real engine and stub notifier."""
    return MCPGateway(engine=engine, notifier=composite)


class TestMCPToolCall:
    """MCPToolCall dataclass."""

    def test_defaults(self) -> None:
        """Default values should be sensible."""
        call = MCPToolCall(tool_name="show_version")
        assert call.tool_name == "show_version"
        assert call.parameters == {}
        assert call.device_targets == []
        assert call.confidence_score == 0.0
        assert call.context == {}
        assert call.caller_id == "unknown"

    def test_full_construction(self) -> None:
        """All fields should be settable."""
        call = MCPToolCall(
            tool_name="configure_interface",
            parameters={"interface": "eth0", "description": "uplink"},
            device_targets=["switch-01", "switch-02"],
            confidence_score=0.95,
            context={"model": "gpt-4", "session": "abc"},
            caller_id="agent-alpha",
        )
        assert call.tool_name == "configure_interface"
        assert len(call.device_targets) == 2
        assert call.caller_id == "agent-alpha"

    def test_frozen(self) -> None:
        """MCPToolCall should be immutable."""
        call = MCPToolCall(tool_name="show_version")
        with pytest.raises(AttributeError):
            call.tool_name = "other"  # type: ignore[misc]


class TestMCPInterceptResult:
    """MCPInterceptResult dataclass."""

    def test_permitted_flag(self) -> None:
        """permitted should reflect the verdict."""
        from datetime import UTC, datetime
        from sna.policy.models import RiskTier

        result = EvaluationResult(
            verdict=Verdict.PERMIT,
            risk_tier=RiskTier.TIER_1_READ,
            tool_name="show_version",
            reason="Permitted",
            confidence_score=0.99,
            confidence_threshold=0.5,
            device_count=1,
        )
        intercept = MCPInterceptResult(
            permitted=True,
            evaluation=result,
            timestamp=datetime.now(UTC),
        )
        assert intercept.permitted is True
        assert intercept.notifications_sent == 0


class TestMCPGateway:
    """MCPGateway.intercept() — full integration with engine and notifier."""

    async def test_permit_tier1_read(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """Tier 1 read with high confidence should be permitted."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )
        result = await gateway.intercept(call)

        assert result.permitted is True
        assert result.evaluation.verdict == Verdict.PERMIT
        assert result.notifications_sent == 0
        assert len(stub_notifier.escalation_calls) == 0
        assert len(stub_notifier.block_calls) == 0

    async def test_escalate_low_confidence(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """Low confidence should trigger ESCALATE and notification."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
            caller_id="test-agent",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE
        assert result.notifications_sent == 1
        assert len(stub_notifier.escalation_calls) == 1
        assert stub_notifier.escalation_calls[0].tool_name == "show_interfaces"

    async def test_block_hard_blocked(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """Hard-blocked action should BLOCK and send notification."""
        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.BLOCK
        assert result.notifications_sent == 1
        assert len(stub_notifier.block_calls) == 1

    async def test_scope_escalation(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """Exceeding scope limit should escalate."""
        targets = [f"switch-{i:02d}" for i in range(60)]
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=targets,
            confidence_score=0.99,
            caller_id="test-agent",
        )
        result = await gateway.intercept(call)

        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE
        assert result.notifications_sent == 1

    async def test_notification_failure_doesnt_change_verdict(
        self, engine: PolicyEngine
    ) -> None:
        """Notification failure should not affect the verdict."""
        failing = _FailingNotifier()
        composite = CompositeNotifier([failing])
        gw = MCPGateway(engine=engine, notifier=composite)

        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
        )
        result = await gw.intercept(call)

        # Verdict is BLOCK regardless of notification failure
        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.BLOCK
        assert result.notifications_sent == 0

    async def test_no_notifiers_configured(self, engine: PolicyEngine) -> None:
        """Empty composite notifier should work without error."""
        composite = CompositeNotifier([])
        gw = MCPGateway(engine=engine, notifier=composite)

        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
        )
        result = await gw.intercept(call)

        assert result.permitted is False
        assert result.notifications_sent == 0

    async def test_multiple_notifiers(self, engine: PolicyEngine) -> None:
        """Multiple notifiers should all receive the notification."""
        stub1 = _StubNotifier()
        stub2 = _StubNotifier()
        composite = CompositeNotifier([stub1, stub2])
        gw = MCPGateway(engine=engine, notifier=composite)

        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
        )
        result = await gw.intercept(call)

        assert result.notifications_sent == 2
        assert len(stub1.block_calls) == 1
        assert len(stub2.block_calls) == 1

    async def test_partial_notification_failure(self, engine: PolicyEngine) -> None:
        """One notifier failing, one succeeding should report 1 sent."""
        stub = _StubNotifier()
        failing = _FailingNotifier()
        composite = CompositeNotifier([stub, failing])
        gw = MCPGateway(engine=engine, notifier=composite)

        call = MCPToolCall(
            tool_name="factory_reset",
            device_targets=["switch-01"],
            confidence_score=0.99,
        )
        result = await gw.intercept(call)

        assert result.notifications_sent == 1
        assert len(stub.block_calls) == 1

    async def test_permit_no_notifications(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """PERMIT verdict should not trigger any notifications."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["router-01"],
            confidence_score=0.99,
        )
        result = await gateway.intercept(call)

        assert result.permitted is True
        assert result.notifications_sent == 0
        assert len(stub_notifier.escalation_calls) == 0
        assert len(stub_notifier.block_calls) == 0

    async def test_result_has_timestamp(self, gateway: MCPGateway) -> None:
        """Intercept result should include a UTC timestamp."""
        from datetime import UTC, datetime

        before = datetime.now(UTC)
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["router-01"],
            confidence_score=0.99,
        )
        result = await gateway.intercept(call)
        after = datetime.now(UTC)

        assert before <= result.timestamp <= after

    async def test_result_contains_evaluation(self, gateway: MCPGateway) -> None:
        """Intercept result should contain the full EvaluationResult."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.99,
        )
        result = await gateway.intercept(call)

        assert result.evaluation.tool_name == "show_interfaces"
        assert result.evaluation.device_count == 1
        assert result.evaluation.confidence_score == 0.99

    async def test_caller_id_preserved(
        self, gateway: MCPGateway, stub_notifier: _StubNotifier
    ) -> None:
        """caller_id should be passed through (for logging)."""
        call = MCPToolCall(
            tool_name="show_interfaces",
            device_targets=["switch-01"],
            confidence_score=0.01,
            caller_id="agent-alpha",
        )
        # Just verifying it doesn't error — caller_id is logged, not in result
        result = await gateway.intercept(call)
        assert result.evaluation is not None

    async def test_gateway_properties(
        self, gateway: MCPGateway, engine: PolicyEngine, composite: CompositeNotifier
    ) -> None:
        """Gateway should expose engine and notifier properties."""
        assert gateway.engine is engine
        assert gateway.notifier is composite

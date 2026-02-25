"""Tests for sna.integrations.notifier — abstract interface and composite dispatch."""

from __future__ import annotations

from uuid import uuid4

import pytest

from sna.integrations.notifier import CompositeNotifier, Notifier, create_notifier
from sna.policy.models import EvaluationResult, RiskTier, Verdict


def _make_result(
    verdict: Verdict = Verdict.ESCALATE,
    tool_name: str = "show_interfaces",
) -> EvaluationResult:
    """Create a sample EvaluationResult for testing."""
    return EvaluationResult(
        verdict=verdict,
        risk_tier=RiskTier.TIER_1_READ,
        tool_name=tool_name,
        reason="Test reason",
        confidence_score=0.5,
        confidence_threshold=0.8,
        device_count=1,
        requires_audit=False,
        requires_senior_approval=False,
        escalation_id=uuid4() if verdict == Verdict.ESCALATE else None,
    )


class _StubNotifier(Notifier):
    """Test stub that records calls and returns a configurable result."""

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
    """Test stub that raises on every call."""

    async def send_escalation(self, result: EvaluationResult) -> bool:
        raise ConnectionError("Simulated failure")

    async def send_block(self, result: EvaluationResult) -> bool:
        raise ConnectionError("Simulated failure")


class TestCompositeNotifier:
    """CompositeNotifier dispatch logic."""

    async def test_empty_composite_returns_empty(self) -> None:
        """No backends means empty result list."""
        composite = CompositeNotifier([])
        result = _make_result()
        assert await composite.send_escalation(result) == []
        assert await composite.send_block(result) == []

    async def test_single_backend_escalation(self) -> None:
        """Single backend receives escalation call."""
        stub = _StubNotifier()
        composite = CompositeNotifier([stub])
        result = _make_result(Verdict.ESCALATE)

        outcomes = await composite.send_escalation(result)

        assert outcomes == [True]
        assert len(stub.escalation_calls) == 1
        assert stub.escalation_calls[0] is result

    async def test_single_backend_block(self) -> None:
        """Single backend receives block call."""
        stub = _StubNotifier()
        composite = CompositeNotifier([stub])
        result = _make_result(Verdict.BLOCK)

        outcomes = await composite.send_block(result)

        assert outcomes == [True]
        assert len(stub.block_calls) == 1

    async def test_multiple_backends(self) -> None:
        """Multiple backends all receive the notification."""
        stub1 = _StubNotifier()
        stub2 = _StubNotifier()
        composite = CompositeNotifier([stub1, stub2])
        result = _make_result()

        outcomes = await composite.send_escalation(result)

        assert outcomes == [True, True]
        assert len(stub1.escalation_calls) == 1
        assert len(stub2.escalation_calls) == 1

    async def test_failing_backend_returns_false(self) -> None:
        """A failing backend returns False but doesn't block others."""
        stub = _StubNotifier()
        failing = _FailingNotifier()
        composite = CompositeNotifier([failing, stub])
        result = _make_result()

        outcomes = await composite.send_escalation(result)

        assert outcomes == [False, True]
        assert len(stub.escalation_calls) == 1

    async def test_all_failing_returns_all_false(self) -> None:
        """All backends failing returns all False."""
        composite = CompositeNotifier([_FailingNotifier(), _FailingNotifier()])
        result = _make_result()

        outcomes = await composite.send_escalation(result)
        assert outcomes == [False, False]

    async def test_backends_property(self) -> None:
        """backends property returns a copy of the notifier list."""
        stub = _StubNotifier()
        composite = CompositeNotifier([stub])
        backends = composite.backends
        assert len(backends) == 1
        assert backends[0] is stub
        # Mutating the returned list should not affect the composite
        backends.clear()
        assert len(composite.backends) == 1

    async def test_backend_returning_false(self) -> None:
        """Backend returning False (not raising) is reported correctly."""
        stub = _StubNotifier(success=False)
        composite = CompositeNotifier([stub])
        result = _make_result()

        outcomes = await composite.send_escalation(result)
        assert outcomes == [False]


class TestCreateNotifier:
    """create_notifier factory function."""

    def test_no_urls_empty_composite(self) -> None:
        """No URLs configured means no backends."""
        composite = create_notifier()
        assert len(composite.backends) == 0

    def test_discord_only(self) -> None:
        """Only Discord URL creates one backend."""
        composite = create_notifier(discord_webhook_url="https://discord.com/api/webhooks/test")
        assert len(composite.backends) == 1
        from sna.integrations.discord import DiscordNotifier
        assert isinstance(composite.backends[0], DiscordNotifier)

    def test_teams_only(self) -> None:
        """Only Teams URL creates one backend."""
        composite = create_notifier(teams_webhook_url="https://teams.microsoft.com/webhook/test")
        assert len(composite.backends) == 1
        from sna.integrations.teams import TeamsNotifier
        assert isinstance(composite.backends[0], TeamsNotifier)

    def test_both_configured(self) -> None:
        """Both URLs configured creates two backends."""
        composite = create_notifier(
            discord_webhook_url="https://discord.com/api/webhooks/test",
            teams_webhook_url="https://teams.microsoft.com/webhook/test",
        )
        assert len(composite.backends) == 2

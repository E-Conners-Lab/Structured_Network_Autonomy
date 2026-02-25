"""Tests for agent reputation scoring — C28.

Covers:
- Time decay math
- Each component individually
- Composite weighting
- Empty history = 0.0
- Lookback window
- compute_agent_reputation with DB
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import Agent, AuditLog, EASHistory, ExecutionLog
from sna.policy.reputation import (
    ReputationConfig,
    compute_agent_reputation,
    compute_eas_component,
    compute_execution_component,
    compute_verdict_component,
    time_decay_weight,
)


class TestTimeDecayWeight:
    def test_zero_age(self) -> None:
        now = datetime.now(UTC)
        assert time_decay_weight(now, now, 14.0) == pytest.approx(1.0)

    def test_one_half_life(self) -> None:
        now = datetime.now(UTC)
        event = now - timedelta(days=14)
        assert time_decay_weight(event, now, 14.0) == pytest.approx(0.5)

    def test_two_half_lives(self) -> None:
        now = datetime.now(UTC)
        event = now - timedelta(days=28)
        assert time_decay_weight(event, now, 14.0) == pytest.approx(0.25)

    def test_future_event(self) -> None:
        now = datetime.now(UTC)
        event = now + timedelta(days=1)
        assert time_decay_weight(event, now, 14.0) == 1.0

    def test_zero_half_life(self) -> None:
        now = datetime.now(UTC)
        event = now - timedelta(days=7)
        assert time_decay_weight(event, now, 0.0) == 1.0


class TestEASComponent:
    def test_empty_history(self) -> None:
        now = datetime.now(UTC)
        assert compute_eas_component([], now, 14.0) == 0.0

    def test_single_entry(self) -> None:
        now = datetime.now(UTC)
        data = [(0.8, now)]
        assert compute_eas_component(data, now, 14.0) == pytest.approx(0.8)

    def test_weighted_average(self) -> None:
        now = datetime.now(UTC)
        data = [
            (1.0, now),  # weight ~1.0
            (0.0, now - timedelta(days=14)),  # weight ~0.5
        ]
        result = compute_eas_component(data, now, 14.0)
        # weighted avg: (1.0*1.0 + 0.0*0.5) / (1.0 + 0.5) = 1.0/1.5 ≈ 0.667
        assert result == pytest.approx(1.0 / 1.5, abs=0.01)


class TestVerdictComponent:
    def test_empty_verdicts(self) -> None:
        now = datetime.now(UTC)
        assert compute_verdict_component([], now, 14.0) == 0.0

    def test_all_permits(self) -> None:
        now = datetime.now(UTC)
        data = [("PERMIT", now - timedelta(hours=i)) for i in range(5)]
        assert compute_verdict_component(data, now, 14.0) == pytest.approx(1.0, abs=0.01)

    def test_all_blocks(self) -> None:
        now = datetime.now(UTC)
        data = [("BLOCK", now - timedelta(hours=i)) for i in range(5)]
        assert compute_verdict_component(data, now, 14.0) == pytest.approx(0.0, abs=0.01)

    def test_mixed(self) -> None:
        now = datetime.now(UTC)
        data = [
            ("PERMIT", now),  # 1.0
            ("ESCALATE", now),  # 0.5
            ("BLOCK", now),  # 0.0
        ]
        result = compute_verdict_component(data, now, 14.0)
        assert result == pytest.approx(0.5, abs=0.01)


class TestExecutionComponent:
    def test_empty_executions(self) -> None:
        now = datetime.now(UTC)
        assert compute_execution_component([], now, 14.0) == 0.0

    def test_all_success(self) -> None:
        now = datetime.now(UTC)
        data = [(True, now - timedelta(hours=i)) for i in range(5)]
        assert compute_execution_component(data, now, 14.0) == pytest.approx(1.0, abs=0.01)

    def test_all_failure(self) -> None:
        now = datetime.now(UTC)
        data = [(False, now - timedelta(hours=i)) for i in range(5)]
        assert compute_execution_component(data, now, 14.0) == pytest.approx(0.0, abs=0.01)

    def test_mixed(self) -> None:
        now = datetime.now(UTC)
        data = [
            (True, now),
            (False, now),
        ]
        result = compute_execution_component(data, now, 14.0)
        assert result == pytest.approx(0.5, abs=0.01)


class TestCompositeScore:
    def test_default_weights_sum_to_one(self) -> None:
        config = ReputationConfig()
        assert config.eas_weight + config.verdict_weight + config.execution_weight == pytest.approx(1.0)


class TestComputeAgentReputation:
    @pytest.fixture
    def session_factory(self, async_engine) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(async_engine, expire_on_commit=False)

    async def test_empty_history_zero_score(self, session_factory) -> None:
        """Agent with no history has 0.0 composite score."""
        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-rep-empty",
                    api_key_hash="hash1",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()
                agent_id = agent.id

        result = await compute_agent_reputation(agent_id, session_factory)
        assert result.composite_score == 0.0
        assert result.eas_component == 0.0
        assert result.verdict_component == 0.0
        assert result.execution_component == 0.0

    async def test_with_verdict_history(self, session_factory) -> None:
        """Agent with verdict history gets a non-zero score."""
        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-rep-verdicts",
                    api_key_hash="hash2",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()
                agent_id = agent.id

                # Add some audit log entries
                for i in range(5):
                    entry = AuditLog(
                        tool_name="show_running_config",
                        device_count=1,
                        verdict="PERMIT",
                        risk_tier="tier_1_read",
                        confidence_score=0.9,
                        confidence_threshold=0.1,
                        reason="test",
                        eas_at_time=0.5,
                        agent_id=agent_id,
                    )
                    session.add(entry)

        result = await compute_agent_reputation(agent_id, session_factory)
        assert result.verdict_component > 0.0
        assert result.composite_score > 0.0

    async def test_with_eas_history(self, session_factory) -> None:
        """Agent with EAS history."""
        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-rep-eas",
                    api_key_hash="hash3",
                    eas=0.8,
                )
                session.add(agent)
                await session.flush()
                agent_id = agent.id

                entry = EASHistory(
                    eas_score=0.8,
                    previous_score=0.5,
                    change_reason="improvement",
                    source="auto_adjustment",
                    agent_id=agent_id,
                )
                session.add(entry)

        result = await compute_agent_reputation(agent_id, session_factory)
        assert result.eas_component > 0.0

    async def test_lookback_window(self, session_factory) -> None:
        """Events outside lookback window are excluded."""
        config = ReputationConfig(lookback_days=7)

        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="test-rep-lookback",
                    api_key_hash="hash4",
                    eas=0.5,
                )
                session.add(agent)
                await session.flush()
                agent_id = agent.id

                # Only add recent entry
                entry = AuditLog(
                    tool_name="ping",
                    device_count=0,
                    verdict="PERMIT",
                    risk_tier="tier_1_read",
                    confidence_score=0.9,
                    confidence_threshold=0.1,
                    reason="test",
                    eas_at_time=0.5,
                    agent_id=agent_id,
                )
                session.add(entry)

        result = await compute_agent_reputation(agent_id, session_factory, config)
        assert result.verdict_component > 0.0

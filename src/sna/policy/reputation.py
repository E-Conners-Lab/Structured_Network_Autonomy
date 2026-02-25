"""Agent reputation scoring — composite score from EAS history, verdicts, and executions.

Uses time-decayed weighting with configurable half-life.
Reputation feeds into dynamic confidence as history_factor.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import AuditLog, EASHistory, ExecutionLog


@dataclass
class ReputationConfig:
    """Configuration for reputation scoring."""

    eas_weight: float = 0.4
    verdict_weight: float = 0.35
    execution_weight: float = 0.25
    half_life_days: float = 14.0
    lookback_days: int = 90


@dataclass
class ReputationComponents:
    """Breakdown of an agent's reputation score."""

    eas_component: float = 0.0
    verdict_component: float = 0.0
    execution_component: float = 0.0
    composite_score: float = 0.0


def time_decay_weight(
    event_time: datetime,
    now: datetime,
    half_life_days: float,
) -> float:
    """Compute time-decay weight using exponential half-life.

    Weight = 2^(-age_days / half_life_days)

    Args:
        event_time: When the event occurred.
        now: Current time.
        half_life_days: Half-life in days.

    Returns:
        Float between 0.0 and 1.0.
    """
    if half_life_days <= 0:
        return 1.0

    # Normalize timezone awareness for subtraction
    if event_time.tzinfo is None and now.tzinfo is not None:
        event_time = event_time.replace(tzinfo=UTC)
    elif event_time.tzinfo is not None and now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    age = now - event_time
    age_days = age.total_seconds() / 86400.0
    if age_days < 0:
        return 1.0

    return math.pow(2.0, -age_days / half_life_days)


def compute_eas_component(
    eas_history: list[tuple[float, datetime]],
    now: datetime,
    half_life_days: float,
) -> float:
    """Compute EAS reputation component from time-decayed score history.

    Args:
        eas_history: List of (eas_score, timestamp) tuples.
        now: Current time.
        half_life_days: Half-life for time decay.

    Returns:
        Weighted average EAS score, or 0.0 if empty.
    """
    if not eas_history:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0

    for score, ts in eas_history:
        w = time_decay_weight(ts, now, half_life_days)
        weighted_sum += score * w
        total_weight += w

    if total_weight == 0.0:
        return 0.0

    return weighted_sum / total_weight


def compute_verdict_component(
    verdicts: list[tuple[str, datetime]],
    now: datetime,
    half_life_days: float,
) -> float:
    """Compute verdict reputation component.

    Verdict scoring: PERMIT=1.0, ESCALATE=0.5, BLOCK=0.0.

    Args:
        verdicts: List of (verdict_string, timestamp) tuples.
        now: Current time.
        half_life_days: Half-life for time decay.

    Returns:
        Weighted average verdict score, or 0.0 if empty.
    """
    if not verdicts:
        return 0.0

    verdict_scores = {"PERMIT": 1.0, "ESCALATE": 0.5, "BLOCK": 0.0}

    total_weight = 0.0
    weighted_sum = 0.0

    for verdict_str, ts in verdicts:
        score = verdict_scores.get(verdict_str, 0.0)
        w = time_decay_weight(ts, now, half_life_days)
        weighted_sum += score * w
        total_weight += w

    if total_weight == 0.0:
        return 0.0

    return weighted_sum / total_weight


def compute_execution_component(
    executions: list[tuple[bool, datetime]],
    now: datetime,
    half_life_days: float,
) -> float:
    """Compute execution reputation component from success/failure history.

    Args:
        executions: List of (success_bool, timestamp) tuples.
        now: Current time.
        half_life_days: Half-life for time decay.

    Returns:
        Weighted average success rate, or 0.0 if empty.
    """
    if not executions:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0

    for success, ts in executions:
        w = time_decay_weight(ts, now, half_life_days)
        weighted_sum += (1.0 if success else 0.0) * w
        total_weight += w

    if total_weight == 0.0:
        return 0.0

    return weighted_sum / total_weight


async def compute_agent_reputation(
    agent_id: int,
    session_factory: async_sessionmaker[AsyncSession],
    config: ReputationConfig | None = None,
) -> ReputationComponents:
    """Compute composite agent reputation score from database history.

    Args:
        agent_id: The database ID of the agent.
        session_factory: Async session factory.
        config: Reputation configuration (uses defaults if None).

    Returns:
        ReputationComponents with individual and composite scores.
    """
    if config is None:
        config = ReputationConfig()

    now = datetime.now(UTC)
    cutoff = now - timedelta(days=config.lookback_days)

    async with session_factory() as session:
        # EAS history
        eas_result = await session.execute(
            select(EASHistory.eas_score, EASHistory.timestamp)
            .where(
                EASHistory.agent_id == agent_id,
                EASHistory.timestamp >= cutoff,
            )
            .order_by(EASHistory.timestamp.desc())
        )
        eas_rows = eas_result.all()

        # Verdict history
        verdict_result = await session.execute(
            select(AuditLog.verdict, AuditLog.timestamp)
            .where(
                AuditLog.agent_id == agent_id,
                AuditLog.timestamp >= cutoff,
            )
            .order_by(AuditLog.timestamp.desc())
        )
        verdict_rows = verdict_result.all()

        # Execution history (via audit_log_id join)
        exec_result = await session.execute(
            select(ExecutionLog.success, ExecutionLog.timestamp)
            .where(
                ExecutionLog.audit_log_id.in_(
                    select(AuditLog.id).where(
                        AuditLog.agent_id == agent_id,
                        AuditLog.timestamp >= cutoff,
                    )
                ),
            )
            .order_by(ExecutionLog.timestamp.desc())
        )
        exec_rows = exec_result.all()

    eas_data = [(float(row[0]), row[1]) for row in eas_rows]
    verdict_data = [(row[0], row[1]) for row in verdict_rows]
    exec_data = [(bool(row[0]), row[1]) for row in exec_rows]

    eas_comp = compute_eas_component(eas_data, now, config.half_life_days)
    verdict_comp = compute_verdict_component(verdict_data, now, config.half_life_days)
    exec_comp = compute_execution_component(exec_data, now, config.half_life_days)

    composite = (
        config.eas_weight * eas_comp
        + config.verdict_weight * verdict_comp
        + config.execution_weight * exec_comp
    )

    return ReputationComponents(
        eas_component=eas_comp,
        verdict_component=verdict_comp,
        execution_component=exec_comp,
        composite_score=composite,
    )

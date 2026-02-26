"""GET /timeline — unified activity feed merging all event sources."""

from __future__ import annotations

import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_api_key
from sna.api.dependencies import get_session_factory
from sna.api.rate_limit import limiter
from sna.api.schemas import PaginatedResponse, PaginationParams, TimelineEventResponse
from sna.db.models import AuditLog, EASHistory, EscalationRecord, ExecutionLog, PolicyVersion

router = APIRouter()

# ---------------------------------------------------------------------------
# Event type constants
# ---------------------------------------------------------------------------

EVENT_POLICY_DECISION = "policy_decision"
EVENT_ESCALATION_CREATED = "escalation_created"
EVENT_ESCALATION_RESOLVED = "escalation_resolved"
EVENT_DEVICE_EXECUTION = "device_execution"
EVENT_EAS_CHANGE = "eas_change"
EVENT_POLICY_CHANGE = "policy_change"

ALL_EVENT_TYPES = {
    EVENT_POLICY_DECISION,
    EVENT_ESCALATION_CREATED,
    EVENT_ESCALATION_RESOLVED,
    EVENT_DEVICE_EXECUTION,
    EVENT_EAS_CHANGE,
    EVENT_POLICY_CHANGE,
}

# ---------------------------------------------------------------------------
# Fetch helpers — each returns list[TimelineEventResponse]
# ---------------------------------------------------------------------------


async def _fetch_audit_logs(
    session: AsyncSession,
    *,
    tool_name: str | None,
    device: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())
    if tool_name:
        stmt = stmt.where(AuditLog.tool_name == tool_name)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        targets = r.device_targets or []
        if device and device not in targets:
            continue
        confidence_pct = f"{r.confidence_score * 100:.0f}%"
        summary = f"{r.verdict} {r.tool_name} — {r.risk_tier}, {confidence_pct}"
        events.append(TimelineEventResponse(
            id=r.external_id,
            timestamp=r.timestamp,
            event_type=EVENT_POLICY_DECISION,
            summary=summary,
            tool_name=r.tool_name,
            verdict=r.verdict,
            risk_tier=r.risk_tier,
            devices=targets,
            details={"reason": r.reason, "confidence": r.confidence_score, "eas": r.eas_at_time},
        ))
    return events


async def _fetch_escalations_created(
    session: AsyncSession,
    *,
    tool_name: str | None,
    device: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = select(EscalationRecord).order_by(EscalationRecord.created_at.desc())
    if tool_name:
        stmt = stmt.where(EscalationRecord.tool_name == tool_name)
    if since:
        stmt = stmt.where(EscalationRecord.created_at >= since)
    if until:
        stmt = stmt.where(EscalationRecord.created_at <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        targets = r.device_targets or []
        if device and device not in targets:
            continue
        summary = f"Escalation created for {r.tool_name} — {r.risk_tier}"
        events.append(TimelineEventResponse(
            id=r.external_id,
            timestamp=r.created_at,
            event_type=EVENT_ESCALATION_CREATED,
            summary=summary,
            tool_name=r.tool_name,
            risk_tier=r.risk_tier,
            devices=targets,
            details={"reason": r.reason, "status": r.status, "confidence": r.confidence_score},
        ))
    return events


async def _fetch_escalations_resolved(
    session: AsyncSession,
    *,
    tool_name: str | None,
    device: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = (
        select(EscalationRecord)
        .where(EscalationRecord.decided_at.is_not(None))
        .order_by(EscalationRecord.decided_at.desc())
    )
    if tool_name:
        stmt = stmt.where(EscalationRecord.tool_name == tool_name)
    if since:
        stmt = stmt.where(EscalationRecord.decided_at >= since)
    if until:
        stmt = stmt.where(EscalationRecord.decided_at <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        targets = r.device_targets or []
        if device and device not in targets:
            continue
        decision = r.status.lower()
        decider = r.decided_by or "unknown"
        summary = f"Escalation {decision} for {r.tool_name} by {decider}"
        events.append(TimelineEventResponse(
            id=f"{r.external_id}-resolved",
            timestamp=r.decided_at,
            event_type=EVENT_ESCALATION_RESOLVED,
            summary=summary,
            tool_name=r.tool_name,
            risk_tier=r.risk_tier,
            devices=targets,
            details={"decision": r.status, "decided_by": r.decided_by, "reason": r.decision_reason},
        ))
    return events


async def _fetch_executions(
    session: AsyncSession,
    *,
    tool_name: str | None,
    device: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = select(ExecutionLog).order_by(ExecutionLog.timestamp.desc())
    if tool_name:
        stmt = stmt.where(ExecutionLog.tool_name == tool_name)
    if device:
        stmt = stmt.where(ExecutionLog.device_target == device)
    if since:
        stmt = stmt.where(ExecutionLog.timestamp >= since)
    if until:
        stmt = stmt.where(ExecutionLog.timestamp <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        status = "success" if r.success else "failure"
        summary = f"Executed {r.tool_name} on {r.device_target} — {status}"
        events.append(TimelineEventResponse(
            id=r.external_id,
            timestamp=r.timestamp,
            event_type=EVENT_DEVICE_EXECUTION,
            summary=summary,
            tool_name=r.tool_name,
            success=r.success,
            device=r.device_target,
            devices=[r.device_target],
            details={"command": r.command_sent, "output": r.output, "error": r.error, "duration": r.duration_seconds},
        ))
    return events


async def _fetch_eas_changes(
    session: AsyncSession,
    *,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = select(EASHistory).order_by(EASHistory.timestamp.desc())
    if since:
        stmt = stmt.where(EASHistory.timestamp >= since)
    if until:
        stmt = stmt.where(EASHistory.timestamp <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        prev_pct = f"{r.previous_score * 100:.0f}%"
        new_pct = f"{r.eas_score * 100:.0f}%"
        summary = f"EAS {prev_pct} → {new_pct} ({r.source})"
        events.append(TimelineEventResponse(
            id=r.external_id,
            timestamp=r.timestamp,
            event_type=EVENT_EAS_CHANGE,
            summary=summary,
            details={"previous": r.previous_score, "new": r.eas_score, "reason": r.change_reason, "source": r.source},
        ))
    return events


async def _fetch_policy_changes(
    session: AsyncSession,
    *,
    since: datetime | None,
    until: datetime | None,
) -> list[TimelineEventResponse]:
    stmt = select(PolicyVersion).order_by(PolicyVersion.created_at.desc())
    if since:
        stmt = stmt.where(PolicyVersion.created_at >= since)
    if until:
        stmt = stmt.where(PolicyVersion.created_at <= until)
    result = await session.execute(stmt)
    records = result.scalars().all()

    events = []
    for r in records:
        summary = f"Policy updated to {r.version_string} by {r.created_by}"
        events.append(TimelineEventResponse(
            id=r.external_id,
            timestamp=r.created_at,
            event_type=EVENT_POLICY_CHANGE,
            summary=summary,
            details={"version": r.version_string, "hash": r.policy_hash, "diff": r.diff_text},
        ))
    return events


# ---------------------------------------------------------------------------
# Count helpers — each returns int
# ---------------------------------------------------------------------------


async def _count_audit_logs(
    session: AsyncSession,
    *,
    tool_name: str | None,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(AuditLog.id))
    if tool_name:
        stmt = stmt.where(AuditLog.tool_name == tool_name)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


async def _count_escalations_created(
    session: AsyncSession,
    *,
    tool_name: str | None,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(EscalationRecord.id))
    if tool_name:
        stmt = stmt.where(EscalationRecord.tool_name == tool_name)
    if since:
        stmt = stmt.where(EscalationRecord.created_at >= since)
    if until:
        stmt = stmt.where(EscalationRecord.created_at <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


async def _count_escalations_resolved(
    session: AsyncSession,
    *,
    tool_name: str | None,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(EscalationRecord.id)).where(EscalationRecord.decided_at.is_not(None))
    if tool_name:
        stmt = stmt.where(EscalationRecord.tool_name == tool_name)
    if since:
        stmt = stmt.where(EscalationRecord.decided_at >= since)
    if until:
        stmt = stmt.where(EscalationRecord.decided_at <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


async def _count_executions(
    session: AsyncSession,
    *,
    tool_name: str | None,
    device: str | None,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(ExecutionLog.id))
    if tool_name:
        stmt = stmt.where(ExecutionLog.tool_name == tool_name)
    if device:
        stmt = stmt.where(ExecutionLog.device_target == device)
    if since:
        stmt = stmt.where(ExecutionLog.timestamp >= since)
    if until:
        stmt = stmt.where(ExecutionLog.timestamp <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


async def _count_eas_changes(
    session: AsyncSession,
    *,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(EASHistory.id))
    if since:
        stmt = stmt.where(EASHistory.timestamp >= since)
    if until:
        stmt = stmt.where(EASHistory.timestamp <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


async def _count_policy_changes(
    session: AsyncSession,
    *,
    since: datetime | None,
    until: datetime | None,
) -> int:
    stmt = select(func.count(PolicyVersion.id))
    if since:
        stmt = stmt.where(PolicyVersion.created_at >= since)
    if until:
        stmt = stmt.where(PolicyVersion.created_at <= until)
    result = await session.execute(stmt)
    return result.scalar() or 0


# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------


@router.get("/timeline", response_model=PaginatedResponse[TimelineEventResponse])
@limiter.limit("30/minute")
async def get_timeline(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    event_types: str | None = Query(default=None, description="Comma-separated event types to include"),
    tool_name: str | None = Query(default=None, description="Filter by tool name"),
    device: str | None = Query(default=None, description="Filter by device name"),
    since: datetime | None = Query(default=None, description="Start of time window (ISO 8601)"),
    until: datetime | None = Query(default=None, description="End of time window (ISO 8601)"),
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[TimelineEventResponse]:
    """Unified activity timeline merging all event sources.

    Returns a paginated, reverse-chronological feed of policy decisions,
    escalations, executions, EAS changes, and policy updates.
    """
    params = PaginationParams(page=page, page_size=page_size)

    # Parse requested event types
    if event_types:
        requested = {t.strip() for t in event_types.split(",")} & ALL_EVENT_TYPES
    else:
        requested = ALL_EVENT_TYPES

    filter_kw = dict(tool_name=tool_name, device=device, since=since, until=until)
    time_kw = dict(since=since, until=until)

    async with session_factory() as session:
        # Build parallel fetch + count tasks based on requested types
        fetch_tasks: list[asyncio.Task] = []
        count_tasks: list[asyncio.Task] = []

        if EVENT_POLICY_DECISION in requested:
            fetch_tasks.append(_fetch_audit_logs(session, **filter_kw))
            count_tasks.append(_count_audit_logs(session, tool_name=tool_name, **time_kw))

        if EVENT_ESCALATION_CREATED in requested:
            fetch_tasks.append(_fetch_escalations_created(session, **filter_kw))
            count_tasks.append(_count_escalations_created(session, tool_name=tool_name, **time_kw))

        if EVENT_ESCALATION_RESOLVED in requested:
            fetch_tasks.append(_fetch_escalations_resolved(session, **filter_kw))
            count_tasks.append(_count_escalations_resolved(session, tool_name=tool_name, **time_kw))

        if EVENT_DEVICE_EXECUTION in requested:
            fetch_tasks.append(_fetch_executions(session, **filter_kw))
            count_tasks.append(_count_executions(session, tool_name=tool_name, device=device, **time_kw))

        if EVENT_EAS_CHANGE in requested:
            fetch_tasks.append(_fetch_eas_changes(session, **time_kw))
            count_tasks.append(_count_eas_changes(session, **time_kw))

        if EVENT_POLICY_CHANGE in requested:
            fetch_tasks.append(_fetch_policy_changes(session, **time_kw))
            count_tasks.append(_count_policy_changes(session, **time_kw))

        # Run all fetches and counts in parallel
        all_results = await asyncio.gather(*fetch_tasks, *count_tasks)

        n_fetches = len(fetch_tasks)
        event_lists = all_results[:n_fetches]
        count_values = all_results[n_fetches:]

    # Merge, sort by timestamp desc, paginate
    all_events: list[TimelineEventResponse] = []
    for event_list in event_lists:
        all_events.extend(event_list)
    all_events.sort(key=lambda e: e.timestamp, reverse=True)

    # Device filter may reduce counts from SQL — use actual merged length for accuracy
    total = len(all_events)
    offset = (params.page - 1) * params.page_size
    page_items = all_events[offset : offset + params.page_size]

    return PaginatedResponse.create(
        items=page_items,
        total=total,
        page=params.page,
        page_size=params.page_size,
    )

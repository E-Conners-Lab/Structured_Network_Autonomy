"""GET /reports/compliance — compliance summary over a time window."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_api_key
from sna.api.dependencies import get_engine, get_session_factory
from sna.db.models import AuditLog
from sna.policy.engine import PolicyEngine

router = APIRouter()


class ComplianceReport(BaseModel):
    """Compliance summary over a time window."""

    time_window_hours: int
    total_evaluations: int
    permit_count: int
    escalate_count: int
    block_count: int
    top_escalated_tools: list[dict[str, object]]
    current_eas: float


@router.get("/reports/compliance", response_model=ComplianceReport)
async def compliance_report(
    request: Request,
    hours: int = Query(default=24, ge=1, le=720),
    _api_key: str = Depends(require_api_key),
    engine: PolicyEngine = Depends(get_engine),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> ComplianceReport:
    """Get compliance summary for the specified time window."""
    cutoff = datetime.now(UTC) - timedelta(hours=hours)

    async with session_factory() as session:
        # Verdict counts
        counts = await session.execute(
            select(
                func.count(AuditLog.id).label("total"),
                func.sum(case((AuditLog.verdict == "PERMIT", 1), else_=0)).label("permits"),
                func.sum(case((AuditLog.verdict == "ESCALATE", 1), else_=0)).label("escalates"),
                func.sum(case((AuditLog.verdict == "BLOCK", 1), else_=0)).label("blocks"),
            ).where(AuditLog.timestamp >= cutoff)
        )
        row = counts.one()
        total = row.total or 0
        permits = row.permits or 0
        escalates = row.escalates or 0
        blocks = row.blocks or 0

        # Top escalated tools
        top_tools = await session.execute(
            select(
                AuditLog.tool_name,
                func.count(AuditLog.id).label("count"),
            )
            .where(AuditLog.verdict == "ESCALATE")
            .where(AuditLog.timestamp >= cutoff)
            .group_by(AuditLog.tool_name)
            .order_by(func.count(AuditLog.id).desc())
            .limit(10)
        )
        top_escalated = [
            {"tool_name": r.tool_name, "count": r.count}
            for r in top_tools
        ]

    return ComplianceReport(
        time_window_hours=hours,
        total_evaluations=total,
        permit_count=permits,
        escalate_count=escalates,
        block_count=blocks,
        top_escalated_tools=top_escalated,
        current_eas=engine.get_eas(),
    )

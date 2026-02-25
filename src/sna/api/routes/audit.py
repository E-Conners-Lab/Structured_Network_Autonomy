"""GET /audit — paginated audit log."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_api_key
from sna.api.dependencies import get_session_factory
from sna.api.schemas import AuditEntryResponse, PaginatedResponse, PaginationParams
from sna.db.models import AuditLog

router = APIRouter()


@router.get("/audit", response_model=PaginatedResponse[AuditEntryResponse])
async def list_audit_log(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[AuditEntryResponse]:
    """Retrieve the paginated audit log. Most recent entries first."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        count_result = await session.execute(
            select(func.count(AuditLog.id))
        )
        total = count_result.scalar() or 0

        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(AuditLog)
            .order_by(AuditLog.timestamp.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        records = result.scalars().all()

    items = [
        AuditEntryResponse(
            external_id=r.external_id,
            timestamp=r.timestamp,
            tool_name=r.tool_name,
            verdict=r.verdict,
            risk_tier=r.risk_tier,
            confidence_score=r.confidence_score,
            confidence_threshold=r.confidence_threshold,
            device_count=r.device_count,
            reason=r.reason,
            requires_audit=r.requires_audit,
            requires_senior_approval=r.requires_senior_approval,
            eas_at_time=r.eas_at_time,
        )
        for r in records
    ]

    return PaginatedResponse.create(
        items=items,
        total=total,
        page=params.page,
        page_size=params.page_size,
    )

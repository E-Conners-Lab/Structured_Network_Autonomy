"""POST /escalation/{id}/decision and GET /escalation/pending."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_admin_key, require_api_key
from sna.api.dependencies import get_session_factory
from sna.api.rate_limit import limiter
from sna.api.schemas import (
    EscalationDecisionRequest,
    EscalationDecisionResponse,
    EscalationResponse,
    PaginatedResponse,
    PaginationParams,
)
from sna.db.models import EscalationRecord, EscalationStatus

router = APIRouter()


@router.post(
    "/escalation/{escalation_id}/decision",
    response_model=EscalationDecisionResponse,
)
@limiter.limit("20/minute")
async def decide_escalation(
    request: Request,
    escalation_id: UUID,
    body: EscalationDecisionRequest,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> EscalationDecisionResponse:
    """Approve or reject a pending escalation. Requires admin API key."""
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                select(EscalationRecord).where(
                    EscalationRecord.external_id == str(escalation_id)
                )
            )
            escalation = result.scalar_one_or_none()

            if escalation is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Escalation not found",
                )

            if escalation.status != EscalationStatus.PENDING.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Escalation already resolved: {escalation.status}",
                )

            now = datetime.now(UTC)
            escalation.status = body.decision
            escalation.decided_by = body.decided_by
            escalation.decided_at = now
            escalation.decision_reason = body.reason

    return EscalationDecisionResponse(
        external_id=escalation_id,
        status=body.decision,
        decided_by=body.decided_by,
        decided_at=now,
    )


@router.get("/escalation/pending", response_model=PaginatedResponse[EscalationResponse])
async def list_pending_escalations(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[EscalationResponse]:
    """List all pending escalations with pagination."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        # Count total pending
        count_result = await session.execute(
            select(func.count(EscalationRecord.id)).where(
                EscalationRecord.status == EscalationStatus.PENDING.value
            )
        )
        total = count_result.scalar() or 0

        # Fetch page
        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(EscalationRecord)
            .where(EscalationRecord.status == EscalationStatus.PENDING.value)
            .order_by(EscalationRecord.created_at.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        records = result.scalars().all()

    items = [
        EscalationResponse(
            external_id=UUID(r.external_id),
            tool_name=r.tool_name,
            parameters=r.parameters,
            risk_tier=r.risk_tier,
            confidence_score=r.confidence_score,
            reason=r.reason,
            device_targets=r.device_targets,
            device_count=r.device_count,
            status=r.status,
            requires_senior_approval=r.requires_senior_approval,
            decided_by=r.decided_by,
            decided_at=r.decided_at,
            decision_reason=r.decision_reason,
            created_at=r.created_at,
        )
        for r in records
    ]

    return PaginatedResponse.create(
        items=items,
        total=total,
        page=params.page,
        page_size=params.page_size,
    )

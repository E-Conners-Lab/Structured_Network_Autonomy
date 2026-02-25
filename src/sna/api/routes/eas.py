"""EAS management API — view and adjust the Earned Autonomy Score."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_admin_key, require_api_key
from sna.api.dependencies import get_engine, get_session_factory
from sna.api.schemas import PaginatedResponse, PaginationParams
from sna.db.models import EASHistory
from sna.policy.engine import PolicyEngine

router = APIRouter()


class EASResponse(BaseModel):
    """Current EAS score response."""

    eas: float
    timestamp: datetime


class EASAdjustRequest(BaseModel):
    """POST /eas request body — manual EAS adjustment."""

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=500)


class EASHistoryResponse(BaseModel):
    """Single EAS history entry."""

    external_id: str
    timestamp: datetime
    eas_score: float
    previous_score: float
    change_reason: str
    source: str


@router.get("/eas", response_model=EASResponse)
async def get_eas(
    request: Request,
    _api_key: str = Depends(require_api_key),
    engine: PolicyEngine = Depends(get_engine),
) -> EASResponse:
    """Get the current Earned Autonomy Score."""
    return EASResponse(
        eas=engine.get_eas(),
        timestamp=datetime.now(UTC),
    )


@router.post("/eas", response_model=EASResponse)
async def adjust_eas(
    request: Request,
    body: EASAdjustRequest,
    _admin_key: str = Depends(require_admin_key),
    engine: PolicyEngine = Depends(get_engine),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> EASResponse:
    """Manually adjust the EAS. Requires admin API key."""
    previous = engine.get_eas()
    engine.set_eas(body.score)

    # Record the change
    async with session_factory() as session:
        async with session.begin():
            history = EASHistory(
                eas_score=body.score,
                previous_score=previous,
                change_reason=body.reason,
                source="admin_api",
            )
            session.add(history)

    return EASResponse(
        eas=engine.get_eas(),
        timestamp=datetime.now(UTC),
    )


@router.get("/eas/history", response_model=PaginatedResponse[EASHistoryResponse])
async def get_eas_history(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[EASHistoryResponse]:
    """Get paginated EAS change history."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        count_result = await session.execute(
            select(func.count(EASHistory.id))
        )
        total = count_result.scalar() or 0

        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(EASHistory)
            .order_by(EASHistory.timestamp.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        records = result.scalars().all()

    items = [
        EASHistoryResponse(
            external_id=r.external_id,
            timestamp=r.timestamp,
            eas_score=r.eas_score,
            previous_score=r.previous_score,
            change_reason=r.change_reason,
            source=r.source,
        )
        for r in records
    ]

    return PaginatedResponse.create(
        items=items,
        total=total,
        page=params.page,
        page_size=params.page_size,
    )

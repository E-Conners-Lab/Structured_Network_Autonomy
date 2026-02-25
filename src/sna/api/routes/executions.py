"""GET /audit/executions — paginated execution audit log."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_api_key
from sna.api.dependencies import get_session_factory
from sna.api.schemas import ExecutionLogResponse, PaginatedResponse, PaginationParams
from sna.db.models import ExecutionLog

router = APIRouter()


@router.get(
    "/audit/executions",
    response_model=PaginatedResponse[ExecutionLogResponse],
)
async def list_execution_log(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[ExecutionLogResponse]:
    """Retrieve the paginated execution audit log. Most recent entries first."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        count_result = await session.execute(
            select(func.count(ExecutionLog.id))
        )
        total = count_result.scalar() or 0

        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(ExecutionLog)
            .order_by(ExecutionLog.timestamp.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        records = result.scalars().all()

    items = [
        ExecutionLogResponse(
            external_id=r.external_id,
            timestamp=r.timestamp,
            tool_name=r.tool_name,
            device_target=r.device_target,
            command_sent=r.command_sent,
            output=r.output,
            success=r.success,
            duration_seconds=r.duration_seconds,
            error=r.error,
        )
        for r in records
    ]

    return PaginatedResponse.create(
        items=items,
        total=total,
        page=params.page,
        page_size=params.page_size,
    )

"""GET /health — engine health. Minimal response unauthenticated, full details with API key."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import optional_api_key
from sna.api.dependencies import get_engine, get_session_factory
from sna.api.schemas import HealthFullResponse, HealthMinimalResponse
from sna.db.models import AuditLog
from sna.policy.engine import PolicyEngine

router = APIRouter()


@router.get("/health")
async def health_check(
    request: Request,
    api_key: str | None = Depends(optional_api_key),
    engine: PolicyEngine = Depends(get_engine),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> HealthMinimalResponse | HealthFullResponse:
    """Check engine health.

    Without authentication: returns minimal {"status": "healthy"}.
    With valid API key: returns full details including EAS, policy status,
    DB connectivity, and last audit timestamp.
    """
    if api_key is None:
        return HealthMinimalResponse(status="healthy")

    # Check DB connectivity and get last audit write
    db_connected = True
    last_audit_write = None
    try:
        async with session_factory() as session:
            result = await session.execute(
                select(AuditLog.timestamp)
                .order_by(AuditLog.timestamp.desc())
                .limit(1)
            )
            row = result.scalar_one_or_none()
            if row is not None:
                last_audit_write = row
    except Exception:
        db_connected = False

    return HealthFullResponse(
        status="healthy" if db_connected else "degraded",
        eas=engine.get_eas(),
        policy_loaded=True,
        policy_version=engine.policy.version,
        db_connected=db_connected,
        last_audit_write=last_audit_write,
    )

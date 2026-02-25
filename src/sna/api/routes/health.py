"""Health check endpoints — liveness, readiness, and full health.

- GET /health/live — fast liveness probe (no auth, no DB)
- GET /health/ready — readiness probe (checks DB connectivity)
- GET /health — full health with optional auth
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import optional_api_key
from sna.api.dependencies import get_engine, get_session_factory
from sna.api.schemas import HealthFullResponse, HealthMinimalResponse
from sna.db.models import AuditLog
from sna.policy.engine import PolicyEngine

router = APIRouter()


class LivenessResponse(BaseModel):
    """Liveness probe response — no sensitive data."""

    status: str


class ReadinessResponse(BaseModel):
    """Readiness probe response — no sensitive data."""

    status: str
    db_ready: bool


@router.get("/health/live", response_model=LivenessResponse)
async def liveness_probe() -> LivenessResponse:
    """Fast liveness probe — is the process running?

    No auth required. No DB check. Returns immediately.
    No sensitive data exposed.
    """
    return LivenessResponse(status="alive")


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness_probe(
    request: Request,
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> ReadinessResponse:
    """Readiness probe — can the service handle requests?

    No auth required. Checks DB connectivity.
    No sensitive data (no hostnames, no URLs).
    """
    db_ready = True
    try:
        async with session_factory() as session:
            await session.execute(select(1))
    except Exception:
        db_ready = False

    return ReadinessResponse(
        status="ready" if db_ready else "not_ready",
        db_ready=db_ready,
    )


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
    No sensitive data (no DB hostnames, no NetBox URLs, no device counts).
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

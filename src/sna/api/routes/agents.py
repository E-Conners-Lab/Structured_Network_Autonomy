"""Agent registration and management API.

Agent registration, lifecycle management, and per-agent EAS tracking.
All admin actions require require_admin_key.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from uuid import UUID

import bcrypt
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_admin_key, require_api_key
from sna.api.dependencies import get_session_factory
from sna.api.schemas import PaginatedResponse, PaginationParams
from sna.api.schemas import ReputationResponse
from sna.db.models import Agent, AgentPolicyOverride, AgentStatus, EASHistory
from sna.policy.reputation import compute_agent_reputation

logger = structlog.get_logger()

router = APIRouter()


# --- Schemas ---


class AgentCreateRequest(BaseModel):
    """POST /agents request body."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=1000)


class AgentCreateResponse(BaseModel):
    """POST /agents response — includes the plaintext API key (shown once)."""

    external_id: str
    name: str
    api_key: str  # Shown once, never stored plaintext, never logged
    status: str
    eas: float


class AgentResponse(BaseModel):
    """Agent detail response (no API key)."""

    external_id: str
    name: str
    description: str
    status: str
    eas: float
    created_at: datetime
    last_seen: datetime | None = None


class AgentStatusResponse(BaseModel):
    """Response after status change."""

    external_id: str
    status: str


class AgentActivityResponse(BaseModel):
    """Agent activity summary."""

    external_id: str
    name: str
    eas: float
    status: str


# --- Endpoints ---


@router.post("/agents", response_model=AgentCreateResponse, status_code=201)
async def register_agent(
    request: Request,
    body: AgentCreateRequest,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentCreateResponse:
    """Register a new AI agent. Returns the API key once — store it securely."""
    # Generate API key
    api_key = secrets.token_urlsafe(32)
    key_hash = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()

    async with session_factory() as session:
        async with session.begin():
            # Check for duplicate name
            existing = await session.execute(
                select(Agent).where(Agent.name == body.name)
            )
            if existing.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Agent with name '{body.name}' already exists",
                )

            agent = Agent(
                name=body.name,
                description=body.description,
                api_key_hash=key_hash,
            )
            session.add(agent)
            await session.flush()

            return AgentCreateResponse(
                external_id=agent.external_id,
                name=agent.name,
                api_key=api_key,
                status=agent.status,
                eas=agent.eas,
            )


@router.get("/agents", response_model=PaginatedResponse[AgentResponse])
async def list_agents(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[AgentResponse]:
    """List all registered agents. Admin only."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        count_result = await session.execute(select(func.count(Agent.id)))
        total = count_result.scalar() or 0

        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(Agent)
            .order_by(Agent.created_at.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        agents = result.scalars().all()

    items = [
        AgentResponse(
            external_id=a.external_id,
            name=a.name,
            description=a.description,
            status=a.status,
            eas=a.eas,
            created_at=a.created_at,
            last_seen=a.last_seen,
        )
        for a in agents
    ]

    return PaginatedResponse.create(
        items=items, total=total, page=params.page, page_size=params.page_size,
    )


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    request: Request,
    agent_id: UUID,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentResponse:
    """Get agent details by ID."""
    async with session_factory() as session:
        result = await session.execute(
            select(Agent).where(Agent.external_id == str(agent_id))
        )
        agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(
        external_id=agent.external_id,
        name=agent.name,
        description=agent.description,
        status=agent.status,
        eas=agent.eas,
        created_at=agent.created_at,
        last_seen=agent.last_seen,
    )


@router.post("/agents/{agent_id}/suspend", response_model=AgentStatusResponse)
async def suspend_agent(
    request: Request,
    agent_id: UUID,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentStatusResponse:
    """Suspend an agent — all requests will be blocked."""
    return await _set_agent_status(agent_id, AgentStatus.SUSPENDED, session_factory)


@router.post("/agents/{agent_id}/activate", response_model=AgentStatusResponse)
async def activate_agent(
    request: Request,
    agent_id: UUID,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentStatusResponse:
    """Re-activate a suspended agent."""
    return await _set_agent_status(agent_id, AgentStatus.ACTIVE, session_factory)


@router.post("/agents/{agent_id}/revoke", response_model=AgentStatusResponse)
async def revoke_agent(
    request: Request,
    agent_id: UUID,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentStatusResponse:
    """Permanently revoke an agent — invalidates key hash."""
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                select(Agent).where(Agent.external_id == str(agent_id))
            )
            agent = result.scalar_one_or_none()
            if agent is None:
                raise HTTPException(status_code=404, detail="Agent not found")

            agent.status = AgentStatus.REVOKED.value
            agent.api_key_hash = "REVOKED"  # Invalidate hash

    return AgentStatusResponse(
        external_id=str(agent_id),
        status=AgentStatus.REVOKED.value,
    )


@router.get("/agents/{agent_id}/activity", response_model=AgentActivityResponse)
async def get_agent_activity(
    request: Request,
    agent_id: UUID,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> AgentActivityResponse:
    """Get agent activity summary."""
    async with session_factory() as session:
        result = await session.execute(
            select(Agent).where(Agent.external_id == str(agent_id))
        )
        agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentActivityResponse(
        external_id=agent.external_id,
        name=agent.name,
        eas=agent.eas,
        status=agent.status,
    )


# --- Override schemas ---


class OverrideCreateRequest(BaseModel):
    """POST /agents/{id}/overrides request body."""

    model_config = ConfigDict(extra="forbid")

    rule_type: str = Field(pattern="^(site|role|tag|tool)$")
    rule_json: dict = Field(default_factory=dict)
    priority: int = Field(default=0, ge=0, le=100)


class OverrideResponse(BaseModel):
    """Override entry in API responses."""

    external_id: str
    rule_type: str
    rule_json: dict
    priority: int
    is_active: bool
    created_at: datetime


# --- Override endpoints ---


@router.post("/agents/{agent_id}/overrides", response_model=OverrideResponse, status_code=201)
async def create_override(
    request: Request,
    agent_id: UUID,
    body: OverrideCreateRequest,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> OverrideResponse:
    """Create a policy override for an agent. Admin only."""
    async with session_factory() as session:
        async with session.begin():
            # Find agent
            result = await session.execute(
                select(Agent).where(Agent.external_id == str(agent_id))
            )
            agent = result.scalar_one_or_none()
            if agent is None:
                raise HTTPException(status_code=404, detail="Agent not found")

            override = AgentPolicyOverride(
                agent_id=agent.id,
                rule_type=body.rule_type,
                rule_json=body.rule_json,
                priority=body.priority,
            )
            session.add(override)
            await session.flush()

            return OverrideResponse(
                external_id=override.external_id,
                rule_type=override.rule_type,
                rule_json=override.rule_json,
                priority=override.priority,
                is_active=override.is_active,
                created_at=override.created_at,
            )


@router.get("/agents/{agent_id}/overrides", response_model=list[OverrideResponse])
async def list_overrides(
    request: Request,
    agent_id: UUID,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> list[OverrideResponse]:
    """List policy overrides for an agent."""
    async with session_factory() as session:
        # Find agent
        agent_result = await session.execute(
            select(Agent).where(Agent.external_id == str(agent_id))
        )
        agent = agent_result.scalar_one_or_none()
        if agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")

        result = await session.execute(
            select(AgentPolicyOverride)
            .where(AgentPolicyOverride.agent_id == agent.id)
            .order_by(AgentPolicyOverride.priority.desc())
        )
        overrides = result.scalars().all()

    return [
        OverrideResponse(
            external_id=o.external_id,
            rule_type=o.rule_type,
            rule_json=o.rule_json,
            priority=o.priority,
            is_active=o.is_active,
            created_at=o.created_at,
        )
        for o in overrides
    ]


@router.get("/agents/{agent_id}/reputation", response_model=ReputationResponse)
async def get_agent_reputation(
    request: Request,
    agent_id: UUID,
    _api_key: str = Depends(require_api_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> ReputationResponse:
    """Get agent reputation score breakdown."""
    async with session_factory() as session:
        result = await session.execute(
            select(Agent).where(Agent.external_id == str(agent_id))
        )
        agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    components = await compute_agent_reputation(agent.id, session_factory)

    return ReputationResponse(
        agent_id=agent_id,
        eas_component=components.eas_component,
        verdict_component=components.verdict_component,
        execution_component=components.execution_component,
        composite_score=components.composite_score,
    )


@router.delete("/agents/{agent_id}/overrides/{override_id}", status_code=200)
async def deactivate_override(
    request: Request,
    agent_id: UUID,
    override_id: UUID,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> dict:
    """Deactivate a policy override for an agent. Admin only."""
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                select(AgentPolicyOverride)
                .where(AgentPolicyOverride.external_id == str(override_id))
            )
            override = result.scalar_one_or_none()
            if override is None:
                raise HTTPException(status_code=404, detail="Override not found")

            override.is_active = False

    return {"status": "deactivated", "override_id": str(override_id)}


async def _set_agent_status(
    agent_id: UUID,
    new_status: AgentStatus,
    session_factory: async_sessionmaker[AsyncSession],
) -> AgentStatusResponse:
    """Set agent status."""
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                select(Agent).where(Agent.external_id == str(agent_id))
            )
            agent = result.scalar_one_or_none()
            if agent is None:
                raise HTTPException(status_code=404, detail="Agent not found")

            agent.status = new_status.value

    return AgentStatusResponse(
        external_id=str(agent_id),
        status=new_status.value,
    )

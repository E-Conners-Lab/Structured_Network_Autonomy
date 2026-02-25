"""Policy management routes — reload, versioning, and rollback.

POST /policy/reload — hot reload policy YAML (admin)
GET /policy/versions — paginated version history (admin)
GET /policy/current — current version info (api key)
POST /policy/rollback/{version_id} — rollback to a previous version (admin)
"""

from __future__ import annotations

from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.api.auth import require_admin_key, require_api_key
from sna.api.dependencies import get_engine, get_session_factory, get_settings
from sna.api.schemas import (
    PaginatedResponse,
    PaginationParams,
    PolicyCurrentResponse,
    PolicyReloadResponse,
    PolicyRollbackResponse,
    PolicyVersionResponse,
)
from sna.config import Settings
from sna.db.models import PolicyVersion
from sna.policy.engine import PolicyEngine
from sna.policy.loader import compute_policy_hash
from sna.policy.models import PolicyConfig

router = APIRouter()


@router.post("/policy/reload", response_model=PolicyReloadResponse)
async def reload_policy(
    request: Request,
    _admin_key: str = Depends(require_admin_key),
    engine: PolicyEngine = Depends(get_engine),
    settings: Settings = Depends(get_settings),
) -> PolicyReloadResponse:
    """Hot reload the policy YAML file.

    Loads the new policy, validates it, computes a diff against the
    current policy, persists a version record, and swaps the active policy.
    """
    new_policy, diff = await engine.reload(settings.policy_file_path)

    return PolicyReloadResponse(
        status="reloaded",
        version=new_policy.version,
        diff=diff,
    )


@router.get("/policy/versions", response_model=PaginatedResponse[PolicyVersionResponse])
async def list_policy_versions(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    _admin_key: str = Depends(require_admin_key),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PaginatedResponse[PolicyVersionResponse]:
    """List policy version history (most recent first). Admin only."""
    params = PaginationParams(page=page, page_size=page_size)

    async with session_factory() as session:
        count_result = await session.execute(select(func.count(PolicyVersion.id)))
        total = count_result.scalar() or 0

        offset = (params.page - 1) * params.page_size
        result = await session.execute(
            select(PolicyVersion)
            .order_by(PolicyVersion.created_at.desc())
            .offset(offset)
            .limit(params.page_size)
        )
        versions = result.scalars().all()

    items = [
        PolicyVersionResponse(
            external_id=UUID(v.external_id),
            version_string=v.version_string,
            policy_hash=v.policy_hash,
            diff_text=v.diff_text,
            created_at=v.created_at,
            created_by=v.created_by,
        )
        for v in versions
    ]

    return PaginatedResponse.create(
        items=items, total=total, page=params.page, page_size=params.page_size,
    )


@router.get("/policy/current", response_model=PolicyCurrentResponse)
async def get_current_policy(
    request: Request,
    _api_key: str = Depends(require_api_key),
    engine: PolicyEngine = Depends(get_engine),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PolicyCurrentResponse:
    """Get current policy version info."""
    # Try to get the latest version hash from DB
    policy_hash = None
    try:
        async with session_factory() as session:
            result = await session.execute(
                select(PolicyVersion)
                .order_by(PolicyVersion.created_at.desc())
                .limit(1)
            )
            latest = result.scalar_one_or_none()
            if latest:
                policy_hash = latest.policy_hash
    except Exception:
        pass

    return PolicyCurrentResponse(
        version=engine.policy.version,
        policy_hash=policy_hash,
    )


@router.post("/policy/rollback/{version_id}", response_model=PolicyRollbackResponse)
async def rollback_policy(
    request: Request,
    version_id: UUID,
    _admin_key: str = Depends(require_admin_key),
    engine: PolicyEngine = Depends(get_engine),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
) -> PolicyRollbackResponse:
    """Rollback to a previous policy version. Admin only.

    Creates a new version entry (rollback is versioned).
    """
    # Find the target version
    async with session_factory() as session:
        result = await session.execute(
            select(PolicyVersion).where(PolicyVersion.external_id == str(version_id))
        )
        target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(status_code=404, detail="Policy version not found")

    # Parse and validate the stored YAML
    data = yaml.safe_load(target.policy_yaml)
    if data is None:
        raise HTTPException(status_code=500, detail="Stored policy YAML is empty")

    new_policy = PolicyConfig(**data)

    # Persist as a new version (rollback is versioned)
    from sna.policy.loader import compute_policy_diff

    diff_text = compute_policy_diff(engine.policy, new_policy)

    await engine._persist_version(
        policy=new_policy,
        raw_yaml=target.policy_yaml,
        diff_text=diff_text,
        created_by=f"rollback_to_{version_id}",
    )

    # Swap the active policy
    engine._policy = new_policy

    return PolicyRollbackResponse(
        status="rolled_back",
        version=new_policy.version,
        rolled_back_to=version_id,
    )

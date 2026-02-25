"""POST /policy/reload — hot reload policy configuration (requires admin API key)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from sna.api.auth import require_admin_key
from sna.api.dependencies import get_engine, get_settings
from sna.api.schemas import PolicyReloadResponse
from sna.config import Settings
from sna.policy.engine import PolicyEngine

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
    current policy, and swaps the active policy. If the new policy
    is invalid, the current policy remains unchanged and an error
    is returned.
    """
    new_policy, diff = await engine.reload(settings.policy_file_path)

    return PolicyReloadResponse(
        status="reloaded",
        version=new_policy.version,
        diff=diff,
    )

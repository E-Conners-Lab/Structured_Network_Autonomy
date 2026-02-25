"""API key authentication — validates Authorization: Bearer <key> header.

Two-tier authentication:
1. Global keys: SNA_API_KEY (standard) and SNA_ADMIN_API_KEY (elevated)
   - Compared with secrets.compare_digest() (timing-safe)
2. Per-agent keys: bcrypt-hashed keys in the Agent table
   - Verified with bcrypt.checkpw() (constant-time)

Global key requests have no agent identity.
Agent key requests attach agent identity to request.state.agent.
"""

from __future__ import annotations

import secrets

import bcrypt
import structlog
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import Agent, AgentStatus

logger = structlog.get_logger()

bearer_scheme = HTTPBearer(auto_error=False)


async def _try_agent_auth(
    request: Request, token: str
) -> bool:
    """Try to authenticate as a per-agent key.

    If successful, attaches agent to request.state.agent.

    Returns:
        True if authenticated as agent, False if no match.

    Raises:
        HTTPException 403: If agent is suspended or revoked.
    """
    session_factory: async_sessionmaker[AsyncSession] | None = getattr(
        request.app.state, "session_factory", None
    )
    if session_factory is None:
        return False

    prefix = token[:8] if len(token) >= 8 else token

    async with session_factory() as session:
        # Fast path: look up by prefix index (O(1) instead of O(n) bcrypt)
        result = await session.execute(
            select(Agent).where(Agent.api_key_prefix == prefix)
        )
        agents = list(result.scalars().all())

        # Fallback: agents created before prefix migration have empty prefix
        if not agents:
            result = await session.execute(
                select(Agent).where(Agent.api_key_prefix == "")
            )
            agents = list(result.scalars().all())

    for agent in agents:
        if agent.api_key_hash == "REVOKED":
            continue
        try:
            if bcrypt.checkpw(token.encode(), agent.api_key_hash.encode()):
                if agent.status == AgentStatus.SUSPENDED.value:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Agent is suspended",
                    )
                if agent.status == AgentStatus.REVOKED.value:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Agent is revoked",
                    )
                request.state.agent = agent
                return True
        except HTTPException:
            raise
        except Exception:
            continue

    return False


async def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str:
    """Validate the request carries a valid API key (global or per-agent).

    Authentication flow:
    1. Try global API key (fast path, timing-safe)
    2. If no match, try per-agent bcrypt verification
    3. If agent found + ACTIVE, attach to request.state

    Returns:
        The validated API key string.

    Raises:
        HTTPException 401: If no credentials or invalid key.
        HTTPException 403: If agent is suspended/revoked.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )

    settings = request.app.state.settings

    # Fast path: global API key
    if secrets.compare_digest(credentials.credentials, settings.sna_api_key):
        return credentials.credentials

    # Slow path: per-agent key
    if await _try_agent_auth(request, credentials.credentials):
        return credentials.credentials

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


async def require_admin_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str:
    """Validate the request carries a valid admin API key.

    Only the global admin key works here — agents cannot perform admin actions.

    Returns:
        The validated admin key string.

    Raises:
        HTTPException 401: If no credentials provided.
        HTTPException 403: If key is not the admin key.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )

    settings = request.app.state.settings
    if not secrets.compare_digest(credentials.credentials, settings.sna_admin_api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return credentials.credentials


async def optional_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str | None:
    """Optionally validate an API key. Returns None if no credentials provided.

    Used for endpoints with tiered responses (e.g., /health returns minimal
    info without auth, full info with auth).

    Returns:
        The API key string if valid, None if no credentials.

    Raises:
        HTTPException 401: If credentials are present but invalid.
    """
    if credentials is None:
        return None

    settings = request.app.state.settings

    # Try global key first
    if secrets.compare_digest(credentials.credentials, settings.sna_api_key):
        return credentials.credentials

    # Try agent key
    if await _try_agent_auth(request, credentials.credentials):
        return credentials.credentials

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )

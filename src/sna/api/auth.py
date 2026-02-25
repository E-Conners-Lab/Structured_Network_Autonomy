"""API key authentication — validates Authorization: Bearer <key> header.

Two auth levels:
- require_api_key: validates against SNA_API_KEY (standard access)
- require_admin_key: validates against SNA_ADMIN_API_KEY (elevated, e.g. policy reload)
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)


async def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str:
    """Validate the request carries a valid API key.

    Compares the Bearer token against the configured SNA_API_KEY.

    Returns:
        The validated API key string.

    Raises:
        HTTPException 401: If no credentials or invalid key.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )

    settings = request.app.state.settings
    if credentials.credentials != settings.sna_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return credentials.credentials


async def require_admin_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str:
    """Validate the request carries a valid admin API key.

    Compares the Bearer token against the configured SNA_ADMIN_API_KEY.
    Used for elevated operations like policy reload.

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
    if credentials.credentials != settings.sna_admin_api_key:
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
    if credentials.credentials != settings.sna_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return credentials.credentials

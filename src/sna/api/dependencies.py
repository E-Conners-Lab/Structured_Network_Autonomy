"""FastAPI dependency injection — engine, database session, configuration.

All dependencies read from app.state, which is populated during lifespan startup.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.config import Settings
from sna.policy.engine import PolicyEngine


def get_engine(request: Request) -> PolicyEngine:
    """Get the PolicyEngine instance from app state."""
    return request.app.state.engine


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    """Get the async session factory from app state."""
    return request.app.state.session_factory


def get_settings(request: Request) -> Settings:
    """Get the Settings instance from app state."""
    return request.app.state.settings

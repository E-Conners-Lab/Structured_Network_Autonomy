"""Shared test fixtures for the SNA test suite.

Provides async test database (in-memory SQLite), sample policy, and mock EAS values.
"""

import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sna.db.models import Base

TESTS_DIR = Path(__file__).parent
PROJECT_ROOT = TESTS_DIR.parent
SAMPLE_POLICY_PATH = PROJECT_ROOT / "policies" / "default.yaml"


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def async_engine():
    """Create an in-memory SQLite async engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional database session that rolls back after each test."""
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with session_factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


@pytest.fixture
def sample_policy_path() -> Path:
    """Path to the default policy YAML for testing."""
    return SAMPLE_POLICY_PATH


@pytest.fixture
def mock_eas_score() -> float:
    """Default mock EAS score for testing — near-zero trust."""
    return 0.1

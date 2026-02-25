"""Shared fixtures for API route tests.

Provides:
- A configured FastAPI test app with in-memory SQLite
- An httpx AsyncClient pointed at the test app
- Pre-configured auth headers
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sna.api.app import create_app
from sna.config import Settings
from sna.db.models import Base
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy

TEST_API_KEY = "test-api-key-12345-abcdefghijklmnop"
TEST_ADMIN_KEY = "test-admin-key-67890-abcdefghijklm"
SAMPLE_POLICY = "policies/default.yaml"


@pytest.fixture
async def test_settings(tmp_path) -> Settings:
    """Create test Settings with in-memory SQLite and test API keys."""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        policy_file_path=SAMPLE_POLICY,
        sna_api_key=TEST_API_KEY,
        sna_admin_api_key=TEST_ADMIN_KEY,
        default_eas=0.1,
        log_level="WARNING",
        log_format="console",
        cors_allowed_origins="http://localhost:3000",
        rate_limit_evaluate=1000,
        rate_limit_escalation_decision=1000,
        rate_limit_policy_reload=1000,
    )


@pytest.fixture
async def test_app(test_settings: Settings) -> AsyncGenerator[object, None]:
    """Create a test FastAPI app with all dependencies initialized."""
    app = create_app(settings=test_settings)

    # Manually run lifespan startup
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    policy = await load_policy(test_settings.policy_file_path)
    policy_engine = PolicyEngine(
        policy=policy,
        session_factory=session_factory,
        initial_eas=test_settings.default_eas,
    )

    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.engine = policy_engine
    app.state.settings = test_settings

    yield app

    await engine.dispose()


@pytest.fixture
async def client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Provide an httpx AsyncClient for the test app."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Standard API key auth headers."""
    return {"Authorization": f"Bearer {TEST_API_KEY}"}


@pytest.fixture
def admin_headers() -> dict[str, str]:
    """Admin API key auth headers."""
    return {"Authorization": f"Bearer {TEST_ADMIN_KEY}"}

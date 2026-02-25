"""Tests for API key authentication with prefix-based lookup."""

from __future__ import annotations

import bcrypt
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.api.app import create_app
from sna.config import Settings
from sna.db.models import Agent, Base
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy

TEST_API_KEY = "auth-test-api-key-abcdefghijklmnop"
TEST_ADMIN_KEY = "auth-test-admin-key-abcdefghijklm"


@pytest.fixture
async def auth_app():
    """Create an app with agents for auth testing."""
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        policy_file_path="policies/default.yaml",
        sna_api_key=TEST_API_KEY,
        sna_admin_api_key=TEST_ADMIN_KEY,
        default_eas=0.1,
        log_level="WARNING",
        log_format="console",
        rate_limit_evaluate=1000,
        rate_limit_escalation_decision=1000,
        rate_limit_policy_reload=1000,
    )
    app = create_app(settings=settings)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    policy = await load_policy(settings.policy_file_path)
    policy_engine = PolicyEngine(
        policy=policy,
        session_factory=session_factory,
        initial_eas=settings.default_eas,
    )

    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.engine = policy_engine
    app.state.settings = settings

    yield app
    await engine.dispose()


@pytest.fixture
async def auth_client(auth_app) -> AsyncClient:
    transport = ASGITransport(app=auth_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestAgentAuthPrefixLookup:
    """Agent auth uses prefix-based lookup to avoid O(n) bcrypt."""

    async def test_agent_auth_uses_prefix_lookup(
        self, auth_app, auth_client: AsyncClient
    ) -> None:
        """Create agent with prefix, auth should use prefix for lookup."""
        # Register an agent via API
        response = await auth_client.post(
            "/agents",
            json={"name": "prefix-test-agent"},
            headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
        )
        assert response.status_code == 201
        agent_key = response.json()["api_key"]

        # Verify the agent was created with a prefix
        session_factory = auth_app.state.session_factory
        from sqlalchemy import select

        async with session_factory() as session:
            result = await session.execute(
                select(Agent).where(Agent.name == "prefix-test-agent")
            )
            agent = result.scalar_one()
            assert agent.api_key_prefix == agent_key[:8]
            assert len(agent.api_key_prefix) == 8

        # Auth with the agent key should work
        response = await auth_client.get(
            "/health",
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 200

    async def test_agent_auth_fallback_empty_prefix(
        self, auth_app, auth_client: AsyncClient
    ) -> None:
        """Agents with empty prefix (pre-migration) should still auth via full scan."""
        # Manually create an agent with empty prefix (simulating pre-migration)
        agent_key = "pre-migration-agent-key-for-testing-abc"
        key_hash = bcrypt.hashpw(agent_key.encode(), bcrypt.gensalt()).decode()

        session_factory = auth_app.state.session_factory
        async with session_factory() as session:
            async with session.begin():
                agent = Agent(
                    name="legacy-agent",
                    api_key_hash=key_hash,
                    api_key_prefix="",  # Empty prefix = pre-migration
                )
                session.add(agent)

        # Auth should still work via fallback scan
        response = await auth_client.get(
            "/health",
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 200

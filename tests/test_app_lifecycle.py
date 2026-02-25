"""Tests for app factory, lifespan, session helpers, and config validators.

Targets coverage gaps in app.py, db/session.py, and config.py.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.api.app import create_app, lifespan
from sna.config import Settings
from sna.db.models import Base
from sna.db.session import (
    create_async_engine_from_url,
    create_session_factory,
    get_db_session,
)
from sna.policy.engine import PolicyEngine

TEST_API_KEY = "lifecycle-test-key-123-abcdefghijklmn"
TEST_ADMIN_KEY = "lifecycle-admin-key-456-abcdefghijkl"


@pytest.fixture
def settings() -> Settings:
    """Test settings with in-memory SQLite."""
    return Settings(
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


@pytest.fixture
async def app_with_lifespan(settings: Settings) -> AsyncGenerator[object, None]:
    """Create an app and manually run its lifespan."""
    app = create_app(settings=settings)
    async with lifespan(app):
        yield app
    # lifespan __aexit__ disposes the engine


@pytest.fixture
async def lifecycle_client(app_with_lifespan) -> AsyncGenerator[AsyncClient, None]:
    """Client connected to an app with lifespan running."""
    transport = ASGITransport(app=app_with_lifespan)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


class TestAppLifespan:
    """Test the full app factory + lifespan startup/shutdown."""

    async def test_app_starts_and_responds(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """App should start, initialize engine, and serve requests."""
        response = await lifecycle_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    async def test_app_engine_initialized(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """After startup, full health check should work."""
        response = await lifecycle_client.get(
            "/health",
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["policy_loaded"] is True
        assert data["db_connected"] is True
        assert data["eas"] == pytest.approx(0.1)

    async def test_app_evaluate_through_lifespan(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """Evaluate endpoint should work through the full lifespan."""
        response = await lifecycle_client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "PERMIT"

    async def test_lifespan_creates_engine_on_state(
        self, app_with_lifespan
    ) -> None:
        """Lifespan should populate app.state with engine, session_factory, settings."""
        assert hasattr(app_with_lifespan.state, "engine")
        assert hasattr(app_with_lifespan.state, "session_factory")
        assert hasattr(app_with_lifespan.state, "db_engine")
        assert isinstance(app_with_lifespan.state.engine, PolicyEngine)

    async def test_app_request_body_size_limit(self, settings: Settings) -> None:
        """Requests exceeding body size limit should be rejected."""
        settings.max_request_body_bytes = 100
        app = create_app(settings=settings)
        async with lifespan(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                large_body = '{"tool_name": "test", "parameters": {}, "device_targets": [], "confidence_score": 0.5, "context": {"data": "' + "x" * 200 + '"}}'
                response = await client.post(
                    "/evaluate",
                    content=large_body,
                    headers={
                        "Authorization": f"Bearer {TEST_API_KEY}",
                        "Content-Type": "application/json",
                        "Content-Length": str(len(large_body)),
                    },
                )
                assert response.status_code == 413

    async def test_app_cors_headers(self, lifecycle_client: AsyncClient) -> None:
        """CORS preflight should return appropriate headers."""
        response = await lifecycle_client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers

    async def test_app_policy_reload_through_lifespan(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """Admin can reload policy through the full lifespan."""
        response = await lifecycle_client.post(
            "/policy/reload",
            headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "reloaded"

    async def test_app_audit_through_lifespan(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """Audit endpoint should work through lifespan with real DB."""
        # First create some audit entries
        await lifecycle_client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )

        response = await lifecycle_client.get(
            "/audit",
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

    async def test_app_escalation_through_lifespan(
        self, lifecycle_client: AsyncClient
    ) -> None:
        """Escalation flow should work through lifespan."""
        # Create an escalation
        eval_resp = await lifecycle_client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.01,
                "context": {},
            },
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert eval_resp.json()["verdict"] == "ESCALATE"
        esc_id = eval_resp.json()["escalation_id"]

        # List pending
        pending_resp = await lifecycle_client.get(
            "/escalation/pending",
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        assert pending_resp.status_code == 200
        assert pending_resp.json()["total"] >= 1

        # Decide (requires admin key)
        decision_resp = await lifecycle_client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "APPROVED",
                "decided_by": "lifecycle-admin",
                "reason": "Lifecycle test",
            },
            headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
        )
        assert decision_resp.status_code == 200
        assert decision_resp.json()["status"] == "APPROVED"


class TestDBSessionHelpers:
    """Test db/session.py helper functions."""

    def test_create_engine_sqlite(self) -> None:
        """Should create a SQLite engine with timeout."""
        engine = create_async_engine_from_url(
            "sqlite+aiosqlite:///:memory:",
            pool_timeout=5,
            connect_timeout=5,
        )
        assert engine is not None

    def test_create_session_factory_returns_maker(self) -> None:
        """Session factory should be an async_sessionmaker."""
        engine = create_async_engine_from_url("sqlite+aiosqlite:///:memory:")
        factory = create_session_factory(engine)
        assert isinstance(factory, async_sessionmaker)

    async def test_get_db_session_commit(self) -> None:
        """get_db_session should commit on success."""
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(engine, expire_on_commit=False)

        async for session in get_db_session(factory):
            from sna.db.models import AuditLog
            audit = AuditLog(
                tool_name="test_commit",
                verdict="PERMIT",
                risk_tier="tier_1_read",
                confidence_score=0.9,
                confidence_threshold=0.5,
                reason="test",
                eas_at_time=0.1,
            )
            session.add(audit)

        # Verify it was committed
        async with factory() as session:
            from sqlalchemy import select, func
            from sna.db.models import AuditLog
            count = await session.execute(
                select(func.count(AuditLog.id)).where(AuditLog.tool_name == "test_commit")
            )
            assert count.scalar() == 1

        await engine.dispose()

    async def test_get_db_session_rollback_on_error(self) -> None:
        """get_db_session should rollback on exception."""
        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        factory = async_sessionmaker(engine, expire_on_commit=False)

        with pytest.raises(ValueError, match="intentional"):
            async for session in get_db_session(factory):
                from sna.db.models import AuditLog
                audit = AuditLog(
                    tool_name="test_rollback",
                    verdict="PERMIT",
                    risk_tier="tier_1_read",
                    confidence_score=0.9,
                    confidence_threshold=0.5,
                    reason="test",
                    eas_at_time=0.1,
                )
                session.add(audit)
                raise ValueError("intentional")

        # Verify it was NOT committed
        async with factory() as session:
            from sqlalchemy import select, func
            from sna.db.models import AuditLog
            count = await session.execute(
                select(func.count(AuditLog.id)).where(AuditLog.tool_name == "test_rollback")
            )
            assert count.scalar() == 0

        await engine.dispose()


class TestConfigValidation:
    """Test config.py validator edge cases."""

    def test_empty_database_url_rejected(self) -> None:
        """Empty DATABASE_URL should be rejected."""
        with pytest.raises(Exception):
            Settings(
                database_url="   ",
                sna_api_key="key",
                sna_admin_api_key="admin",
            )

    def test_empty_api_key_rejected(self) -> None:
        """Empty API key should be rejected."""
        with pytest.raises(Exception):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                sna_api_key="   ",
                sna_admin_api_key="admin",
            )

    def test_empty_admin_key_rejected(self) -> None:
        """Empty admin key should be rejected."""
        with pytest.raises(Exception):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                sna_api_key="key",
                sna_admin_api_key="   ",
            )

    def test_eas_out_of_range_rejected(self) -> None:
        """EAS outside 0.0–1.0 should be rejected."""
        with pytest.raises(Exception):
            Settings(
                database_url="sqlite+aiosqlite:///:memory:",
                sna_api_key="a" * 32,
                sna_admin_api_key="b" * 32,
                default_eas=1.5,
            )

    def test_cors_origins_parsed(self) -> None:
        """Comma-separated CORS origins should be parsed into a list."""
        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            sna_api_key="a" * 32,
            sna_admin_api_key="b" * 32,
            cors_allowed_origins="http://localhost:3000,http://localhost:8080",
        )
        assert s.cors_origins_list == ["http://localhost:3000", "http://localhost:8080"]

    def test_valid_settings(self) -> None:
        """Valid settings should construct without error."""
        valid_key = "valid-key-" + "x" * 22
        valid_admin = "valid-admin-" + "x" * 20
        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            sna_api_key=valid_key,
            sna_admin_api_key=valid_admin,
            default_eas=0.5,
        )
        assert s.sna_api_key == valid_key
        assert s.default_eas == 0.5

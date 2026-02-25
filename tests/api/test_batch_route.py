"""Tests for batch route security — policy evaluation for all tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.api.app import create_app
from sna.config import Settings
from sna.db.models import Base
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy
from sna.policy.models import EvaluationResult, RiskTier, Verdict

TEST_API_KEY = "test-batch-api-key-abcdefghijklmnop"
TEST_ADMIN_KEY = "test-batch-admin-key-abcdefghijklm"


@pytest.fixture
async def batch_app():
    """Create a test app with a mock policy engine for batch tests."""
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
        rate_limit_batch=1000,
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
    app.state.batch_executor = AsyncMock()

    yield app
    await engine.dispose()


@pytest.fixture
async def batch_client(batch_app) -> AsyncClient:
    transport = ASGITransport(app=batch_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestBatchPolicyEvaluation:
    """Batch route evaluates ALL tools, not just alphabetically first."""

    async def test_batch_rejects_if_any_tool_blocked(
        self, batch_app, batch_client: AsyncClient
    ) -> None:
        """A batch with one PERMIT tool and one BLOCK tool should return 403."""
        call_count = 0
        original_evaluate = batch_app.state.engine.evaluate

        async def mock_evaluate(request):
            nonlocal call_count
            call_count += 1
            if request.tool_name == "configure_bgp_neighbor":
                return EvaluationResult(
                    verdict=Verdict.BLOCK,
                    risk_tier=RiskTier.TIER_4_HIGH_RISK_WRITE,
                    tool_name=request.tool_name,
                    reason="High-risk tool blocked",
                    confidence_score=0.5,
                    confidence_threshold=0.9,
                    device_count=1,
                )
            return EvaluationResult(
                verdict=Verdict.PERMIT,
                risk_tier=RiskTier.TIER_1_READ,
                tool_name=request.tool_name,
                reason="Permitted",
                confidence_score=0.99,
                confidence_threshold=0.5,
                device_count=1,
            )

        batch_app.state.engine.evaluate = mock_evaluate

        response = await batch_client.post(
            "/batch/execute",
            json={
                "items": [
                    {
                        "device_target": "switch-01",
                        "tool_name": "aaa_clear_attempt",
                        "params": {},
                    },
                    {
                        "device_target": "switch-02",
                        "tool_name": "configure_bgp_neighbor",
                        "params": {},
                    },
                ],
                "confidence_score": 0.5,
                "context": {},
            },
            headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
        )

        assert response.status_code == 403
        assert "BLOCK" in response.json()["detail"]
        assert "configure_bgp_neighbor" in response.json()["detail"]

    async def test_batch_evaluates_all_tools(
        self, batch_app, batch_client: AsyncClient
    ) -> None:
        """Policy engine should be called once per unique tool in batch."""
        evaluated_tools = []
        original_evaluate = batch_app.state.engine.evaluate

        async def tracking_evaluate(request):
            evaluated_tools.append(request.tool_name)
            return EvaluationResult(
                verdict=Verdict.PERMIT,
                risk_tier=RiskTier.TIER_1_READ,
                tool_name=request.tool_name,
                reason="Permitted",
                confidence_score=0.99,
                confidence_threshold=0.5,
                device_count=1,
            )

        batch_app.state.engine.evaluate = tracking_evaluate
        batch_app.state.batch_executor.execute_batch = AsyncMock(
            return_value=AsyncMock(
                batch_id="test-batch",
                items=[],
                total=2,
                succeeded=2,
                failed=0,
                rolled_back=0,
                duration_seconds=0.1,
            )
        )

        await batch_client.post(
            "/batch/execute",
            json={
                "items": [
                    {
                        "device_target": "switch-01",
                        "tool_name": "show_interfaces",
                        "params": {},
                    },
                    {
                        "device_target": "switch-02",
                        "tool_name": "configure_vlan",
                        "params": {},
                    },
                ],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {TEST_ADMIN_KEY}"},
        )

        assert "configure_vlan" in evaluated_tools
        assert "show_interfaces" in evaluated_tools
        assert len(evaluated_tools) == 2

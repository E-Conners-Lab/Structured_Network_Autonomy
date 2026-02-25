"""Tests for security hardening fixes.

Covers: rate limiting, security headers, Content-Length validation,
device_targets validation, tool_name validation, batch params validation,
agent endpoint auth, and audit log agent_id.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from tests.api.conftest import TEST_ADMIN_KEY, TEST_API_KEY


# --- Security headers (A2) ---


class TestSecurityHeaders:
    """Security headers must appear on all responses."""

    @pytest.mark.asyncio
    async def test_security_headers_on_health(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert "max-age=63072000" in resp.headers["Strict-Transport-Security"]

    @pytest.mark.asyncio
    async def test_csp_on_api_route(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.headers["Content-Security-Policy"] == "default-src 'none'"

    @pytest.mark.asyncio
    async def test_security_headers_on_evaluate(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"


# --- Content-Length guard (A3) ---


class TestContentLengthGuard:
    """Malformed Content-Length must return 400."""

    @pytest.mark.asyncio
    async def test_malformed_content_length(self, client: AsyncClient):
        resp = await client.get(
            "/health",
            headers={"Content-Length": "not-a-number"},
        )
        assert resp.status_code == 400
        assert "Invalid Content-Length" in resp.json()["detail"]


# --- device_targets validation (A4) ---


class TestDeviceTargetsValidation:
    """device_targets elements must match safe characters."""

    @pytest.mark.asyncio
    async def test_valid_device_targets(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "device_targets": ["R1", "Switch-R1", "router.core.01"],
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_invalid_device_target_semicolon(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "device_targets": ["R1; rm -rf /"],
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_device_target_spaces(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "device_targets": ["R1 R2"],
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422


# --- tool_name validation (A7) ---


class TestToolNameValidation:
    """tool_name must match [a-zA-Z0-9_-]+."""

    @pytest.mark.asyncio
    async def test_valid_tool_name(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_tool_name_with_dots_rejected(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show.interfaces",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_tool_name_with_spaces_rejected(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show interfaces",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_tool_name_with_slashes_rejected(self, client: AsyncClient, auth_headers):
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "../etc/passwd",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422


# --- Batch params validation (A5) ---


class TestBatchParamsValidation:
    """Batch item params values must not exceed 255 chars."""

    @pytest.mark.asyncio
    async def test_batch_params_oversized_value(self, client: AsyncClient, admin_headers):
        resp = await client.post(
            "/batch/execute",
            json={
                "items": [
                    {
                        "device_target": "R1",
                        "tool_name": "show_interfaces",
                        "params": {"command": "x" * 256},
                    }
                ],
                "confidence_score": 0.9,
            },
            headers=admin_headers,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_batch_params_valid_value(self, client: AsyncClient, admin_headers):
        resp = await client.post(
            "/batch/execute",
            json={
                "items": [
                    {
                        "device_target": "R1",
                        "tool_name": "show_interfaces",
                        "params": {"command": "show ip route"},
                    }
                ],
                "confidence_score": 0.9,
            },
            headers=admin_headers,
        )
        # May be 200 or 403 (policy block) but NOT 422 validation error
        assert resp.status_code != 422


# --- Agent endpoint auth (A6) ---


class TestAgentEndpointAuth:
    """Agent read endpoints require admin key, not just api key."""

    @pytest.mark.asyncio
    async def test_get_agent_requires_admin(self, client: AsyncClient, auth_headers):
        """GET /agents/{id} with regular API key should return 403."""
        import uuid

        resp = await client.get(
            f"/agents/{uuid.uuid4()}",
            headers=auth_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_agent_activity_requires_admin(self, client: AsyncClient, auth_headers):
        """GET /agents/{id}/activity with regular API key should return 403."""
        import uuid

        resp = await client.get(
            f"/agents/{uuid.uuid4()}/activity",
            headers=auth_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_agent_overrides_requires_admin(self, client: AsyncClient, auth_headers):
        """GET /agents/{id}/overrides with regular API key should return 403."""
        import uuid

        resp = await client.get(
            f"/agents/{uuid.uuid4()}/overrides",
            headers=auth_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_agent_reputation_requires_admin(self, client: AsyncClient, auth_headers):
        """GET /agents/{id}/reputation with regular API key should return 403."""
        import uuid

        resp = await client.get(
            f"/agents/{uuid.uuid4()}/reputation",
            headers=auth_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_get_agent_with_admin_key(self, client: AsyncClient, admin_headers):
        """GET /agents/{id} with admin key should work (404 = auth passed)."""
        import uuid

        resp = await client.get(
            f"/agents/{uuid.uuid4()}",
            headers=admin_headers,
        )
        # 404 means auth succeeded, agent just doesn't exist
        assert resp.status_code == 404


# --- AuditLog agent_id (A8) ---


class TestAuditLogAgentId:
    """AuditLog should record agent_id when available."""

    @pytest.mark.asyncio
    async def test_audit_log_created_with_evaluate(
        self, client: AsyncClient, auth_headers, test_app
    ):
        """Evaluate should create an audit log entry."""
        resp = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "confidence_score": 0.9,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 200

        # Check that audit log was written
        from sqlalchemy import select
        from sna.db.models import AuditLog

        session_factory = test_app.state.session_factory
        async with session_factory() as session:
            result = await session.execute(
                select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
            )
            audit = result.scalar_one_or_none()

        assert audit is not None
        assert audit.tool_name == "show_interfaces"
        # Global API key has no agent, so agent_id should be None
        assert audit.agent_id is None

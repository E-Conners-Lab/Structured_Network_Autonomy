"""Tests for GET /health — minimal unauthenticated, full authenticated."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestHealthEndpoint:
    """GET /health — tiered health check."""

    async def test_health_minimal_no_auth(self, client: AsyncClient) -> None:
        """Unauthenticated request should return minimal response."""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        # Minimal response should NOT expose internal details
        assert "eas" not in data
        assert "policy_version" not in data
        assert "db_connected" not in data

    async def test_health_full_with_auth(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Authenticated request should return full health details."""
        response = await client.get("/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "eas" in data
        assert "policy_loaded" in data
        assert data["policy_loaded"] is True
        assert "policy_version" in data
        assert "db_connected" in data
        assert data["db_connected"] is True

    async def test_health_full_eas_value(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Full health should report the current EAS value."""
        response = await client.get("/health", headers=auth_headers)
        data = response.json()
        assert isinstance(data["eas"], float)
        assert 0.0 <= data["eas"] <= 1.0

    async def test_health_invalid_key(self, client: AsyncClient) -> None:
        """Invalid API key should return 401."""
        response = await client.get(
            "/health",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert response.status_code == 401

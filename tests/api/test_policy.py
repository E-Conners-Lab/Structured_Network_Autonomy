"""Tests for POST /policy/reload — admin-only hot reload."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestPolicyReload:
    """POST /policy/reload — hot reload policy YAML."""

    async def test_reload_with_admin_key(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Admin key should allow policy reload."""
        response = await client.post("/policy/reload", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "reloaded"
        assert "version" in data

    async def test_reload_with_standard_key_forbidden(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Standard API key should be rejected (403)."""
        response = await client.post("/policy/reload", headers=auth_headers)
        assert response.status_code == 403

    async def test_reload_without_auth(self, client: AsyncClient) -> None:
        """No auth should return 401."""
        response = await client.post("/policy/reload")
        assert response.status_code == 401

    async def test_reload_wrong_key(self, client: AsyncClient) -> None:
        """Invalid key should return 403."""
        response = await client.post(
            "/policy/reload",
            headers={"Authorization": "Bearer totally-wrong-key"},
        )
        assert response.status_code == 403

    async def test_reload_returns_version(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Reload response should include policy version."""
        response = await client.post("/policy/reload", headers=admin_headers)
        data = response.json()
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

"""Tests for EAS management API."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestEASEndpoints:
    """EAS management API tests."""

    async def test_get_eas(self, client: AsyncClient, auth_headers: dict) -> None:
        """GET /eas should return current EAS."""
        response = await client.get("/eas", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "eas" in data
        assert 0.0 <= data["eas"] <= 1.0

    async def test_get_eas_requires_auth(self, client: AsyncClient) -> None:
        response = await client.get("/eas")
        assert response.status_code == 401

    async def test_adjust_eas(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """POST /eas should adjust EAS with admin key."""
        response = await client.post(
            "/eas",
            json={"score": 0.75, "reason": "Testing adjustment"},
            headers=admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["eas"] == pytest.approx(0.75)

    async def test_adjust_eas_requires_admin(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """POST /eas with regular key should be forbidden."""
        response = await client.post(
            "/eas",
            json={"score": 0.5, "reason": "test"},
            headers=auth_headers,
        )
        assert response.status_code == 403

    async def test_adjust_eas_out_of_range(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """EAS above 1.0 should be rejected."""
        response = await client.post(
            "/eas",
            json={"score": 1.5, "reason": "test"},
            headers=admin_headers,
        )
        assert response.status_code == 422

    async def test_eas_history_empty(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Empty history returns empty paginated response."""
        response = await client.get("/eas/history", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["items"] == []

    async def test_eas_history_after_adjustment(
        self, client: AsyncClient, admin_headers: dict, auth_headers: dict
    ) -> None:
        """After adjusting EAS, history should contain the change."""
        await client.post(
            "/eas",
            json={"score": 0.8, "reason": "After test adjustment"},
            headers=admin_headers,
        )
        response = await client.get("/eas/history", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert data["items"][0]["eas_score"] == pytest.approx(0.8)

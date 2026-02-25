"""Tests for GET /audit — paginated audit log retrieval."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestAuditEndpoint:
    """GET /audit — paginated audit log."""

    async def test_audit_empty(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Empty database should return empty paginated response."""
        response = await client.get("/audit", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["total_pages"] == 1

    async def test_audit_with_entries(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """After evaluating actions, audit entries should appear."""
        # Create some audit entries by evaluating
        await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers=auth_headers,
        )
        await client.post(
            "/evaluate",
            json={
                "tool_name": "show_version",
                "parameters": {},
                "device_targets": ["router-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers=auth_headers,
        )

        response = await client.get("/audit", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2
        assert len(data["items"]) >= 2

        # Verify entry shape
        entry = data["items"][0]
        assert "external_id" in entry
        assert "timestamp" in entry
        assert "tool_name" in entry
        assert "verdict" in entry
        assert "risk_tier" in entry
        assert "confidence_score" in entry
        assert "eas_at_time" in entry

    async def test_audit_pagination(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Pagination parameters should be respected."""
        response = await client.get(
            "/audit?page=1&page_size=5",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 5

    async def test_audit_page_size_limit(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Page size > 100 should fail validation."""
        response = await client.get(
            "/audit?page_size=200",
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_audit_requires_auth(self, client: AsyncClient) -> None:
        """Audit log without auth should return 401."""
        response = await client.get("/audit")
        assert response.status_code == 401

    async def test_audit_invalid_key(self, client: AsyncClient) -> None:
        """Audit log with wrong key should return 401."""
        response = await client.get(
            "/audit",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert response.status_code == 401

"""Tests for compliance reports API."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestComplianceReport:
    """GET /reports/compliance tests."""

    async def test_empty_report(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Empty database should return zero counts."""
        response = await client.get("/reports/compliance", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 0
        assert data["permit_count"] == 0
        assert data["escalate_count"] == 0
        assert data["block_count"] == 0

    async def test_report_after_evaluations(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Report should reflect evaluation verdicts."""
        # Create a PERMIT
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

        # Create a BLOCK
        await client.post(
            "/evaluate",
            json={
                "tool_name": "factory_reset",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers=auth_headers,
        )

        response = await client.get("/reports/compliance", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] >= 2
        assert data["permit_count"] >= 1
        assert data["block_count"] >= 1

    async def test_report_requires_auth(self, client: AsyncClient) -> None:
        response = await client.get("/reports/compliance")
        assert response.status_code == 401

    async def test_report_custom_window(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Custom time window should be accepted."""
        response = await client.get(
            "/reports/compliance?hours=1",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["time_window_hours"] == 1

"""Tests for POST /escalation/{id}/decision and GET /escalation/pending."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestEscalationDecision:
    """POST /escalation/{id}/decision — approve or reject."""

    async def _create_escalation(
        self, client: AsyncClient, auth_headers: dict
    ) -> str:
        """Helper: evaluate an action that triggers ESCALATE, return escalation_id."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.01,
                "context": {},
            },
            headers=auth_headers,
        )
        data = response.json()
        assert data["verdict"] == "ESCALATE"
        assert data["escalation_id"] is not None
        return data["escalation_id"]

    async def test_approve_escalation(
        self, client: AsyncClient, auth_headers: dict, admin_headers: dict
    ) -> None:
        """Approving a pending escalation should succeed."""
        esc_id = await self._create_escalation(client, auth_headers)

        response = await client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "APPROVED",
                "decided_by": "senior-admin",
                "reason": "Looks safe",
            },
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "APPROVED"
        assert data["decided_by"] == "senior-admin"
        assert data["external_id"] == esc_id

    async def test_reject_escalation(
        self, client: AsyncClient, auth_headers: dict, admin_headers: dict
    ) -> None:
        """Rejecting a pending escalation should succeed."""
        esc_id = await self._create_escalation(client, auth_headers)

        response = await client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "REJECTED",
                "decided_by": "senior-admin",
                "reason": "Too risky",
            },
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "REJECTED"

    async def test_double_decision_conflict(
        self, client: AsyncClient, auth_headers: dict, admin_headers: dict
    ) -> None:
        """Deciding on an already-resolved escalation should return 409."""
        esc_id = await self._create_escalation(client, auth_headers)

        # First decision
        await client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "APPROVED",
                "decided_by": "senior-admin",
                "reason": "Approved first time",
            },
            headers=admin_headers,
        )

        # Second decision
        response = await client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "REJECTED",
                "decided_by": "another-admin",
                "reason": "Too late",
            },
            headers=admin_headers,
        )
        assert response.status_code == 409

    async def test_decision_not_found(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Decision on non-existent escalation should return 404."""
        response = await client.post(
            "/escalation/00000000-0000-0000-0000-000000000000/decision",
            json={
                "decision": "APPROVED",
                "decided_by": "admin",
                "reason": "test",
            },
            headers=admin_headers,
        )
        assert response.status_code == 404

    async def test_decision_invalid_status(
        self, client: AsyncClient, auth_headers: dict, admin_headers: dict
    ) -> None:
        """Invalid decision value should fail validation."""
        esc_id = await self._create_escalation(client, auth_headers)

        response = await client.post(
            f"/escalation/{esc_id}/decision",
            json={
                "decision": "MAYBE",
                "decided_by": "admin",
                "reason": "test",
            },
            headers=admin_headers,
        )
        assert response.status_code == 422

    async def test_decision_requires_auth(self, client: AsyncClient) -> None:
        """Decision without auth should return 401."""
        response = await client.post(
            "/escalation/00000000-0000-0000-0000-000000000000/decision",
            json={
                "decision": "APPROVED",
                "decided_by": "admin",
                "reason": "test",
            },
        )
        assert response.status_code == 401


class TestListPendingEscalations:
    """GET /escalation/pending — paginated pending list."""

    async def test_list_empty(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Empty database should return empty paginated response."""
        response = await client.get("/escalation/pending", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_with_pending(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """After creating an escalation, it should appear in pending list."""
        # Create an escalation via evaluate
        await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.01,
                "context": {},
            },
            headers=auth_headers,
        )

        response = await client.get("/escalation/pending", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        assert data["items"][0]["status"] == "PENDING"

    async def test_list_pagination(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Pagination parameters should be respected."""
        response = await client.get(
            "/escalation/pending?page=1&page_size=2",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 2

    async def test_list_requires_auth(self, client: AsyncClient) -> None:
        """Listing without auth should return 401."""
        response = await client.get("/escalation/pending")
        assert response.status_code == 401

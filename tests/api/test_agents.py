"""Tests for agent registration and management API."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestAgentRegistration:
    """POST /agents — register new agent."""

    async def test_register_agent(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Admin can register a new agent."""
        response = await client.post(
            "/agents",
            json={"name": "test-agent-1", "description": "Test agent"},
            headers=admin_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-agent-1"
        assert "api_key" in data
        assert len(data["api_key"]) > 0
        assert data["status"] == "ACTIVE"

    async def test_register_requires_admin(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Regular API key cannot register agents."""
        response = await client.post(
            "/agents",
            json={"name": "test-agent", "description": "Test"},
            headers=auth_headers,
        )
        assert response.status_code == 403

    async def test_register_duplicate_name(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Duplicate agent name should fail."""
        await client.post(
            "/agents",
            json={"name": "dup-agent"},
            headers=admin_headers,
        )
        response = await client.post(
            "/agents",
            json={"name": "dup-agent"},
            headers=admin_headers,
        )
        assert response.status_code == 409


class TestAgentAuthentication:
    """Per-agent API key authentication."""

    async def test_agent_can_authenticate(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Agent key should authenticate against /evaluate."""
        # Register agent
        reg = await client.post(
            "/agents",
            json={"name": "auth-agent"},
            headers=admin_headers,
        )
        agent_key = reg.json()["api_key"]

        # Use agent key to call /evaluate
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["switch-01"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "PERMIT"


class TestAgentLifecycle:
    """Agent suspend, activate, revoke lifecycle."""

    async def test_suspend_blocks_requests(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Suspended agent should get 403."""
        # Register
        reg = await client.post(
            "/agents",
            json={"name": "suspend-agent"},
            headers=admin_headers,
        )
        agent_key = reg.json()["api_key"]
        agent_id = reg.json()["external_id"]

        # Suspend
        resp = await client.post(
            f"/agents/{agent_id}/suspend",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "SUSPENDED"

        # Try to authenticate
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 403

    async def test_reactivate_agent(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Reactivated agent should work again."""
        reg = await client.post(
            "/agents",
            json={"name": "reactivate-agent"},
            headers=admin_headers,
        )
        agent_id = reg.json()["external_id"]
        agent_key = reg.json()["api_key"]

        # Suspend then activate
        await client.post(f"/agents/{agent_id}/suspend", headers=admin_headers)
        await client.post(f"/agents/{agent_id}/activate", headers=admin_headers)

        # Should work again
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": ["sw1"],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 200

    async def test_revoke_permanently_disables(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Revoked agent cannot authenticate."""
        reg = await client.post(
            "/agents",
            json={"name": "revoke-agent"},
            headers=admin_headers,
        )
        agent_key = reg.json()["api_key"]
        agent_id = reg.json()["external_id"]

        # Revoke
        await client.post(f"/agents/{agent_id}/revoke", headers=admin_headers)

        # Try to authenticate — should fail
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        assert response.status_code == 401


class TestAgentListing:
    """GET /agents and GET /agents/{id} tests."""

    async def test_list_agents(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Admin can list all agents."""
        await client.post(
            "/agents",
            json={"name": "list-agent"},
            headers=admin_headers,
        )
        response = await client.get("/agents", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["total"] >= 1

    async def test_get_agent_detail(
        self, client: AsyncClient, admin_headers: dict, auth_headers: dict
    ) -> None:
        """Admin can get agent details."""
        reg = await client.post(
            "/agents",
            json={"name": "detail-agent"},
            headers=admin_headers,
        )
        agent_id = reg.json()["external_id"]

        response = await client.get(
            f"/agents/{agent_id}", headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["name"] == "detail-agent"

    async def test_get_agent_not_found(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        response = await client.get(
            "/agents/00000000-0000-0000-0000-000000000000",
            headers=admin_headers,
        )
        assert response.status_code == 404

    async def test_get_agent_activity(
        self, client: AsyncClient, admin_headers: dict, auth_headers: dict
    ) -> None:
        reg = await client.post(
            "/agents",
            json={"name": "activity-agent"},
            headers=admin_headers,
        )
        agent_id = reg.json()["external_id"]

        response = await client.get(
            f"/agents/{agent_id}/activity", headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["name"] == "activity-agent"

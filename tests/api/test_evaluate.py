"""Tests for POST /evaluate endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestEvaluateEndpoint:
    """POST /evaluate — policy evaluation."""

    async def test_evaluate_permit_tier1(self, client: AsyncClient, auth_headers: dict) -> None:
        """Tier 1 read action with high confidence should be PERMIT."""
        response = await client.post(
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
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PERMIT"
        assert data["risk_tier"] == "tier_1_read"
        assert data["tool_name"] == "show_interfaces"
        assert data["requires_audit"] is False

    async def test_evaluate_escalate_low_confidence(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Low confidence score should trigger ESCALATE."""
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
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "ESCALATE"
        assert data["escalation_id"] is not None

    async def test_evaluate_block_hard_blocked(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Hard-blocked action should return BLOCK."""
        response = await client.post(
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
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCK"

    async def test_evaluate_scope_escalation(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Exceeding device scope limit should trigger ESCALATE."""
        targets = [f"switch-{i:02d}" for i in range(5)]
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": targets,
                "confidence_score": 0.99,
                "context": {},
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "ESCALATE"
        assert "scope limit" in data["reason"].lower() or "device count" in data["reason"].lower()

    async def test_evaluate_requires_auth(self, client: AsyncClient) -> None:
        """Request without auth should return 401."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.99,
                "context": {},
            },
        )
        assert response.status_code == 401

    async def test_evaluate_invalid_key(self, client: AsyncClient) -> None:
        """Request with wrong API key should return 401."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.99,
                "context": {},
            },
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert response.status_code == 401

    async def test_evaluate_invalid_confidence(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Confidence score > 1.0 should fail validation."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 1.5,
                "context": {},
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_evaluate_empty_tool_name(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Empty tool_name should fail validation."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.9,
                "context": {},
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_evaluate_extra_fields_rejected(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Extra fields in request body should be rejected (extra=forbid)."""
        response = await client.post(
            "/evaluate",
            json={
                "tool_name": "show_interfaces",
                "parameters": {},
                "device_targets": [],
                "confidence_score": 0.9,
                "context": {},
                "unexpected_field": "should_fail",
            },
            headers=auth_headers,
        )
        assert response.status_code == 422

    async def test_evaluate_response_shape(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Verify all expected fields are present in response."""
        response = await client.post(
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
        data = response.json()
        expected_keys = {
            "verdict", "risk_tier", "tool_name", "reason",
            "confidence_score", "confidence_threshold", "device_count",
            "requires_audit", "requires_senior_approval", "escalation_id",
        }
        assert expected_keys == set(data.keys())

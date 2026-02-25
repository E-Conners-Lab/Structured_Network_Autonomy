"""Tests for policy versioning API endpoints — C25.

Covers:
- GET /policy/versions — paginated history
- GET /policy/current — current version info
- POST /policy/rollback/{version_id} — rollback
- 404 on bad version_id
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient


class TestPolicyVersions:
    async def test_versions_after_reload(self, client: AsyncClient, admin_headers: dict) -> None:
        # Reload to create a version entry
        await client.post("/policy/reload", headers=admin_headers)

        response = await client.get("/policy/versions", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        item = data["items"][0]
        assert "external_id" in item
        assert "version_string" in item
        assert "policy_hash" in item

    async def test_versions_requires_admin(self, client: AsyncClient, auth_headers: dict) -> None:
        response = await client.get("/policy/versions", headers=auth_headers)
        assert response.status_code == 403


class TestPolicyCurrent:
    async def test_current_version(self, client: AsyncClient, auth_headers: dict) -> None:
        response = await client.get("/policy/current", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert isinstance(data["version"], str)


class TestPolicyRollback:
    async def test_rollback_creates_new_version(self, client: AsyncClient, admin_headers: dict) -> None:
        # Reload to create a version
        await client.post("/policy/reload", headers=admin_headers)

        # Get versions
        versions_resp = await client.get("/policy/versions", headers=admin_headers)
        versions = versions_resp.json()["items"]
        target_id = versions[0]["external_id"]

        # Count before rollback
        before_count = versions_resp.json()["total"]

        # Rollback
        response = await client.post(
            f"/policy/rollback/{target_id}", headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "rolled_back"
        assert data["rolled_back_to"] == target_id

        # Verify new version created
        after_resp = await client.get("/policy/versions", headers=admin_headers)
        after_count = after_resp.json()["total"]
        assert after_count == before_count + 1

    async def test_rollback_404_bad_id(self, client: AsyncClient, admin_headers: dict) -> None:
        fake_id = str(uuid4())
        response = await client.post(
            f"/policy/rollback/{fake_id}", headers=admin_headers,
        )
        assert response.status_code == 404

    async def test_rollback_requires_admin(self, client: AsyncClient, auth_headers: dict) -> None:
        fake_id = str(uuid4())
        response = await client.post(
            f"/policy/rollback/{fake_id}", headers=auth_headers,
        )
        assert response.status_code == 403

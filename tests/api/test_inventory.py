"""Tests for the inventory API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestInventoryDevices:
    """GET /inventory/devices and GET /inventory/devices/{name}."""

    async def test_list_devices_no_netbox(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Without NetBox configured, returns empty list."""
        response = await client.get("/inventory/devices", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == []

    async def test_get_device_no_netbox(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Without NetBox configured, returns 404."""
        response = await client.get(
            "/inventory/devices/switch-01", headers=auth_headers
        )
        assert response.status_code == 404

    async def test_list_devices_requires_auth(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/inventory/devices")
        assert response.status_code == 401


class TestInventorySync:
    """POST /inventory/sync."""

    async def test_sync_no_netbox(
        self, client: AsyncClient, admin_headers: dict
    ) -> None:
        """Without NetBox, sync returns skipped."""
        response = await client.post(
            "/inventory/sync", headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "skipped"

    async def test_sync_requires_admin(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        response = await client.post(
            "/inventory/sync", headers=auth_headers
        )
        assert response.status_code == 403


class TestMaintenanceWindows:
    """GET /inventory/maintenance."""

    async def test_list_no_windows(
        self, client: AsyncClient, auth_headers: dict
    ) -> None:
        """Without maintenance windows configured, returns empty list."""
        response = await client.get(
            "/inventory/maintenance", headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json() == []

    async def test_requires_auth(self, client: AsyncClient) -> None:
        response = await client.get("/inventory/maintenance")
        assert response.status_code == 401

"""Tests for device context enrichment from NetBox."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sna.devices.enrichment import (
    DeviceContext,
    DeviceInfo,
    enrich_device_context,
    _highest_risk_device,
    _parse_device_info,
)
from sna.integrations.netbox import NetBoxClient, NetBoxError


class TestHighestRiskDevice:
    """Fallback device for when NetBox is unreachable."""

    def test_returns_unenriched(self) -> None:
        d = _highest_risk_device("switch-01")
        assert d.name == "switch-01"
        assert d.role == "unknown"
        assert d.site == "unknown"
        assert not d.enriched


class TestParseDeviceInfo:
    """Parsing NetBox device response into DeviceInfo."""

    def test_full_device(self) -> None:
        nb = {
            "name": "core-01",
            "role": {"slug": "core-router"},
            "site": {"slug": "hq"},
            "tenant": {"slug": "ops"},
            "platform": {"slug": "ios-xe"},
            "status": {"value": "active"},
            "tags": [{"slug": "production-core"}, {"slug": "managed"}],
            "custom_fields": {"region": "us-east"},
        }
        info = _parse_device_info("core-01", nb)
        assert info.name == "core-01"
        assert info.role == "core-router"
        assert info.site == "hq"
        assert info.tenant == "ops"
        assert info.platform == "ios-xe"
        assert info.status == "active"
        assert "production-core" in info.tags
        assert info.enriched

    def test_missing_fields(self) -> None:
        nb = {"name": "bare"}
        info = _parse_device_info("bare", nb)
        assert info.role == "unknown"
        assert info.site == "unknown"
        assert info.enriched

    def test_device_role_fallback(self) -> None:
        """NetBox v3 uses device_role, v4 uses role."""
        nb = {"name": "old", "device_role": {"slug": "switch"}}
        info = _parse_device_info("old", nb)
        assert info.role == "switch"

    def test_status_as_string(self) -> None:
        nb = {"name": "str-status", "status": "active"}
        info = _parse_device_info("str-status", nb)
        assert info.status == "active"


class TestEnrichDeviceContext:
    """Device context enrichment integration."""

    async def test_empty_targets(self) -> None:
        ctx = await enrich_device_context([], None)
        assert ctx.devices == ()
        assert not ctx.all_enriched

    async def test_no_netbox_client(self) -> None:
        """Without NetBox, returns unenriched fallback devices."""
        ctx = await enrich_device_context(["sw1", "sw2"], None)
        assert len(ctx.devices) == 2
        assert not ctx.all_enriched
        assert not ctx.devices[0].enriched
        assert not ctx.devices[1].enriched

    async def test_all_devices_enriched(self) -> None:
        mock_client = AsyncMock(spec=NetBoxClient)
        mock_client.get_device = AsyncMock(
            side_effect=lambda name: {
                "name": name,
                "role": {"slug": "access-switch"},
                "site": {"slug": "hq"},
                "tenant": None,
                "platform": {"slug": "ios-xe"},
                "status": {"value": "active"},
                "tags": [{"slug": "managed"}],
                "custom_fields": {},
            }
        )

        ctx = await enrich_device_context(["sw1", "sw2"], mock_client)
        assert ctx.all_enriched
        assert len(ctx.devices) == 2
        assert ctx.devices[0].enriched
        assert "hq" in ctx.sites
        assert "access-switch" in ctx.roles

    async def test_partial_enrichment(self) -> None:
        """One device found, one not — all_enriched is False."""
        mock_client = AsyncMock(spec=NetBoxClient)

        async def mock_get(name: str):
            if name == "sw1":
                return {
                    "name": "sw1",
                    "role": {"slug": "switch"},
                    "site": {"slug": "hq"},
                    "status": {"value": "active"},
                    "tags": [],
                }
            return None

        mock_client.get_device = AsyncMock(side_effect=mock_get)

        ctx = await enrich_device_context(["sw1", "sw2"], mock_client)
        assert not ctx.all_enriched
        assert ctx.devices[0].enriched
        assert not ctx.devices[1].enriched

    async def test_netbox_error_fails_closed(self) -> None:
        """NetBox error → unenriched fallback (fail-closed)."""
        mock_client = AsyncMock(spec=NetBoxClient)
        mock_client.get_device = AsyncMock(side_effect=NetBoxError("connection failed"))

        ctx = await enrich_device_context(["sw1"], mock_client)
        assert not ctx.all_enriched
        assert not ctx.devices[0].enriched

    async def test_production_core_detection(self) -> None:
        mock_client = AsyncMock(spec=NetBoxClient)
        mock_client.get_device = AsyncMock(return_value={
            "name": "core-01",
            "role": {"slug": "core-router"},
            "site": {"slug": "dc1"},
            "status": {"value": "active"},
            "tags": [{"slug": "production-core"}],
        })

        ctx = await enrich_device_context(["core-01"], mock_client)
        assert ctx.has_production_core

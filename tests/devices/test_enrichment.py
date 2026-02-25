"""Tests for device context enrichment from NetBox."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from sna.devices.enrichment import (
    CRITICALITY_MAP,
    DeviceContext,
    DeviceInfo,
    build_policy_context,
    compute_device_criticality,
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


class TestComputeDeviceCriticality:
    """Criticality score computation from device role."""

    def test_known_role(self) -> None:
        device = DeviceInfo(name="r1", role="core-router", enriched=True)
        assert compute_device_criticality(device) == 0.9

    def test_unknown_role(self) -> None:
        device = DeviceInfo(name="r1", role="unknown", enriched=False)
        assert compute_device_criticality(device) == 0.5

    def test_role_not_in_map(self) -> None:
        device = DeviceInfo(name="r1", role="custom-device", enriched=True)
        assert compute_device_criticality(device) == 0.5

    def test_custom_default(self) -> None:
        device = DeviceInfo(name="r1", role="custom-device", enriched=True)
        assert compute_device_criticality(device, default_criticality=0.7) == 0.7

    def test_empty_role(self) -> None:
        device = DeviceInfo(name="r1", role="", enriched=True)
        assert compute_device_criticality(device) == 0.5

    def test_clamps_to_valid_range(self) -> None:
        device = DeviceInfo(name="r1", role="firewall", enriched=True)
        result = compute_device_criticality(device)
        assert 0.0 <= result <= 1.0


class TestBuildPolicyContext:
    """Policy context building from device context."""

    def test_single_device(self) -> None:
        device = DeviceInfo(
            name="sw1", role="access-switch", site="hq",
            tags=("managed", "monitored"), enriched=True,
        )
        ctx = DeviceContext(devices=(device,), all_enriched=True, sites=("hq",), roles=("access-switch",))
        result = build_policy_context(ctx)
        assert result["site"] == "hq"
        assert result["device_role"] == "access-switch"
        assert result["device_criticality"] == 0.3
        assert "managed" in result["device_tags"]
        assert "monitored" in result["device_tags"]

    def test_multiple_devices_highest_criticality_wins(self) -> None:
        d1 = DeviceInfo(name="sw1", role="access-switch", site="hq", enriched=True)
        d2 = DeviceInfo(name="r1", role="core-router", site="dc1", enriched=True)
        ctx = DeviceContext(
            devices=(d1, d2), all_enriched=True,
            sites=("dc1", "hq"), roles=("access-switch", "core-router"),
        )
        result = build_policy_context(ctx)
        assert result["device_criticality"] == 0.9  # core-router wins

    def test_empty_context(self) -> None:
        ctx = DeviceContext()
        result = build_policy_context(ctx)
        assert result == {}

    def test_tags_merged(self) -> None:
        d1 = DeviceInfo(name="sw1", role="access-switch", tags=("managed",), enriched=True)
        d2 = DeviceInfo(name="sw2", role="access-switch", tags=("managed", "critical"), enriched=True)
        ctx = DeviceContext(devices=(d1, d2), all_enriched=True)
        result = build_policy_context(ctx)
        assert set(result["device_tags"]) == {"managed", "critical"}

    def test_unknown_sites_and_roles(self) -> None:
        device = DeviceInfo(name="sw1", role="unknown", site="unknown", enriched=False)
        ctx = DeviceContext(devices=(device,))
        result = build_policy_context(ctx)
        assert result["site"] == "unknown"
        assert result["device_role"] == "unknown"

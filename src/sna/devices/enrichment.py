"""Device context enrichment from NetBox.

Pulls device role, site, tenant, platform, status, and tags from NetBox
to enrich policy evaluation context. Fails closed: if NetBox is unreachable,
all devices are treated as highest risk tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from sna.integrations.netbox import NetBoxClient, NetBoxError

logger = structlog.get_logger()


@dataclass(frozen=True)
class DeviceInfo:
    """Enriched device information from NetBox."""

    name: str
    role: str = "unknown"
    site: str = "unknown"
    tenant: str = ""
    platform: str = "unknown"
    status: str = "unknown"
    tags: tuple[str, ...] = ()
    custom_fields: dict = field(default_factory=dict)
    enriched: bool = False  # True if data came from NetBox, False if default/fallback


@dataclass(frozen=True)
class DeviceContext:
    """Enrichment context for policy evaluation.

    Contains device information for all targets in an evaluation request.
    """

    devices: tuple[DeviceInfo, ...] = ()
    all_enriched: bool = False  # True only if all devices were enriched from NetBox
    has_production_core: bool = False
    sites: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()


def _highest_risk_device(name: str) -> DeviceInfo:
    """Return a fallback DeviceInfo with highest-risk defaults."""
    return DeviceInfo(
        name=name,
        role="unknown",
        site="unknown",
        tenant="",
        platform="unknown",
        status="active",
        tags=(),
        enriched=False,
    )


def _parse_device_info(name: str, nb_device: dict) -> DeviceInfo:
    """Parse NetBox device response into DeviceInfo."""
    role = ""
    if nb_device.get("role"):
        role = nb_device["role"].get("slug", "") or nb_device["role"].get("name", "")
    elif nb_device.get("device_role"):
        role = nb_device["device_role"].get("slug", "") or nb_device["device_role"].get("name", "")

    site = ""
    if nb_device.get("site"):
        site = nb_device["site"].get("slug", "") or nb_device["site"].get("name", "")

    tenant = ""
    if nb_device.get("tenant"):
        tenant = nb_device["tenant"].get("slug", "") or nb_device["tenant"].get("name", "")

    platform = ""
    if nb_device.get("platform"):
        platform = nb_device["platform"].get("slug", "") or nb_device["platform"].get("name", "")

    status_val = nb_device.get("status", {})
    status = status_val.get("value", "") if isinstance(status_val, dict) else str(status_val)

    tags_raw = nb_device.get("tags", [])
    tags = tuple(
        t.get("slug", "") or t.get("name", "")
        for t in tags_raw
        if isinstance(t, dict)
    )

    custom_fields = nb_device.get("custom_fields", {}) or {}

    return DeviceInfo(
        name=name,
        role=role or "unknown",
        site=site or "unknown",
        tenant=tenant,
        platform=platform or "unknown",
        status=status or "unknown",
        tags=tags,
        custom_fields=custom_fields,
        enriched=True,
    )


async def enrich_device_context(
    device_targets: list[str],
    netbox_client: NetBoxClient | None,
) -> DeviceContext:
    """Enrich device targets with NetBox data.

    Fail-closed: if NetBox is unreachable, treat all devices as highest risk.

    Args:
        device_targets: List of device names to enrich.
        netbox_client: Optional NetBox client. If None, returns unenriched context.

    Returns:
        DeviceContext with enriched device information.
    """
    if not device_targets:
        return DeviceContext()

    if netbox_client is None:
        devices = tuple(_highest_risk_device(name) for name in device_targets)
        return DeviceContext(
            devices=devices,
            all_enriched=False,
            sites=(),
            roles=(),
        )

    devices: list[DeviceInfo] = []
    all_enriched = True

    for name in device_targets:
        try:
            nb_device = await netbox_client.get_device(name)
            if nb_device:
                devices.append(_parse_device_info(name, nb_device))
            else:
                await logger.awarning("netbox_device_not_found", device=name)
                devices.append(_highest_risk_device(name))
                all_enriched = False
        except NetBoxError:
            await logger.awarning("netbox_enrichment_failed", device=name, exc_info=True)
            devices.append(_highest_risk_device(name))
            all_enriched = False

    devices_tuple = tuple(devices)
    sites = tuple(sorted(set(d.site for d in devices_tuple if d.site != "unknown")))
    roles = tuple(sorted(set(d.role for d in devices_tuple if d.role != "unknown")))
    has_production_core = any("production-core" in d.tags for d in devices_tuple)

    return DeviceContext(
        devices=devices_tuple,
        all_enriched=all_enriched,
        has_production_core=has_production_core,
        sites=sites,
        roles=roles,
    )

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

# Maps device roles to criticality scores for policy decisions.
# Higher score = more critical device = stricter policy thresholds.
CRITICALITY_MAP: dict[str, float] = {
    "core-router": 0.9,
    "core-switch": 0.9,
    "distribution-router": 0.7,
    "distribution-switch": 0.7,
    "border-router": 0.85,
    "firewall": 0.95,
    "load-balancer": 0.8,
    "access-switch": 0.3,
    "access-point": 0.2,
    "management": 0.4,
    "unknown": 0.5,
}


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


def compute_device_criticality(
    device_info: DeviceInfo,
    default_criticality: float = 0.5,
) -> float:
    """Compute criticality score for a device based on its role.

    Args:
        device_info: Enriched device information.
        default_criticality: Default criticality for unknown roles.

    Returns:
        Criticality score clamped to [0.0, 1.0].
    """
    raw = CRITICALITY_MAP.get(device_info.role, default_criticality)
    return max(0.0, min(1.0, float(raw)))


def build_policy_context(
    device_context: DeviceContext,
    default_criticality: float = 0.5,
) -> dict[str, object]:
    """Build a policy evaluation context dict from enriched device data.

    For multiple devices, the highest criticality wins and all tags are merged.

    Args:
        device_context: Enriched device context.
        default_criticality: Fallback criticality for unknown roles.

    Returns:
        Dict with site, device_role, device_tags, device_criticality keys.
    """
    if not device_context.devices:
        return {}

    max_criticality = 0.0
    all_tags: set[str] = set()
    sites: set[str] = set()
    roles: set[str] = set()

    for device in device_context.devices:
        criticality = compute_device_criticality(device, default_criticality)
        # Clamp enriched criticality to [0.0, 1.0] (security: prevents NetBox injection)
        criticality = max(0.0, min(1.0, criticality))
        if criticality > max_criticality:
            max_criticality = criticality

        for tag in device.tags:
            if isinstance(tag, str):
                all_tags.add(tag)

        if device.site != "unknown" and isinstance(device.site, str):
            sites.add(device.site)

        if device.role != "unknown" and isinstance(device.role, str):
            roles.add(device.role)

    # Use the first valid site/role for single-device cases, comma-join for multi
    site_str = ",".join(sorted(sites)) if sites else "unknown"
    role_str = ",".join(sorted(roles)) if roles else "unknown"

    return {
        "site": site_str,
        "device_role": role_str,
        "device_tags": sorted(all_tags),
        "device_criticality": max_criticality,
    }


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

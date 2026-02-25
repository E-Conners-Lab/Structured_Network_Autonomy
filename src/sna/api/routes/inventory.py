"""Inventory API — NetBox device inventory and maintenance windows.

Provides cached device list, individual device details, manual sync trigger,
and active maintenance window listing.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from sna.api.auth import require_admin_key, require_api_key

router = APIRouter()


class DeviceResponse(BaseModel):
    """Device detail from NetBox cache."""

    name: str
    role: str
    site: str
    tenant: str
    platform: str
    status: str
    tags: list[str]


class InventorySyncResponse(BaseModel):
    """Response after manual sync trigger."""

    status: str
    message: str


class MaintenanceWindowResponse(BaseModel):
    """Active maintenance window."""

    name: str
    sites: list[str]
    devices: list[str]
    start: datetime | None
    end: datetime | None
    active: bool


@router.get("/inventory/devices", response_model=list[DeviceResponse])
async def list_devices(
    request: Request,
    _api_key: str = Depends(require_api_key),
) -> list[DeviceResponse]:
    """List cached devices from NetBox.

    Returns empty list if NetBox is not configured.
    """
    netbox = getattr(request.app.state, "netbox_client", None)
    if netbox is None:
        return []

    devices = await netbox.get_devices()
    return [
        DeviceResponse(
            name=d.get("name", "unknown"),
            role=(d.get("role") or d.get("device_role") or {}).get("slug", "unknown"),
            site=(d.get("site") or {}).get("slug", "unknown"),
            tenant=(d.get("tenant") or {}).get("slug", ""),
            platform=(d.get("platform") or {}).get("slug", "unknown"),
            status=d.get("status", {}).get("value", "unknown") if isinstance(d.get("status"), dict) else str(d.get("status", "unknown")),
            tags=[t.get("slug", "") for t in d.get("tags", []) if isinstance(t, dict)],
        )
        for d in devices
    ]


@router.get("/inventory/devices/{name}", response_model=DeviceResponse)
async def get_device(
    request: Request,
    name: str,
    _api_key: str = Depends(require_api_key),
) -> DeviceResponse:
    """Get a single device by name from NetBox."""
    netbox = getattr(request.app.state, "netbox_client", None)
    if netbox is None:
        raise HTTPException(status_code=404, detail="NetBox not configured")

    device = await netbox.get_device(name)
    if device is None:
        raise HTTPException(status_code=404, detail=f"Device '{name}' not found")

    return DeviceResponse(
        name=device.get("name", name),
        role=(device.get("role") or device.get("device_role") or {}).get("slug", "unknown"),
        site=(device.get("site") or {}).get("slug", "unknown"),
        tenant=(device.get("tenant") or {}).get("slug", ""),
        platform=(device.get("platform") or {}).get("slug", "unknown"),
        status=device.get("status", {}).get("value", "unknown") if isinstance(device.get("status"), dict) else str(device.get("status", "unknown")),
        tags=[t.get("slug", "") for t in device.get("tags", []) if isinstance(t, dict)],
    )


@router.post("/inventory/sync", response_model=InventorySyncResponse)
async def sync_inventory(
    request: Request,
    _admin_key: str = Depends(require_admin_key),
) -> InventorySyncResponse:
    """Trigger a manual inventory sync from NetBox. Admin only."""
    netbox = getattr(request.app.state, "netbox_client", None)
    if netbox is None:
        return InventorySyncResponse(status="skipped", message="NetBox not configured")

    try:
        devices = await netbox.get_devices()
        return InventorySyncResponse(
            status="ok",
            message=f"Synced {len(devices)} devices from NetBox",
        )
    except Exception as exc:
        return InventorySyncResponse(
            status="error",
            message=f"Sync failed: {exc}",
        )


@router.get("/inventory/maintenance", response_model=list[MaintenanceWindowResponse])
async def list_maintenance_windows(
    request: Request,
    _api_key: str = Depends(require_api_key),
) -> list[MaintenanceWindowResponse]:
    """List maintenance windows. Returns empty if none configured."""
    windows = getattr(request.app.state, "maintenance_windows", [])
    now = datetime.now(UTC)

    return [
        MaintenanceWindowResponse(
            name=w.name,
            sites=list(w.sites),
            devices=list(w.devices),
            start=w.start,
            end=w.end,
            active=(w.start is not None and w.end is not None and w.start <= now <= w.end),
        )
        for w in windows
    ]

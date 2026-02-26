"""Device status API — live TCP reachability for inventory devices."""

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from sna.api.auth import require_api_key

logger = structlog.get_logger()

router = APIRouter()


class DeviceStatusItem(BaseModel):
    """Single device with live reachability status."""

    name: str
    host: str
    platform: str
    status: str  # "reachable" | "unreachable"


class DeviceStatusResponse(BaseModel):
    """All inventory devices with reachability."""

    devices: list[DeviceStatusItem]


async def _check_port(host: str, port: int = 22, timeout: float = 3.0) -> bool:
    """Check TCP connectivity to host:port with timeout."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


@router.get("/devices/status", response_model=DeviceStatusResponse)
async def device_status(
    request: Request,
    _api_key: str = Depends(require_api_key),
) -> DeviceStatusResponse:
    """Return all inventory devices with live SSH (port 22) reachability.

    Checks all devices concurrently — 9 devices complete in ~3s worst case.
    """
    inventory = getattr(request.app.state, "device_inventory", None)
    if inventory is None or len(inventory) == 0:
        return DeviceStatusResponse(devices=[])

    device_names = inventory.list_devices()
    entries = [inventory.get_entry(name) for name in device_names]

    # Run all TCP checks concurrently
    checks = [_check_port(entry.host) for entry in entries]
    results = await asyncio.gather(*checks, return_exceptions=True)

    devices = []
    for entry, reachable in zip(entries, results):
        devices.append(
            DeviceStatusItem(
                name=entry.name,
                host=entry.host,
                platform=entry.platform.value,
                status="reachable" if reachable is True else "unreachable",
            )
        )

    await logger.ainfo(
        "device_status_check",
        total=len(devices),
        reachable=sum(1 for d in devices if d.status == "reachable"),
    )

    return DeviceStatusResponse(devices=devices)

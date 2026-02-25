"""Device inventory — resolves device names to IPs and platforms.

Loads a YAML inventory file mapping device names (e.g. "R1") to their
management IPs (e.g. "10.255.255.11") and platform types. This allows
SNA to execute on real devices without hardcoding IPs in tool calls.
"""

from __future__ import annotations

from dataclasses import dataclass

import aiofiles
import structlog
import yaml

from sna.devices.registry import Platform

logger = structlog.get_logger()

# Maps common platform alias strings to the Platform enum
PLATFORM_ALIASES: dict[str, Platform] = {
    "cisco_iosxe": Platform.IOS_XE,
    "ios-xe": Platform.IOS_XE,
    "iosxe": Platform.IOS_XE,
    "cisco_nxos": Platform.NX_OS,
    "nx-os": Platform.NX_OS,
    "nxos": Platform.NX_OS,
    "arista_eos": Platform.EOS,
    "eos": Platform.EOS,
    "juniper_junos": Platform.JUNOS,
    "junos": Platform.JUNOS,
}


@dataclass(frozen=True)
class DeviceEntry:
    """A single device in the inventory."""

    name: str
    host: str
    platform: Platform


class DeviceInventory:
    """Dict-backed device inventory with name-to-host/platform resolution."""

    def __init__(self, devices: dict[str, DeviceEntry] | None = None) -> None:
        self._devices: dict[str, DeviceEntry] = devices or {}

    def resolve_host(self, name: str) -> str | None:
        """Resolve a device name to its management IP/host.

        Returns None if the device is not in the inventory.
        """
        entry = self._devices.get(name)
        return entry.host if entry else None

    def resolve_platform(self, name: str) -> Platform | None:
        """Resolve a device name to its platform type.

        Returns None if the device is not in the inventory.
        """
        entry = self._devices.get(name)
        return entry.platform if entry else None

    def get_entry(self, name: str) -> DeviceEntry | None:
        """Get the full device entry by name."""
        return self._devices.get(name)

    def list_devices(self) -> list[str]:
        """List all device names in the inventory."""
        return list(self._devices.keys())

    def __len__(self) -> int:
        return len(self._devices)

    def __contains__(self, name: str) -> bool:
        return name in self._devices


def _resolve_platform(platform_str: str) -> Platform:
    """Resolve a platform string to a Platform enum value.

    Raises:
        ValueError: If the platform string is not recognized.
    """
    normalized = platform_str.lower().strip()
    if normalized in PLATFORM_ALIASES:
        return PLATFORM_ALIASES[normalized]
    # Try direct enum value match
    for p in Platform:
        if p.value == normalized:
            return p
    raise ValueError(
        f"Unknown platform '{platform_str}'. "
        f"Valid aliases: {', '.join(sorted(PLATFORM_ALIASES.keys()))}"
    )


async def load_inventory(file_path: str) -> DeviceInventory:
    """Load a device inventory from a YAML file.

    Expected format:
        devices:
          R1:
            host: "10.255.255.11"
            platform: cisco_iosxe

    Args:
        file_path: Path to the inventory YAML file.

    Returns:
        A populated DeviceInventory.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the YAML structure is invalid.
    """
    async with aiofiles.open(file_path, mode="r", encoding="utf-8") as f:
        raw = await f.read()

    data = yaml.safe_load(raw)
    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(f"Inventory file must contain a 'devices' key: {file_path}")

    devices_raw = data["devices"]
    if not isinstance(devices_raw, dict):
        raise ValueError(f"'devices' must be a mapping: {file_path}")

    devices: dict[str, DeviceEntry] = {}
    for name, info in devices_raw.items():
        if not isinstance(info, dict) or "host" not in info:
            raise ValueError(f"Device '{name}' must have a 'host' field")

        platform_str = info.get("platform", "cisco_iosxe")
        platform = _resolve_platform(platform_str)

        devices[name] = DeviceEntry(
            name=name,
            host=info["host"],
            platform=platform,
        )

    await logger.ainfo(
        "inventory_loaded",
        file_path=file_path,
        device_count=len(devices),
        devices=list(devices.keys()),
    )

    return DeviceInventory(devices)

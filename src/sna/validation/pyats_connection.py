"""pyATS device connection adapter.

Creates pyATS Device objects from SNA's DriverConfig.
All pyATS imports guarded with try/except ImportError.
"""

from __future__ import annotations

from sna.devices.registry import DriverConfig, Platform

# Map SNA Platform enum to pyATS os values
_PLATFORM_TO_PYATS_OS: dict[Platform, str] = {
    Platform.IOS_XE: "iosxe",
    Platform.NX_OS: "nxos",
    Platform.EOS: "eos",
    Platform.JUNOS: "junos",
}


async def create_pyats_device(driver_config: DriverConfig) -> object | None:
    """Create a pyATS Device object from SNA's DriverConfig.

    Args:
        driver_config: SNA driver configuration for the device.

    Returns:
        A pyATS Device object, or None if pyATS is not available.
    """
    try:
        from pyats.topology import Device  # type: ignore[import-untyped]
    except ImportError:
        return None

    pyats_os = _PLATFORM_TO_PYATS_OS.get(driver_config.platform, "iosxe")

    device = Device(
        name=driver_config.host,
        os=pyats_os,
        credentials={
            "default": {
                "username": driver_config.auth_username,
                "password": driver_config.auth_password,
            }
        },
        connections={
            "default": {
                "protocol": "ssh",
                "ip": driver_config.host,
                "port": driver_config.port,
            }
        },
    )

    return device

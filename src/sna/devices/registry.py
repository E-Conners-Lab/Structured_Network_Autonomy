"""Device platform registry — platform enum and driver configuration.

Defines supported network platforms and their Scrapli driver configurations.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Platform(str, enum.Enum):
    """Supported network device platforms."""

    IOS_XE = "cisco_iosxe"
    NX_OS = "cisco_nxos"
    EOS = "arista_eos"
    JUNOS = "juniper_junos"


@dataclass(frozen=True)
class DriverConfig:
    """Scrapli driver configuration for a platform.

    timeout_socket and timeout_transport are hardcoded per CLAUDE.md.
    """

    platform: Platform
    host: str
    port: int = 22
    auth_username: str = ""
    auth_password: str = ""
    auth_strict_key: bool = True
    ssh_known_hosts_file: str = "~/.ssh/known_hosts"
    timeout_socket: int = 10  # Hardcoded per CLAUDE.md — not configurable
    timeout_transport: int = 10  # Hardcoded per CLAUDE.md — not configurable
    timeout_ops: int = 30
    transport: str = "asyncssh"


# Default Scrapli platform mapping
PLATFORM_DRIVER_MAP: dict[Platform, str] = {
    Platform.IOS_XE: "cisco_iosxe",
    Platform.NX_OS: "cisco_nxos",
    Platform.EOS: "arista_eos",
    Platform.JUNOS: "juniper_junos",
}

"""Maintenance window support for context-aware policy evaluation.

Maintenance windows define periods where write operation thresholds may be
relaxed (during active windows) or auto-escalated (outside windows for covered devices).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class MaintenanceWindow:
    """A maintenance window definition."""

    name: str
    sites: tuple[str, ...] = ()
    devices: tuple[str, ...] = ()
    start: datetime | None = None
    end: datetime | None = None
    relax_thresholds: bool = True  # If True, reduce thresholds during window


def is_window_active(window: MaintenanceWindow, now: datetime | None = None) -> bool:
    """Check if a maintenance window is currently active."""
    if now is None:
        now = datetime.now(UTC)
    if window.start is None or window.end is None:
        return False
    return window.start <= now <= window.end


def find_active_windows(
    windows: list[MaintenanceWindow],
    now: datetime | None = None,
) -> list[MaintenanceWindow]:
    """Return all currently active maintenance windows."""
    return [w for w in windows if is_window_active(w, now)]


def device_in_maintenance(
    device_name: str,
    device_site: str,
    windows: list[MaintenanceWindow],
    now: datetime | None = None,
) -> MaintenanceWindow | None:
    """Check if a device is covered by an active maintenance window.

    Matches by device name or site.

    Returns:
        The matching MaintenanceWindow if found, None otherwise.
    """
    for window in find_active_windows(windows, now):
        if device_name in window.devices:
            return window
        if device_site in window.sites:
            return window
    return None


def should_escalate_outside_window(
    device_name: str,
    device_site: str,
    tool_is_write: bool,
    windows: list[MaintenanceWindow],
    now: datetime | None = None,
) -> bool:
    """Check if a write operation on a covered device should be escalated
    because it falls outside all maintenance windows.

    Only returns True if:
    1. The tool is a write operation
    2. The device IS covered by at least one window definition
    3. None of those windows are currently active
    """
    if not tool_is_write:
        return False

    # Check if device is covered by any window definition (active or not)
    covered = False
    for window in windows:
        if device_name in window.devices or device_site in window.sites:
            covered = True
            break

    if not covered:
        return False

    # Device is covered — check if any covering window is active
    active = device_in_maintenance(device_name, device_site, windows, now)
    return active is None

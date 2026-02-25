"""Tests for maintenance window support."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sna.policy.maintenance import (
    MaintenanceWindow,
    device_in_maintenance,
    find_active_windows,
    is_window_active,
    should_escalate_outside_window,
)


NOW = datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC)


class TestIsWindowActive:
    """Maintenance window active check."""

    def test_active_window(self) -> None:
        w = MaintenanceWindow(
            name="test",
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
        )
        assert is_window_active(w, NOW)

    def test_expired_window(self) -> None:
        w = MaintenanceWindow(
            name="expired",
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        assert not is_window_active(w, NOW)

    def test_future_window(self) -> None:
        w = MaintenanceWindow(
            name="future",
            start=NOW + timedelta(hours=1),
            end=NOW + timedelta(hours=2),
        )
        assert not is_window_active(w, NOW)

    def test_no_start_end(self) -> None:
        w = MaintenanceWindow(name="none")
        assert not is_window_active(w, NOW)

    def test_boundary_start(self) -> None:
        """Exactly at start time = active."""
        w = MaintenanceWindow(name="exact", start=NOW, end=NOW + timedelta(hours=1))
        assert is_window_active(w, NOW)

    def test_boundary_end(self) -> None:
        """Exactly at end time = active."""
        w = MaintenanceWindow(name="exact-end", start=NOW - timedelta(hours=1), end=NOW)
        assert is_window_active(w, NOW)


class TestFindActiveWindows:
    """Finding active windows from a list."""

    def test_filters_active(self) -> None:
        windows = [
            MaintenanceWindow(name="active", start=NOW - timedelta(hours=1), end=NOW + timedelta(hours=1)),
            MaintenanceWindow(name="expired", start=NOW - timedelta(hours=2), end=NOW - timedelta(hours=1)),
        ]
        active = find_active_windows(windows, NOW)
        assert len(active) == 1
        assert active[0].name == "active"

    def test_empty_list(self) -> None:
        assert find_active_windows([], NOW) == []


class TestDeviceInMaintenance:
    """Device-to-window matching."""

    def test_match_by_device_name(self) -> None:
        w = MaintenanceWindow(
            name="device-maint",
            devices=("sw1", "sw2"),
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
        )
        result = device_in_maintenance("sw1", "hq", [w], NOW)
        assert result is not None
        assert result.name == "device-maint"

    def test_match_by_site(self) -> None:
        w = MaintenanceWindow(
            name="site-maint",
            sites=("hq",),
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
        )
        result = device_in_maintenance("unknown-device", "hq", [w], NOW)
        assert result is not None

    def test_no_match(self) -> None:
        w = MaintenanceWindow(
            name="other",
            devices=("sw3",),
            sites=("dc1",),
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
        )
        result = device_in_maintenance("sw1", "hq", [w], NOW)
        assert result is None

    def test_inactive_window_no_match(self) -> None:
        w = MaintenanceWindow(
            name="expired",
            devices=("sw1",),
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        result = device_in_maintenance("sw1", "hq", [w], NOW)
        assert result is None


class TestShouldEscalateOutsideWindow:
    """Write operations outside maintenance windows."""

    def test_escalate_when_covered_but_outside(self) -> None:
        """Device is covered by a window definition but window is not active."""
        w = MaintenanceWindow(
            name="expired",
            devices=("sw1",),
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        assert should_escalate_outside_window("sw1", "hq", True, [w], NOW)

    def test_no_escalate_when_in_maintenance(self) -> None:
        """Device is in an active maintenance window — no escalation."""
        w = MaintenanceWindow(
            name="active",
            devices=("sw1",),
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
        )
        assert not should_escalate_outside_window("sw1", "hq", True, [w], NOW)

    def test_no_escalate_for_read_tools(self) -> None:
        """Read tools are never escalated for maintenance."""
        w = MaintenanceWindow(
            name="expired",
            devices=("sw1",),
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        assert not should_escalate_outside_window("sw1", "hq", False, [w], NOW)

    def test_no_escalate_uncovered_device(self) -> None:
        """Device not covered by any window — no escalation."""
        w = MaintenanceWindow(
            name="other",
            devices=("sw2",),
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        assert not should_escalate_outside_window("sw1", "hq", True, [w], NOW)

    def test_site_coverage(self) -> None:
        """Device covered by site in window definition."""
        w = MaintenanceWindow(
            name="site-window",
            sites=("hq",),
            start=NOW - timedelta(hours=2),
            end=NOW - timedelta(hours=1),
        )
        assert should_escalate_outside_window("sw1", "hq", True, [w], NOW)

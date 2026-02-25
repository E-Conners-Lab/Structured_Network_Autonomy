"""Tests for the device inventory module."""

from __future__ import annotations

import pytest

from sna.devices.inventory import (
    DeviceEntry,
    DeviceInventory,
    PLATFORM_ALIASES,
    _resolve_platform,
    load_inventory,
)
from sna.devices.registry import Platform


# --- DeviceEntry ---


class TestDeviceEntry:
    def test_frozen_dataclass(self):
        entry = DeviceEntry(name="R1", host="10.255.255.11", platform=Platform.IOS_XE)
        assert entry.name == "R1"
        assert entry.host == "10.255.255.11"
        assert entry.platform == Platform.IOS_XE
        with pytest.raises(AttributeError):
            entry.host = "changed"  # type: ignore[misc]


# --- DeviceInventory ---


class TestDeviceInventory:
    def _make_inventory(self) -> DeviceInventory:
        return DeviceInventory({
            "R1": DeviceEntry(name="R1", host="10.255.255.11", platform=Platform.IOS_XE),
            "R2": DeviceEntry(name="R2", host="10.255.255.12", platform=Platform.NX_OS),
        })

    def test_resolve_host_found(self):
        inv = self._make_inventory()
        assert inv.resolve_host("R1") == "10.255.255.11"

    def test_resolve_host_not_found(self):
        inv = self._make_inventory()
        assert inv.resolve_host("R99") is None

    def test_resolve_platform_found(self):
        inv = self._make_inventory()
        assert inv.resolve_platform("R2") == Platform.NX_OS

    def test_resolve_platform_not_found(self):
        inv = self._make_inventory()
        assert inv.resolve_platform("R99") is None

    def test_get_entry(self):
        inv = self._make_inventory()
        entry = inv.get_entry("R1")
        assert entry is not None
        assert entry.host == "10.255.255.11"

    def test_get_entry_not_found(self):
        inv = self._make_inventory()
        assert inv.get_entry("R99") is None

    def test_list_devices(self):
        inv = self._make_inventory()
        assert sorted(inv.list_devices()) == ["R1", "R2"]

    def test_len(self):
        inv = self._make_inventory()
        assert len(inv) == 2

    def test_contains(self):
        inv = self._make_inventory()
        assert "R1" in inv
        assert "R99" not in inv

    def test_empty_inventory(self):
        inv = DeviceInventory()
        assert len(inv) == 0
        assert inv.resolve_host("R1") is None


# --- _resolve_platform ---


class TestResolvePlatform:
    def test_cisco_iosxe(self):
        assert _resolve_platform("cisco_iosxe") == Platform.IOS_XE

    def test_ios_xe_alias(self):
        assert _resolve_platform("ios-xe") == Platform.IOS_XE

    def test_iosxe_alias(self):
        assert _resolve_platform("iosxe") == Platform.IOS_XE

    def test_nxos(self):
        assert _resolve_platform("cisco_nxos") == Platform.NX_OS

    def test_eos(self):
        assert _resolve_platform("arista_eos") == Platform.EOS

    def test_junos(self):
        assert _resolve_platform("juniper_junos") == Platform.JUNOS

    def test_case_insensitive(self):
        assert _resolve_platform("Cisco_IOSXE") == Platform.IOS_XE

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown platform"):
            _resolve_platform("unknown_platform")

    def test_all_aliases_resolve(self):
        for alias, expected in PLATFORM_ALIASES.items():
            assert _resolve_platform(alias) == expected


# --- load_inventory ---


class TestLoadInventory:
    @pytest.fixture
    def inventory_yaml(self, tmp_path):
        content = """\
devices:
  R1:
    host: "10.255.255.11"
    platform: cisco_iosxe
  R2:
    host: "10.255.255.12"
    platform: cisco_nxos
  Switch-R1:
    host: "10.255.255.21"
    platform: ios-xe
"""
        path = tmp_path / "inventory.yaml"
        path.write_text(content)
        return str(path)

    @pytest.fixture
    def minimal_yaml(self, tmp_path):
        content = """\
devices:
  R1:
    host: "10.0.0.1"
"""
        path = tmp_path / "minimal.yaml"
        path.write_text(content)
        return str(path)

    @pytest.fixture
    def bad_no_devices(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("something_else: true\n")
        return str(path)

    @pytest.fixture
    def bad_no_host(self, tmp_path):
        content = """\
devices:
  R1:
    platform: cisco_iosxe
"""
        path = tmp_path / "bad_host.yaml"
        path.write_text(content)
        return str(path)

    @pytest.mark.asyncio
    async def test_load_full_inventory(self, inventory_yaml):
        inv = await load_inventory(inventory_yaml)
        assert len(inv) == 3
        assert inv.resolve_host("R1") == "10.255.255.11"
        assert inv.resolve_platform("R1") == Platform.IOS_XE
        assert inv.resolve_host("R2") == "10.255.255.12"
        assert inv.resolve_platform("R2") == Platform.NX_OS
        assert inv.resolve_host("Switch-R1") == "10.255.255.21"
        assert inv.resolve_platform("Switch-R1") == Platform.IOS_XE

    @pytest.mark.asyncio
    async def test_load_minimal_defaults_to_iosxe(self, minimal_yaml):
        inv = await load_inventory(minimal_yaml)
        assert inv.resolve_host("R1") == "10.0.0.1"
        assert inv.resolve_platform("R1") == Platform.IOS_XE

    @pytest.mark.asyncio
    async def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            await load_inventory(str(tmp_path / "nonexistent.yaml"))

    @pytest.mark.asyncio
    async def test_missing_devices_key(self, bad_no_devices):
        with pytest.raises(ValueError, match="must contain a 'devices' key"):
            await load_inventory(bad_no_devices)

    @pytest.mark.asyncio
    async def test_missing_host_field(self, bad_no_host):
        with pytest.raises(ValueError, match="must have a 'host' field"):
            await load_inventory(bad_no_host)

    @pytest.mark.asyncio
    async def test_load_eveng_lab(self):
        """Smoke test against the actual EVE-NG lab inventory file."""
        import os
        lab_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "inventory", "eveng-lab.yaml"
        )
        if not os.path.exists(lab_path):
            pytest.skip("EVE-NG lab inventory not found")
        inv = await load_inventory(lab_path)
        assert len(inv) >= 9
        assert inv.resolve_host("R1") == "10.255.255.11"

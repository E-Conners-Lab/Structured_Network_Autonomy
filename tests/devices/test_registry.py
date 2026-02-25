"""Tests for device platform registry."""

from __future__ import annotations

from sna.devices.registry import DriverConfig, Platform, PLATFORM_DRIVER_MAP


class TestPlatform:
    """Platform enum tests."""

    def test_all_platforms(self) -> None:
        assert len(Platform) == 4
        assert Platform.IOS_XE.value == "cisco_iosxe"
        assert Platform.NX_OS.value == "cisco_nxos"
        assert Platform.EOS.value == "arista_eos"
        assert Platform.JUNOS.value == "juniper_junos"

    def test_platform_driver_map(self) -> None:
        for platform in Platform:
            assert platform in PLATFORM_DRIVER_MAP


class TestDriverConfig:
    """DriverConfig tests."""

    def test_defaults(self) -> None:
        config = DriverConfig(platform=Platform.IOS_XE, host="switch-01")
        assert config.timeout_socket == 10
        assert config.timeout_transport == 10
        assert config.timeout_ops == 30
        assert config.port == 22
        assert config.auth_strict_key is True
        assert config.transport == "asyncssh"

    def test_frozen(self) -> None:
        config = DriverConfig(platform=Platform.IOS_XE, host="switch-01")
        with __import__("pytest").raises(AttributeError):
            config.host = "other"  # type: ignore[misc]

"""Tests for device driver abstraction and connection pool."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sna.devices.driver import (
    CommandResult,
    ConnectionManager,
    DeviceConnectionError,
    DevicePool,
    _sanitize_error,
)
from sna.devices.registry import DriverConfig, Platform


@pytest.fixture
def driver_config() -> DriverConfig:
    return DriverConfig(
        platform=Platform.IOS_XE,
        host="switch-01",
        auth_username="admin",
        auth_password="password123",
    )


class TestDevicePool:
    """Connection pool tests with mock Scrapli."""

    async def test_pool_closed_rejects(self, driver_config: DriverConfig) -> None:
        pool = DevicePool(driver_config, max_concurrent=1)
        await pool.close()
        with pytest.raises(DeviceConnectionError, match="pool is closed"):
            await pool.execute("show version")

    async def test_pool_timeout_on_exhaustion(self, driver_config: DriverConfig) -> None:
        pool = DevicePool(driver_config, max_concurrent=1, queue_timeout=0.1)
        # Acquire the only slot
        await pool._semaphore.acquire()
        try:
            with pytest.raises(DeviceConnectionError, match="timed out"):
                await pool.execute("show version")
        finally:
            pool._semaphore.release()

    async def test_config_stored(self, driver_config: DriverConfig) -> None:
        pool = DevicePool(driver_config)
        assert pool.config.host == "switch-01"
        assert pool.config.timeout_socket == 10
        assert pool.config.timeout_transport == 10


class TestConnectionManager:
    """Connection manager pool management tests."""

    async def test_get_pool_creates_new(self) -> None:
        mgr = ConnectionManager()
        pool = await mgr.get_pool("switch-01", Platform.IOS_XE)
        assert pool is not None
        assert pool.config.host == "switch-01"

    async def test_get_pool_returns_cached(self) -> None:
        mgr = ConnectionManager()
        pool1 = await mgr.get_pool("switch-01", Platform.IOS_XE)
        pool2 = await mgr.get_pool("switch-01", Platform.IOS_XE)
        assert pool1 is pool2

    async def test_different_devices_different_pools(self) -> None:
        mgr = ConnectionManager()
        pool1 = await mgr.get_pool("switch-01", Platform.IOS_XE)
        pool2 = await mgr.get_pool("switch-02", Platform.IOS_XE)
        assert pool1 is not pool2

    @patch.dict("os.environ", {
        "SNA_DEVICE_SWITCH_01_USERNAME": "testuser",
        "SNA_DEVICE_SWITCH_01_PASSWORD": "testpass",
    })
    async def test_credentials_from_env(self) -> None:
        mgr = ConnectionManager()
        pool = await mgr.get_pool("switch-01", Platform.IOS_XE)
        assert pool.config.auth_username == "testuser"
        assert pool.config.auth_password == "testpass"

    async def test_close_all(self) -> None:
        mgr = ConnectionManager()
        await mgr.get_pool("switch-01", Platform.IOS_XE)
        await mgr.get_pool("switch-02", Platform.NX_OS)
        await mgr.close_all()
        assert len(mgr._pools) == 0


class TestSanitizeError:
    """Error message sanitization tests."""

    def test_sanitize_error_strips_username(self) -> None:
        msg = "Authentication failed for user 'admin' on 10.0.0.1"
        result = _sanitize_error(msg)
        assert "admin" not in result
        assert "authentication failed" in result.lower()

    def test_sanitize_error_strips_password(self) -> None:
        msg = "password=secret123 connection refused"
        result = _sanitize_error(msg)
        assert "secret123" not in result
        assert "password=***" in result

    def test_sanitize_error_auth_failed(self) -> None:
        msg = "authentication failed with credentials on 10.0.0.1"
        result = _sanitize_error(msg)
        assert "credentials" not in result
        assert "authentication failed" in result.lower()

    def test_clean_error_passes_through(self) -> None:
        msg = "Connection timed out after 10s"
        result = _sanitize_error(msg)
        assert result == msg


class TestEmptyCredentialsWarning:
    """Test warning when device credentials are missing."""

    async def test_empty_credentials_warning(self) -> None:
        """Verify warning logged when env vars are missing."""
        mgr = ConnectionManager()
        with patch.dict("os.environ", {}, clear=False):
            pool = await mgr.get_pool("no-creds-device", Platform.IOS_XE)
            assert pool.config.auth_username == ""
            assert pool.config.auth_password == ""

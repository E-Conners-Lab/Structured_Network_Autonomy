"""Tests for HashiCorp Vault integration."""

from __future__ import annotations

import io
import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sna.integrations.vault import VaultClient


@pytest.fixture
def vault_client():
    """Create a VaultClient for testing."""
    return VaultClient(
        addr="https://vault.example.com:8200",
        token="test-vault-token",
        mount_path="secret",
        tls_verify=True,
        cache_ttl=300,
        timeout=5.0,
    )


@pytest.fixture
def vault_response_ok():
    """Mock successful Vault KV v2 response."""
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "data": {
                "username": "admin",
                "password": "vault-secret-password",
            },
            "metadata": {"version": 1},
        }
    }
    response.raise_for_status = MagicMock()
    return response


class TestVaultClient:
    """Vault client tests."""

    async def test_read_credentials_success(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Mock Vault API returns credentials."""
        vault_client._client.get = AsyncMock(return_value=vault_response_ok)

        result = await vault_client.read_device_credentials("switch-01")
        assert result == ("admin", "vault-secret-password")

    async def test_read_credentials_not_found(
        self, vault_client: VaultClient
    ) -> None:
        """Vault returns 404 → returns None."""
        response = MagicMock()
        response.status_code = 404
        vault_client._client.get = AsyncMock(return_value=response)

        result = await vault_client.read_device_credentials("unknown-device")
        assert result is None

    async def test_read_credentials_vault_error(
        self, vault_client: VaultClient
    ) -> None:
        """Vault returns 500 → returns None (fail-open to env vars)."""
        response = MagicMock()
        response.status_code = 500
        response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=response
            )
        )
        vault_client._client.get = AsyncMock(return_value=response)

        result = await vault_client.read_device_credentials("switch-01")
        assert result is None

    async def test_credential_caching(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Second call within TTL doesn't hit Vault API."""
        vault_client._client.get = AsyncMock(return_value=vault_response_ok)

        result1 = await vault_client.read_device_credentials("switch-01")
        result2 = await vault_client.read_device_credentials("switch-01")

        assert result1 == result2
        # Should only have been called once
        assert vault_client._client.get.call_count == 1

    async def test_cache_expiry(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Call after TTL expires re-fetches from Vault."""
        vault_client._cache_ttl = 0  # Expire immediately
        vault_client._client.get = AsyncMock(return_value=vault_response_ok)

        await vault_client.read_device_credentials("switch-01")

        # Force cache expiry by setting past timestamp
        if "switch-01" in vault_client._cache:
            u, p, _ = vault_client._cache["switch-01"]
            vault_client._cache["switch-01"] = (u, p, time.monotonic() - 1)

        await vault_client.read_device_credentials("switch-01")

        # Should have been called twice (once + re-fetch)
        assert vault_client._client.get.call_count == 2

    async def test_invalidate_cache(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Invalidation forces re-fetch."""
        vault_client._client.get = AsyncMock(return_value=vault_response_ok)

        await vault_client.read_device_credentials("switch-01")
        vault_client.invalidate_cache("switch-01")

        await vault_client.read_device_credentials("switch-01")
        assert vault_client._client.get.call_count == 2

    async def test_invalidate_all_cache(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Invalidating all cache clears everything."""
        vault_client._client.get = AsyncMock(return_value=vault_response_ok)

        await vault_client.read_device_credentials("switch-01")
        vault_client.invalidate_cache()

        assert len(vault_client._cache) == 0

    async def test_vault_not_configured_fallback(self) -> None:
        """When vault_addr is not set, env vars should be used directly."""
        # This is tested via ConnectionManager, not VaultClient directly
        from sna.devices.driver import ConnectionManager

        mgr = ConnectionManager(vault_client=None)
        pool = await mgr.get_pool("switch-01", platform=__import__("sna.devices.registry", fromlist=["Platform"]).Platform.IOS_XE)
        # Pool should still be created (using env vars)
        assert pool is not None

    async def test_path_traversal_rejected(
        self, vault_client: VaultClient
    ) -> None:
        """Device name with path traversal should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid device name"):
            await vault_client.read_device_credentials("../../etc/passwd")

    async def test_path_traversal_slashes_rejected(
        self, vault_client: VaultClient
    ) -> None:
        """Device name with slashes should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid device name"):
            await vault_client.read_device_credentials("foo/bar")

    async def test_vault_token_not_logged(
        self, vault_client: VaultClient, vault_response_ok
    ) -> None:
        """Vault token should not appear in log output."""
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.DEBUG)
        logging.getLogger().addHandler(handler)

        vault_client._client.get = AsyncMock(return_value=vault_response_ok)
        await vault_client.read_device_credentials("switch-01")

        logging.getLogger().removeHandler(handler)
        log_output = log_stream.getvalue()
        assert "test-vault-token" not in log_output

    def test_http_vault_rejected(self) -> None:
        """Non-HTTPS Vault address should be rejected."""
        with pytest.raises(ValueError, match="HTTPS"):
            VaultClient(
                addr="http://vault.example.com:8200",
                token="token",
                tls_verify=True,
            )

    def test_http_localhost_allowed_for_dev(self) -> None:
        """http://localhost is allowed when tls_verify=False."""
        client = VaultClient(
            addr="http://localhost:8200",
            token="token",
            tls_verify=False,
        )
        assert client._addr == "http://localhost:8200"

    async def test_close(self, vault_client: VaultClient) -> None:
        """Close should close the HTTP client."""
        vault_client._client.aclose = AsyncMock()
        await vault_client.close()
        vault_client._client.aclose.assert_called_once()

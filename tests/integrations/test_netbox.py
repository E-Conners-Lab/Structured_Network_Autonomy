"""Tests for the async NetBox client — circuit breaker, caching, retry."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sna.integrations.netbox import (
    CircuitBreaker,
    NetBoxCircuitOpen,
    NetBoxClient,
    NetBoxError,
)


class TestCircuitBreaker:
    """Circuit breaker logic."""

    def test_starts_closed(self) -> None:
        cb = CircuitBreaker()
        assert not cb.is_open()

    def test_opens_after_threshold(self) -> None:
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open()

    def test_stays_closed_below_threshold(self) -> None:
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert not cb.is_open()

    def test_success_resets_failures(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        assert not cb.is_open()

    def test_closes_after_cooldown(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        cb.record_failure()
        # cooldown=0 means it's immediately past the open window
        assert not cb.is_open()

    def test_consecutive_failures_property(self) -> None:
        cb = CircuitBreaker()
        assert cb.consecutive_failures == 0
        cb.record_failure()
        cb.record_failure()
        assert cb.consecutive_failures == 2


class TestNetBoxClient:
    """NetBox client with mocked HTTP."""

    @pytest.fixture
    def client(self) -> NetBoxClient:
        return NetBoxClient(
            base_url="https://netbox.example.com",
            token="test-token",
            cache_ttl=300,
            max_retries=2,
        )

    async def test_get_device_success(self, client: NetBoxClient) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{"name": "switch-01", "role": {"slug": "access-switch"}}],
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get_device("switch-01")

        assert result is not None
        assert result["name"] == "switch-01"
        await client.close()

    async def test_get_device_not_found(self, client: NetBoxClient) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get_device("nonexistent")

        assert result is None
        await client.close()

    async def test_get_devices_success(self, client: NetBoxClient) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [{"name": "sw1"}, {"name": "sw2"}],
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get_devices(site="hq")

        assert len(result) == 2
        await client.close()

    async def test_caching(self, client: NetBoxClient) -> None:
        """Second call should use cache, not make another HTTP request."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"name": "cached-device"}]}
        mock_response.raise_for_status = MagicMock()

        mock_get = AsyncMock(return_value=mock_response)
        with patch.object(httpx.AsyncClient, "get", mock_get):
            await client.get_device("cached-device")
            await client.get_device("cached-device")

        # Only one HTTP call should be made
        assert mock_get.call_count == 1
        await client.close()

    async def test_circuit_breaker_opens(self, client: NetBoxClient) -> None:
        """After max_retries * threshold failures, circuit should open."""
        client._breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)

        with patch.object(
            httpx.AsyncClient, "get",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("timeout"),
        ):
            # First call: 2 retries = 2 failures → circuit opens
            result = await client.get_device("fail-device")
            assert result is None  # get_device returns None on error

        assert client.circuit_breaker.is_open()
        await client.close()

    async def test_circuit_open_raises(self, client: NetBoxClient) -> None:
        """When circuit is open, _request raises NetBoxCircuitOpen."""
        client._breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=999)
        client._breaker.record_failure()  # Open the circuit

        with pytest.raises(NetBoxCircuitOpen):
            await client._request("/api/dcim/devices/")
        await client.close()

    async def test_get_site(self, client: NetBoxClient) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"name": "hq-site"}]}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get_site("hq-site")

        assert result is not None
        assert result["name"] == "hq-site"
        await client.close()

    async def test_get_prefixes(self, client: NetBoxClient) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"prefix": "10.0.0.0/24"}]}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get_prefixes("hq")

        assert len(result) == 1
        await client.close()

    async def test_retry_with_eventual_success(self, client: NetBoxClient) -> None:
        """Client retries on failure and succeeds on second attempt."""
        success_response = MagicMock()
        success_response.json.return_value = {"results": [{"name": "retry-device"}]}
        success_response.raise_for_status = MagicMock()

        mock_get = AsyncMock(
            side_effect=[httpx.TimeoutException("timeout"), success_response]
        )

        with patch.object(httpx.AsyncClient, "get", mock_get):
            result = await client.get_device("retry-device")

        assert result is not None
        assert result["name"] == "retry-device"
        await client.close()

    async def test_close_idempotent(self, client: NetBoxClient) -> None:
        """Closing twice should not raise."""
        await client.close()
        await client.close()

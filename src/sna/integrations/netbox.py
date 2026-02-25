"""Async NetBox client for device inventory enrichment.

Provides methods to query NetBox for device details, sites, and prefixes.
Includes circuit breaker, TTL caching, and retry with exponential backoff.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx
import structlog

logger = structlog.get_logger()


class NetBoxError(Exception):
    """Base exception for NetBox client errors."""


class NetBoxCircuitOpen(NetBoxError):
    """Circuit breaker is open — failing fast."""


@dataclass
class CircuitBreaker:
    """Simple circuit breaker: after N consecutive failures, fail fast for cooldown_seconds."""

    failure_threshold: int = 5
    cooldown_seconds: float = 60.0
    _consecutive_failures: int = 0
    _circuit_open_until: float = 0.0

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._circuit_open_until = time.monotonic() + self.cooldown_seconds

    def is_open(self) -> bool:
        if self._consecutive_failures < self.failure_threshold:
            return False
        return time.monotonic() < self._circuit_open_until

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures


@dataclass
class CacheEntry:
    """TTL-based cache entry."""

    data: dict
    expires_at: float


class NetBoxClient:
    """Async NetBox REST API client with circuit breaker and caching.

    Args:
        base_url: NetBox base URL (e.g. "https://netbox.example.com").
        token: NetBox API token (must be read-only scope).
        timeout: HTTP request timeout in seconds.
        cache_ttl: Cache time-to-live in seconds.
        max_retries: Max retry attempts with exponential backoff.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 10.0,
        cache_ttl: float = 300.0,
        max_retries: int = 3,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._max_retries = max_retries
        self._cache: dict[str, CacheEntry] = {}
        self._breaker = CircuitBreaker()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Token {self._token}",
                    "Accept": "application/json",
                },
                timeout=self._timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _get_cached(self, key: str) -> dict | None:
        entry = self._cache.get(key)
        if entry and time.monotonic() < entry.expires_at:
            return entry.data
        if entry:
            del self._cache[key]
        return None

    def _set_cached(self, key: str, data: dict) -> None:
        self._cache[key] = CacheEntry(data=data, expires_at=time.monotonic() + self._cache_ttl)

    async def _request(self, path: str, params: dict | None = None) -> dict:
        """Make an authenticated GET request with retry, circuit breaker, and caching."""
        cache_key = f"{path}:{params}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        if self._breaker.is_open():
            raise NetBoxCircuitOpen(
                f"Circuit breaker open after {self._breaker.consecutive_failures} failures"
            )

        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                response = await client.get(path, params=params)
                response.raise_for_status()
                data = response.json()
                self._breaker.record_success()
                self._set_cached(cache_key, data)
                return data
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_error = exc
                self._breaker.record_failure()
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        raise NetBoxError(f"NetBox request failed after {self._max_retries} retries: {last_error}")

    async def get_device(self, name: str) -> dict | None:
        """Get a single device by name. Returns None if not found."""
        try:
            data = await self._request("/api/dcim/devices/", params={"name": name})
            results = data.get("results", [])
            return results[0] if results else None
        except NetBoxError:
            return None

    async def get_devices(self, **filters: str) -> list[dict]:
        """Get devices matching filters (e.g. site="hq", role="router")."""
        try:
            data = await self._request("/api/dcim/devices/", params=filters)
            return data.get("results", [])
        except NetBoxError:
            return []

    async def get_site(self, name: str) -> dict | None:
        """Get a site by name."""
        try:
            data = await self._request("/api/dcim/sites/", params={"name": name})
            results = data.get("results", [])
            return results[0] if results else None
        except NetBoxError:
            return None

    async def get_prefixes(self, site: str) -> list[dict]:
        """Get prefixes for a site."""
        try:
            data = await self._request("/api/ipam/prefixes/", params={"site": site})
            return data.get("results", [])
        except NetBoxError:
            return []

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """Access the circuit breaker for inspection/testing."""
        return self._breaker

"""HashiCorp Vault KV v2 integration — fetch device credentials.

Falls back to environment variables when Vault is not configured or
when credential lookup fails. Caches credentials with configurable TTL.

SECURITY:
- Vault token is never logged
- Device names are validated against path traversal
- TLS verification enabled by default
"""

from __future__ import annotations

import re
import time

import httpx
import structlog

logger = structlog.get_logger()

_DEVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")


class VaultClient:
    """Client for HashiCorp Vault KV v2 secret engine.

    Fetches device credentials from Vault with caching and fallback.

    Args:
        addr: Vault server address (e.g., "https://vault.example.com:8200").
        token: Vault authentication token. Treated as a secret.
        mount_path: KV v2 mount path (default: "secret").
        tls_verify: Whether to verify TLS certificates (default: True).
        cache_ttl: Credential cache TTL in seconds (default: 300).
        timeout: HTTP request timeout in seconds (default: 10.0).
    """

    def __init__(
        self,
        addr: str,
        token: str,
        mount_path: str = "secret",
        tls_verify: bool = True,
        cache_ttl: int = 300,
        timeout: float = 10.0,
    ) -> None:
        # Validate addr scheme
        if not addr.startswith("https://"):
            if addr.startswith("http://localhost") and not tls_verify:
                pass  # Allow http://localhost for dev only
            else:
                raise ValueError(
                    "Vault address must use HTTPS "
                    "(http://localhost allowed only when tls_verify=False)"
                )

        self._addr = addr.rstrip("/")
        self._token = token
        self._mount_path = mount_path
        self._cache_ttl = cache_ttl
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=tls_verify,
            headers={"X-Vault-Token": token},
        )
        # Cache: device_name → (username, password, expiry_timestamp)
        self._cache: dict[str, tuple[str, str, float]] = {}

    async def read_device_credentials(
        self, device_name: str
    ) -> tuple[str, str] | None:
        """Read device credentials from Vault KV v2.

        Args:
            device_name: Device hostname/identifier. Must match ^[a-zA-Z0-9._-]+$.

        Returns:
            (username, password) tuple, or None if not found.

        Raises:
            ValueError: If device_name fails path traversal validation.
        """
        if not _DEVICE_NAME_PATTERN.match(device_name):
            raise ValueError(
                f"Invalid device name for Vault lookup: {device_name!r}"
            )

        # Check cache
        cached = self._cache.get(device_name)
        if cached is not None:
            username, password, expiry = cached
            if time.monotonic() < expiry:
                return (username, password)
            # Expired — remove from cache
            del self._cache[device_name]

        return await self._fetch_from_vault(device_name)

    async def _fetch_from_vault(
        self, device_name: str
    ) -> tuple[str, str] | None:
        """Fetch credentials from Vault API."""
        path = f"{self._addr}/v1/{self._mount_path}/data/sna/devices/{device_name}"

        try:
            response = await self._client.get(path)

            if response.status_code == 404:
                await logger.ainfo(
                    "vault_secret_not_found",
                    device=device_name,
                )
                return None

            response.raise_for_status()
            data = response.json()

            # KV v2 response: data.data.{username, password}
            secret_data = data.get("data", {}).get("data", {})
            username = secret_data.get("username")
            password = secret_data.get("password")

            if not isinstance(username, str) or not isinstance(password, str):
                await logger.awarning(
                    "vault_invalid_credential_format",
                    device=device_name,
                )
                return None

            # Cache the result
            expiry = time.monotonic() + self._cache_ttl
            self._cache[device_name] = (username, password, expiry)

            await logger.ainfo(
                "vault_credentials_loaded",
                device=device_name,
            )
            return (username, password)

        except httpx.HTTPStatusError as exc:
            await logger.aerror(
                "vault_http_error",
                device=device_name,
                status_code=exc.response.status_code,
            )
            return None

        except httpx.RequestError:
            await logger.aerror(
                "vault_request_error",
                device=device_name,
                exc_info=True,
            )
            return None

    def invalidate_cache(self, device_name: str | None = None) -> None:
        """Invalidate cached credentials.

        Args:
            device_name: Specific device to invalidate, or None for all.
        """
        if device_name is not None:
            self._cache.pop(device_name, None)
        else:
            self._cache.clear()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

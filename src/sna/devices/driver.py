"""Async Scrapli wrapper with connection pooling.

Provides a connection pool per device with configurable concurrency limits.
When the pool is exhausted, requests queue with a timeout instead of rejecting.

SECURITY: timeout_socket=10 and timeout_transport=10 are hardcoded per CLAUDE.md.
SSH host key verification is enforced (no known_hosts=False).
Device credentials come from environment variables.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

import structlog

from sna.devices.inventory import DeviceInventory
from sna.devices.registry import DriverConfig, Platform

logger = structlog.get_logger()


def _sanitize_error(error_msg: str) -> str:
    """Remove potential credential fragments from error messages."""
    import re

    msg = re.sub(r"(?i)for user ['\"]?\S+['\"]?", "for user ***", error_msg)
    msg = re.sub(r"(?i)password\s*[:=]\s*\S+", "password=***", msg)
    msg = re.sub(r"(?i)auth(entication)?\s+failed.*", "authentication failed", msg)
    return msg


@dataclass
class CommandResult:
    """Result of executing a command on a device."""

    output: str
    success: bool
    elapsed_seconds: float
    device: str
    command: str


class DeviceConnectionError(Exception):
    """Raised when a device connection fails."""


class DevicePool:
    """Connection pool for a single device.

    Limits concurrent Scrapli sessions using a semaphore.
    When the pool is full, requests queue with a timeout.

    Args:
        config: Driver configuration for the device.
        max_concurrent: Maximum concurrent sessions (default 3).
        queue_timeout: Seconds to wait for a slot (default 30).
    """

    def __init__(
        self,
        config: DriverConfig,
        max_concurrent: int = 3,
        queue_timeout: float = 30.0,
    ) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._queue_timeout = queue_timeout
        self._closed = False

    @property
    def config(self) -> DriverConfig:
        """The driver configuration for this pool."""
        return self._config

    async def execute(self, command: str, timeout_ops: int = 30) -> CommandResult:
        """Execute a command on the device with pool-limited concurrency.

        Args:
            command: The CLI command to execute.
            timeout_ops: Per-command operation timeout in seconds.

        Returns:
            A CommandResult with the output.

        Raises:
            DeviceConnectionError: If connection fails or pool is exhausted.
        """
        if self._closed:
            raise DeviceConnectionError("Connection pool is closed")

        try:
            await asyncio.wait_for(
                self._semaphore.acquire(), timeout=self._queue_timeout
            )
        except asyncio.TimeoutError:
            raise DeviceConnectionError(
                f"Connection pool exhausted for {self._config.host}, "
                f"timed out after {self._queue_timeout}s"
            )

        try:
            return await self._execute_with_driver(command, timeout_ops)
        finally:
            self._semaphore.release()

    async def _execute_with_driver(
        self, command: str, timeout_ops: int
    ) -> CommandResult:
        """Connect to device and execute the command via Scrapli."""
        import time

        from scrapli import AsyncScrapli

        start = time.monotonic()
        try:
            driver_kwargs = {
                "host": self._config.host,
                "port": self._config.port,
                "auth_username": self._config.auth_username,
                "auth_password": self._config.auth_password,
                "auth_strict_key": self._config.auth_strict_key,
                "ssh_known_hosts_file": self._config.ssh_known_hosts_file,
                "timeout_socket": self._config.timeout_socket,
                "timeout_transport": self._config.timeout_transport,
                "timeout_ops": timeout_ops,
                "transport": self._config.transport,
                "platform": self._config.platform.value,
            }

            async with AsyncScrapli(**driver_kwargs) as conn:
                # Check if this is a config command (contains newline = multiple commands)
                if "\n" in command:
                    response = await conn.send_configs(
                        configs=command.split("\n"),
                        timeout_ops=timeout_ops,
                    )
                    output = response.result
                    success = not response.failed
                else:
                    response = await conn.send_command(
                        command=command,
                        timeout_ops=timeout_ops,
                    )
                    output = response.result
                    success = not response.failed

            elapsed = time.monotonic() - start
            return CommandResult(
                output=output,
                success=success,
                elapsed_seconds=elapsed,
                device=self._config.host,
                command=command,
            )

        except Exception as exc:
            elapsed = time.monotonic() - start
            safe_error = _sanitize_error(str(exc))
            await logger.aerror(
                "device_connection_error",
                host=self._config.host,
                error=safe_error,
                elapsed=elapsed,
            )
            raise DeviceConnectionError(
                f"Failed to execute on {self._config.host}: {safe_error}"
            ) from exc

    async def close(self) -> None:
        """Mark the pool as closed. Prevents new requests."""
        self._closed = True


class ConnectionManager:
    """Manages device connection pools.

    Creates and caches pools per device. Provides graceful shutdown.

    Args:
        max_concurrent_per_device: Max concurrent sessions per device.
    """

    def __init__(
        self,
        max_concurrent_per_device: int = 3,
        vault_client: object | None = None,
        inventory: DeviceInventory | None = None,
    ) -> None:
        self._pools: dict[str, DevicePool] = {}
        self._max_concurrent = max_concurrent_per_device
        self._vault_client = vault_client
        self._inventory = inventory

    async def get_pool(self, device_name: str, platform: Platform) -> DevicePool:
        """Get or create a connection pool for a device.

        Credentials are loaded from Vault (if configured) or environment variables:
        SNA_DEVICE_{NAME}_USERNAME and SNA_DEVICE_{NAME}_PASSWORD.

        Args:
            device_name: Device hostname/identifier.
            platform: Device platform type.

        Returns:
            A DevicePool for the device.
        """
        if device_name in self._pools:
            return self._pools[device_name]

        # Resolve host from inventory if available
        host = device_name
        if self._inventory is not None:
            resolved_host = self._inventory.resolve_host(device_name)
            if resolved_host is not None:
                host = resolved_host
                # Also resolve platform from inventory if not explicitly provided
                inv_platform = self._inventory.resolve_platform(device_name)
                if inv_platform is not None:
                    platform = inv_platform

        env_name = device_name.upper().replace("-", "_").replace(".", "_")
        username: str | None = None
        password: str | None = None

        # Try Vault first if configured
        if self._vault_client is not None:
            try:
                creds = await self._vault_client.read_device_credentials(device_name)
                if creds is not None:
                    username, password = creds
            except Exception:
                await logger.awarning(
                    "vault_credential_fetch_failed",
                    device=device_name,
                )

        # Fall back to environment variables
        if username is None:
            username = os.environ.get(f"SNA_DEVICE_{env_name}_USERNAME", "")
        if password is None:
            password = os.environ.get(f"SNA_DEVICE_{env_name}_PASSWORD", "")

        if not username or not password:
            await logger.awarning(
                "device_credentials_missing",
                device=device_name,
                env_username_var=f"SNA_DEVICE_{env_name}_USERNAME",
            )
            raise DeviceConnectionError(
                f"Missing credentials for device '{device_name}'. "
                f"Set SNA_DEVICE_{env_name}_USERNAME and SNA_DEVICE_{env_name}_PASSWORD "
                f"environment variables, or configure Vault."
            )

        config = DriverConfig(
            platform=platform,
            host=host,
            auth_username=username,
            auth_password=password,
        )

        pool = DevicePool(config, max_concurrent=self._max_concurrent)
        self._pools[device_name] = pool
        return pool

    async def close_all(self) -> None:
        """Gracefully close all device pools."""
        for pool in self._pools.values():
            await pool.close()
        self._pools.clear()
        await logger.ainfo("connection_pools_closed")

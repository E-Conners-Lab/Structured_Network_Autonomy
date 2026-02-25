"""Rollback executor — restores device config from stored rollback data.

Used by post-change validation (Phase 7) and available as admin API.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import ExecutionLog
from sna.devices.driver import ConnectionManager, DeviceConnectionError
from sna.devices.registry import Platform

logger = structlog.get_logger()


class RollbackError(Exception):
    """Raised when a rollback operation fails."""


class RollbackExecutor:
    """Restores device configuration from stored rollback data.

    Args:
        connection_manager: Manages device connection pools.
        session_factory: Async SQLAlchemy session factory.
    """

    def __init__(
        self,
        connection_manager: ConnectionManager,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._connections = connection_manager
        self._session_factory = session_factory

    async def rollback(
        self,
        execution_log_id: int,
        platform: Platform = Platform.IOS_XE,
    ) -> bool:
        """Rollback a device to its pre-change configuration.

        Args:
            execution_log_id: The ID of the ExecutionLog entry to rollback.
            platform: Device platform.

        Returns:
            True if rollback succeeded, False otherwise.

        Raises:
            RollbackError: If the execution log or rollback data is missing.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(ExecutionLog).where(ExecutionLog.id == execution_log_id)
            )
            log_entry = result.scalar_one_or_none()

        if log_entry is None:
            raise RollbackError(f"Execution log not found: {execution_log_id}")

        if not log_entry.rollback_data:
            raise RollbackError(
                f"No rollback data available for execution {execution_log_id}"
            )

        device = log_entry.device_target
        pool = self._connections.get_pool(device, platform)

        try:
            # Push the stored config back to the device
            config_lines = log_entry.rollback_data.strip().split("\n")
            # Filter out comments and empty lines
            commands = [
                line.strip()
                for line in config_lines
                if line.strip() and not line.strip().startswith("!")
            ]

            result = await pool.execute(
                "\n".join(commands),
                timeout_ops=120,
            )

            if result.success:
                await logger.ainfo(
                    "rollback_success",
                    execution_log_id=execution_log_id,
                    device=device,
                )
                return True

            await logger.aerror(
                "rollback_command_failed",
                execution_log_id=execution_log_id,
                device=device,
                output=result.output,
            )
            return False

        except DeviceConnectionError as exc:
            await logger.aerror(
                "rollback_connection_failed",
                execution_log_id=execution_log_id,
                device=device,
                error=str(exc),
            )
            raise RollbackError(
                f"Rollback failed for {device}: {exc}"
            ) from exc

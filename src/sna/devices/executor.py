"""Device execution service — runs approved commands on network devices.

Accepts an EvaluationResult as proof of PERMIT. Does not re-evaluate.
Captures pre-change config for write operations (rollback support).
All output is sanitized before storage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import ExecutionLog
from sna.devices.command_builder import CommandBuilder, CommandValidationError
from sna.devices.driver import CommandResult, ConnectionManager, DeviceConnectionError
from sna.devices.registry import Platform
from sna.devices.sanitizer import sanitize_output
from sna.policy.models import EvaluationResult, RiskTier, Verdict

logger = structlog.get_logger()

# Tools that modify device configuration (require rollback capture)
WRITE_TOOLS = {
    "set_interface_description",
    "configure_logging",
    "configure_static_route",
    "configure_vlan",
    "configure_acl",
    "configure_bgp_neighbor",
    "configure_ospf_area",
    "modify_security_policy",
}


@dataclass(frozen=True)
class ExecutionResult:
    """Result of executing a command on a device."""

    success: bool
    output: str
    duration_seconds: float
    device: str
    command: str
    rollback_data: str | None = None
    error: str | None = None


class DeviceExecutor:
    """Executes approved commands on network devices.

    Args:
        command_builder: Builds validated CLI commands from tool params.
        connection_manager: Manages device connection pools.
        session_factory: Async SQLAlchemy session factory for logging.
    """

    def __init__(
        self,
        command_builder: CommandBuilder,
        connection_manager: ConnectionManager,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._builder = command_builder
        self._connections = connection_manager
        self._session_factory = session_factory

    async def execute(
        self,
        tool_name: str,
        device_target: str,
        params: dict[str, str],
        evaluation_result: EvaluationResult,
        platform: Platform = Platform.IOS_XE,
    ) -> ExecutionResult:
        """Execute an approved tool on a device.

        Args:
            tool_name: The MCP tool name.
            device_target: The device hostname/identifier.
            params: Tool parameters.
            evaluation_result: Proof of PERMIT verdict.
            platform: Device platform (default IOS-XE).

        Returns:
            An ExecutionResult with the outcome.

        Raises:
            ValueError: If evaluation result is not PERMIT.
            CommandValidationError: If parameters fail validation.
            DeviceConnectionError: If device connection fails.
        """
        if evaluation_result.verdict != Verdict.PERMIT:
            raise ValueError(
                f"Cannot execute with verdict {evaluation_result.verdict.value}"
            )

        # Build the validated command
        try:
            command = self._builder.build(tool_name, params)
        except CommandValidationError as exc:
            await logger.aerror(
                "command_build_failed",
                tool_name=tool_name,
                device=device_target,
                error=str(exc),
            )
            return ExecutionResult(
                success=False,
                output="",
                duration_seconds=0.0,
                device=device_target,
                command="",
                error=str(exc),
            )

        timeout = self._builder.get_timeout(tool_name)
        pool = self._connections.get_pool(device_target, platform)

        # Capture pre-change config for write tools
        rollback_data: str | None = None
        if tool_name in WRITE_TOOLS:
            try:
                config_result = await pool.execute("show running-config", timeout_ops=60)
                if config_result.success:
                    rollback_data = config_result.output
            except DeviceConnectionError:
                await logger.awarning(
                    "rollback_capture_failed",
                    tool_name=tool_name,
                    device=device_target,
                )

        # Execute the command
        try:
            result = await pool.execute(command, timeout_ops=timeout)
        except DeviceConnectionError as exc:
            execution_result = ExecutionResult(
                success=False,
                output="",
                duration_seconds=0.0,
                device=device_target,
                command=command,
                error=str(exc),
            )
            await self._log_execution(
                tool_name, device_target, command, execution_result
            )
            return execution_result

        # Sanitize output before storage
        sanitized_output = sanitize_output(result.output)

        execution_result = ExecutionResult(
            success=result.success,
            output=sanitized_output,
            duration_seconds=result.elapsed_seconds,
            device=device_target,
            command=command,
            rollback_data=rollback_data,
        )

        await self._log_execution(
            tool_name, device_target, command, execution_result
        )

        await logger.ainfo(
            "device_execution_complete",
            tool_name=tool_name,
            device=device_target,
            success=result.success,
            duration=result.elapsed_seconds,
        )

        return execution_result

    async def _log_execution(
        self,
        tool_name: str,
        device: str,
        command: str,
        result: ExecutionResult,
    ) -> None:
        """Write execution to the ExecutionLog."""
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    log_entry = ExecutionLog(
                        tool_name=tool_name,
                        device_target=device,
                        command_sent=command,
                        output=result.output,
                        success=result.success,
                        duration_seconds=result.duration_seconds,
                        rollback_data=result.rollback_data,
                        error=result.error,
                    )
                    session.add(log_entry)
        except Exception:
            await logger.aerror(
                "execution_log_write_failed",
                tool_name=tool_name,
                device=device,
                exc_info=True,
            )

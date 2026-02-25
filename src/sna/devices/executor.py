"""Device execution service — runs approved commands on network devices.

Accepts an EvaluationResult as proof of PERMIT. Does not re-evaluate.
Captures pre-change config for write operations (rollback support).
All output is sanitized before storage.
Post-change validation is run for write tools when a ValidationEngine is configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import ExecutionLog, ValidationLog
from sna.devices.command_builder import CommandBuilder, CommandValidationError
from sna.devices.driver import CommandResult, ConnectionManager, DeviceConnectionError
from sna.devices.registry import Platform
from sna.devices.sanitizer import sanitize_output
from sna.policy.models import EvaluationResult, RiskTier, Verdict
from sna.validation.validator import ValidationResult

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
    validation_results: tuple[ValidationResult, ...] = ()
    validation_triggered_rollback: bool = False


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
        validation_engine: object | None = None,
        validation_trigger_rollback: bool = True,
    ) -> None:
        self._builder = command_builder
        self._connections = connection_manager
        self._session_factory = session_factory
        self._validation_engine = validation_engine  # ValidationEngine (avoid circular import)
        self._validation_trigger_rollback = validation_trigger_rollback

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

        execution_log_id = await self._log_execution(
            tool_name, device_target, command, execution_result
        )

        # Post-change validation for write tools
        validation_results: list[ValidationResult] = []
        validation_triggered_rollback = False

        if (
            self._validation_engine is not None
            and tool_name in WRITE_TOOLS
            and result.success
        ):
            try:
                before_state = {"running_config": rollback_data or ""}
                after_state: dict[str, str] = {"running_config": sanitized_output}

                validation_results = await self._validation_engine.run_validations(
                    tool_name, device_target, before_state, after_state,
                )

                # Persist validation results
                await self._log_validations(
                    execution_log_id, tool_name, device_target, validation_results,
                    triggered_rollback=False,
                )

                # Check for failures and trigger rollback if configured
                if self._validation_engine.has_failures(validation_results):
                    if self._validation_trigger_rollback:
                        validation_triggered_rollback = True
                        await logger.awarning(
                            "validation_failed_rollback_triggered",
                            tool_name=tool_name,
                            device=device_target,
                        )
                        # Update validation logs with rollback flag
                        await self._log_validations(
                            execution_log_id, tool_name, device_target,
                            validation_results, triggered_rollback=True,
                        )

                    execution_result = ExecutionResult(
                        success=False,
                        output=sanitized_output,
                        duration_seconds=result.elapsed_seconds,
                        device=device_target,
                        command=command,
                        rollback_data=rollback_data,
                        error="Post-change validation failed",
                        validation_results=tuple(validation_results),
                        validation_triggered_rollback=validation_triggered_rollback,
                    )

                    await logger.ainfo(
                        "device_execution_complete",
                        tool_name=tool_name,
                        device=device_target,
                        success=False,
                        duration=result.elapsed_seconds,
                        validation_failed=True,
                    )
                    return execution_result

            except Exception:
                await logger.aerror(
                    "post_change_validation_error",
                    tool_name=tool_name,
                    device=device_target,
                    exc_info=True,
                )

        execution_result = ExecutionResult(
            success=result.success,
            output=sanitized_output,
            duration_seconds=result.elapsed_seconds,
            device=device_target,
            command=command,
            rollback_data=rollback_data,
            validation_results=tuple(validation_results),
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
    ) -> int | None:
        """Write execution to the ExecutionLog. Returns the log entry ID."""
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
                    await session.flush()
                    return log_entry.id
        except Exception:
            await logger.aerror(
                "execution_log_write_failed",
                tool_name=tool_name,
                device=device,
                exc_info=True,
            )
            return None

    async def _log_validations(
        self,
        execution_log_id: int | None,
        tool_name: str,
        device_target: str,
        results: list[ValidationResult],
        triggered_rollback: bool = False,
    ) -> None:
        """Persist validation results to the ValidationLog table."""
        if not results:
            return

        try:
            async with self._session_factory() as session:
                async with session.begin():
                    for vr in results:
                        # Sanitize message and details before storage
                        sanitized_message = sanitize_output(vr.message)
                        sanitized_details = None
                        if vr.details:
                            sanitized_details = {
                                k: sanitize_output(str(v)) if isinstance(v, str) else v
                                for k, v in vr.details.items()
                            }

                        log_entry = ValidationLog(
                            execution_log_id=execution_log_id,
                            tool_name=tool_name,
                            device_target=device_target,
                            testcase_name=vr.testcase_name,
                            status=vr.status.value,
                            message=sanitized_message,
                            details=sanitized_details,
                            duration_seconds=vr.duration_seconds,
                            triggered_rollback=triggered_rollback,
                        )
                        session.add(log_entry)
        except Exception:
            await logger.aerror(
                "validation_log_write_failed",
                tool_name=tool_name,
                device=device_target,
                exc_info=True,
            )

"""Tests for DeviceExecutor with mock driver."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import Base, ExecutionLog
from sna.devices.command_builder import create_default_command_builder
from sna.devices.driver import CommandResult, ConnectionManager, DeviceConnectionError
from sna.devices.executor import DeviceExecutor
from sna.devices.registry import Platform
from sna.policy.models import EvaluationResult, RiskTier, Verdict


@pytest.fixture
async def executor_setup():
    """Create a DeviceExecutor with in-memory DB and mock connection manager."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    command_builder = create_default_command_builder()
    connection_manager = ConnectionManager()

    executor = DeviceExecutor(
        command_builder=command_builder,
        connection_manager=connection_manager,
        session_factory=session_factory,
    )

    yield executor, session_factory, connection_manager

    await engine.dispose()


def _permit_result(tool_name: str = "show_interfaces") -> EvaluationResult:
    return EvaluationResult(
        verdict=Verdict.PERMIT,
        risk_tier=RiskTier.TIER_1_READ,
        tool_name=tool_name,
        reason="Permitted",
        confidence_score=0.99,
        confidence_threshold=0.1,
        device_count=1,
    )


def _block_result() -> EvaluationResult:
    return EvaluationResult(
        verdict=Verdict.BLOCK,
        risk_tier=RiskTier.TIER_5_CRITICAL,
        tool_name="factory_reset",
        reason="Hard-blocked",
        confidence_score=0.99,
        confidence_threshold=1.0,
        device_count=1,
    )


class TestDeviceExecutor:
    """DeviceExecutor tests with mocked device connections."""

    async def test_rejects_non_permit_verdict(self, executor_setup) -> None:
        executor, _, _ = executor_setup
        with pytest.raises(ValueError, match="Cannot execute with verdict BLOCK"):
            await executor.execute(
                tool_name="factory_reset",
                device_target="switch-01",
                params={},
                evaluation_result=_block_result(),
            )

    async def test_invalid_params_returns_failure(self, executor_setup) -> None:
        executor, _, _ = executor_setup
        result = await executor.execute(
            tool_name="ping",
            device_target="switch-01",
            params={"target": "not-an-ip"},
            evaluation_result=_permit_result("ping"),
        )
        assert result.success is False
        assert "not a valid IPv4" in (result.error or "")

    async def test_unknown_tool_returns_failure(self, executor_setup) -> None:
        executor, _, _ = executor_setup
        result = await executor.execute(
            tool_name="nonexistent_tool",
            device_target="switch-01",
            params={},
            evaluation_result=EvaluationResult(
                verdict=Verdict.PERMIT,
                risk_tier=RiskTier.TIER_1_READ,
                tool_name="nonexistent_tool",
                reason="Permitted",
                confidence_score=0.99,
                confidence_threshold=0.1,
                device_count=1,
            ),
        )
        assert result.success is False
        assert "Unknown tool" in (result.error or "")

    async def test_connection_error_logged(self, executor_setup) -> None:
        executor, session_factory, connection_manager = executor_setup

        # Mock the pool to raise DeviceConnectionError
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(
            side_effect=DeviceConnectionError("Connection refused")
        )
        connection_manager._pools["switch-01"] = mock_pool

        result = await executor.execute(
            tool_name="show_interfaces",
            device_target="switch-01",
            params={},
            evaluation_result=_permit_result(),
        )
        assert result.success is False
        assert "Connection refused" in (result.error or "")

    async def test_successful_execution_logged(self, executor_setup) -> None:
        executor, session_factory, connection_manager = executor_setup

        # Mock the pool to return success
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(return_value=CommandResult(
            output="Interface GigabitEthernet0/1 is up",
            success=True,
            elapsed_seconds=0.5,
            device="switch-01",
            command="show interfaces",
        ))
        connection_manager._pools["switch-01"] = mock_pool

        result = await executor.execute(
            tool_name="show_interfaces",
            device_target="switch-01",
            params={},
            evaluation_result=_permit_result(),
        )
        assert result.success is True
        assert "GigabitEthernet0/1" in result.output

        # Verify execution was logged
        from sqlalchemy import select, func
        async with session_factory() as session:
            count = await session.execute(
                select(func.count(ExecutionLog.id))
            )
            assert count.scalar() >= 1

    async def test_output_sanitized_before_storage(self, executor_setup) -> None:
        executor, session_factory, connection_manager = executor_setup

        # Mock pool returning output with passwords
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(return_value=CommandResult(
            output="enable secret 5 $1$mERr$hash\ninterface Gi0/1",
            success=True,
            elapsed_seconds=0.3,
            device="switch-01",
            command="show running-config",
        ))
        connection_manager._pools["switch-01"] = mock_pool

        result = await executor.execute(
            tool_name="show_running_config",
            device_target="switch-01",
            params={},
            evaluation_result=_permit_result("show_running_config"),
        )
        assert "$1$mERr$hash" not in result.output
        assert "***REDACTED***" in result.output

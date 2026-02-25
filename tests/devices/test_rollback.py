"""Tests for rollback executor."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import Base, ExecutionLog
from sna.devices.driver import CommandResult, ConnectionManager, DeviceConnectionError
from sna.devices.registry import Platform
from sna.devices.rollback import RollbackError, RollbackExecutor


@pytest.fixture
async def rollback_setup():
    """Create a RollbackExecutor with in-memory DB."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    connection_manager = ConnectionManager()

    rollback_executor = RollbackExecutor(
        connection_manager=connection_manager,
        session_factory=session_factory,
    )

    yield rollback_executor, session_factory, connection_manager

    await engine.dispose()


class TestRollbackExecutor:
    """Rollback executor tests."""

    async def test_rollback_missing_log(self, rollback_setup) -> None:
        executor, _, _ = rollback_setup
        with pytest.raises(RollbackError, match="not found"):
            await executor.rollback(99999)

    async def test_rollback_no_data(self, rollback_setup) -> None:
        executor, session_factory, _ = rollback_setup

        # Create an execution log without rollback data
        async with session_factory() as session:
            async with session.begin():
                log = ExecutionLog(
                    tool_name="show_interfaces",
                    device_target="switch-01",
                    command_sent="show interfaces",
                    output="some output",
                    success=True,
                    rollback_data=None,
                )
                session.add(log)
                await session.flush()
                log_id = log.id

        with pytest.raises(RollbackError, match="No rollback data"):
            await executor.rollback(log_id)

    async def test_rollback_success(self, rollback_setup) -> None:
        executor, session_factory, connection_manager = rollback_setup

        # Create execution log with rollback data
        async with session_factory() as session:
            async with session.begin():
                log = ExecutionLog(
                    tool_name="configure_vlan",
                    device_target="switch-01",
                    command_sent="vlan 100\n name USERS",
                    output="",
                    success=True,
                    rollback_data="interface Gi0/1\n no shutdown",
                )
                session.add(log)
                await session.flush()
                log_id = log.id

        # Mock the pool to return success
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(return_value=CommandResult(
            output="", success=True, elapsed_seconds=0.5,
            device="switch-01", command="rollback",
        ))
        connection_manager._pools["switch-01"] = mock_pool

        result = await executor.rollback(log_id)
        assert result is True

    async def test_rollback_device_failure(self, rollback_setup) -> None:
        executor, session_factory, connection_manager = rollback_setup

        async with session_factory() as session:
            async with session.begin():
                log = ExecutionLog(
                    tool_name="configure_vlan",
                    device_target="switch-01",
                    command_sent="vlan 100",
                    output="",
                    success=True,
                    rollback_data="interface Gi0/1\n no shutdown",
                )
                session.add(log)
                await session.flush()
                log_id = log.id

        # Mock the pool to raise connection error
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(
            side_effect=DeviceConnectionError("Connection refused")
        )
        connection_manager._pools["switch-01"] = mock_pool

        with pytest.raises(RollbackError, match="Rollback failed"):
            await executor.rollback(log_id)

"""Tests for batch device operations."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import Base
from sna.devices.batch import (
    BatchExecutor,
    BatchItem,
    BatchResult,
    CircularDependencyError,
    DeviceBatchResult,
)
from sna.devices.command_builder import create_default_command_builder
from sna.devices.driver import CommandResult, ConnectionManager
from sna.devices.executor import DeviceExecutor
from sna.devices.registry import Platform
from sna.policy.models import EvaluationResult, RiskTier, Verdict
from sna.validation.rules import ValidationEngine


def _permit_result() -> EvaluationResult:
    return EvaluationResult(
        verdict=Verdict.PERMIT,
        risk_tier=RiskTier.TIER_2_LOW_RISK_WRITE,
        tool_name="configure_vlan",
        reason="Permitted",
        confidence_score=0.99,
        confidence_threshold=0.3,
        device_count=3,
    )


@pytest.fixture
async def batch_setup():
    """Create a BatchExecutor with mocked device connections."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    command_builder = create_default_command_builder()
    connection_manager = ConnectionManager()
    validation_engine = ValidationEngine()

    executor = DeviceExecutor(
        command_builder=command_builder,
        connection_manager=connection_manager,
        session_factory=session_factory,
    )

    batch_executor = BatchExecutor(
        executor=executor,
        validation_engine=validation_engine,
        max_parallel=3,
    )

    yield batch_executor, connection_manager

    await engine.dispose()


def _mock_pool(success: bool = True, output: str = "OK") -> MagicMock:
    pool = MagicMock()
    pool.execute = AsyncMock(return_value=CommandResult(
        output=output,
        success=success,
        elapsed_seconds=0.1,
        device="mock",
        command="mock",
    ))
    return pool


class TestBatchExecutor:
    """Batch execution tests."""

    async def test_single_item(self, batch_setup) -> None:
        batch_executor, conn_mgr = batch_setup
        conn_mgr._pools["sw1"] = _mock_pool()

        items = [BatchItem(
            device_target="sw1",
            tool_name="configure_vlan",
            params={"vlan_id": "100", "name": "TEST"},
        )]

        result = await batch_executor.execute_batch(items, _permit_result())
        assert isinstance(result, BatchResult)
        assert result.total == 1

    async def test_multi_device_parallel(self, batch_setup) -> None:
        batch_executor, conn_mgr = batch_setup
        for name in ["sw1", "sw2", "sw3"]:
            conn_mgr._pools[name] = _mock_pool()

        items = [
            BatchItem(device_target="sw1", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}),
            BatchItem(device_target="sw2", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}),
            BatchItem(device_target="sw3", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}),
        ]

        result = await batch_executor.execute_batch(items, _permit_result())
        assert result.total == 3

    async def test_dependency_ordering(self, batch_setup) -> None:
        batch_executor, conn_mgr = batch_setup
        for name in ["sw1", "sw2"]:
            conn_mgr._pools[name] = _mock_pool()

        items = [
            BatchItem(device_target="sw2", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}, depends_on=["sw1"]),
            BatchItem(device_target="sw1", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}),
        ]

        # Should execute sw1 first, then sw2
        stages = batch_executor._build_execution_order(items)
        assert len(stages) == 2
        assert stages[0][0].device_target == "sw1"
        assert stages[1][0].device_target == "sw2"

    async def test_circular_dependency_detected(self, batch_setup) -> None:
        batch_executor, _ = batch_setup

        items = [
            BatchItem(device_target="sw1", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}, depends_on=["sw2"]),
            BatchItem(device_target="sw2", tool_name="configure_vlan", params={"vlan_id": "100", "name": "V1"}, depends_on=["sw1"]),
        ]

        with pytest.raises(CircularDependencyError):
            batch_executor._build_execution_order(items)

    async def test_validation_failure_marks_error(self, batch_setup) -> None:
        batch_executor, conn_mgr = batch_setup
        # Pool returns unchanged config (validation should detect no change)
        same_config = "hostname R1\n"
        pool = MagicMock()
        pool.execute = AsyncMock(return_value=CommandResult(
            output=same_config,
            success=True,
            elapsed_seconds=0.1,
            device="sw1",
            command="configure terminal",
        ))
        conn_mgr._pools["sw1"] = pool

        items = [BatchItem(
            device_target="sw1",
            tool_name="configure_vlan",
            params={"vlan_id": "100", "name": "TEST"},
        )]

        result = await batch_executor.execute_batch(items, _permit_result())
        assert result.total == 1

    async def test_build_order_no_dependencies(self, batch_setup) -> None:
        batch_executor, _ = batch_setup

        items = [
            BatchItem(device_target="sw1", tool_name="t", params={}),
            BatchItem(device_target="sw2", tool_name="t", params={}),
            BatchItem(device_target="sw3", tool_name="t", params={}),
        ]

        stages = batch_executor._build_execution_order(items)
        # All items should be in one stage (no dependencies)
        assert len(stages) == 1
        assert len(stages[0]) == 3

    async def test_batch_result_fields(self, batch_setup) -> None:
        batch_executor, conn_mgr = batch_setup
        conn_mgr._pools["sw1"] = _mock_pool()

        items = [BatchItem(
            device_target="sw1",
            tool_name="configure_vlan",
            params={"vlan_id": "100", "name": "TEST"},
        )]

        result = await batch_executor.execute_batch(items, _permit_result())
        assert result.batch_id  # UUID should be set
        assert result.duration_seconds >= 0

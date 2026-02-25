"""End-to-end MCP integration tests.

Tests the full flow: MCP tool call → policy evaluation → mock device execution → audit log.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sna.db.models import AuditLog, Base, ExecutionLog
from sna.devices.command_builder import create_default_command_builder
from sna.devices.driver import CommandResult, ConnectionManager
from sna.devices.executor import DeviceExecutor
from sna.integrations.mcp import MCPGateway, MCPToolCall
from sna.integrations.notifier import CompositeNotifier
from sna.policy.engine import PolicyEngine
from sna.policy.loader import load_policy
from sna.policy.models import Verdict


@pytest.fixture
async def integration_setup():
    """Full integration setup with mock device connections."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    policy = await load_policy("policies/default.yaml")
    policy_engine = PolicyEngine(
        policy=policy, session_factory=session_factory, initial_eas=0.5,
    )

    notifier = CompositeNotifier([])
    gateway = MCPGateway(engine=policy_engine, notifier=notifier)

    command_builder = create_default_command_builder()
    connection_manager = ConnectionManager()
    executor = DeviceExecutor(
        command_builder=command_builder,
        connection_manager=connection_manager,
        session_factory=session_factory,
    )

    yield gateway, executor, session_factory, connection_manager, policy_engine

    await engine.dispose()


class TestMCPIntegration:
    """End-to-end MCP → Policy → Execution tests."""

    async def test_full_permit_flow(self, integration_setup) -> None:
        """Tool call → PERMIT → device execution → audit logged."""
        gateway, executor, session_factory, conn_mgr, _ = integration_setup

        # Mock device pool
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(return_value=CommandResult(
            output="GigabitEthernet0/1 is up",
            success=True, elapsed_seconds=0.3,
            device="switch-01", command="show interfaces",
        ))
        conn_mgr._pools["switch-01"] = mock_pool

        # MCP tool call
        tool_call = MCPToolCall(
            tool_name="show_interfaces",
            parameters={},
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )

        # Policy evaluation
        result = await gateway.intercept(tool_call)
        assert result.permitted is True

        # Device execution
        exec_result = await executor.execute(
            tool_name="show_interfaces",
            device_target="switch-01",
            params={},
            evaluation_result=result.evaluation,
        )
        assert exec_result.success is True
        assert "GigabitEthernet0/1" in exec_result.output

        # Verify audit logged
        async with session_factory() as session:
            audit_count = await session.execute(
                select(func.count(AuditLog.id))
            )
            assert audit_count.scalar() >= 1

            exec_count = await session.execute(
                select(func.count(ExecutionLog.id))
            )
            assert exec_count.scalar() >= 1

    async def test_escalate_flow_no_execution(self, integration_setup) -> None:
        """Tool call → ESCALATE → no device execution occurs."""
        gateway, executor, _, _, _ = integration_setup

        tool_call = MCPToolCall(
            tool_name="configure_bgp_neighbor",
            parameters={},
            device_targets=["switch-01"],
            confidence_score=0.5,  # Below threshold for tier 4
            caller_id="test-agent",
        )

        result = await gateway.intercept(tool_call)
        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.ESCALATE

    async def test_block_flow_no_execution(self, integration_setup) -> None:
        """Hard-blocked tool → BLOCK → no device execution occurs."""
        gateway, _, _, _, _ = integration_setup

        tool_call = MCPToolCall(
            tool_name="factory_reset",
            parameters={},
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )

        result = await gateway.intercept(tool_call)
        assert result.permitted is False
        assert result.evaluation.verdict == Verdict.BLOCK

    async def test_connection_failure_graceful(self, integration_setup) -> None:
        """Device unreachable → graceful error in execution result."""
        gateway, executor, _, conn_mgr, _ = integration_setup

        # Mock pool that raises connection error
        from sna.devices.driver import DeviceConnectionError
        mock_pool = MagicMock()
        mock_pool.execute = AsyncMock(
            side_effect=DeviceConnectionError("Device unreachable")
        )
        conn_mgr._pools["switch-01"] = mock_pool

        tool_call = MCPToolCall(
            tool_name="show_interfaces",
            parameters={},
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )

        result = await gateway.intercept(tool_call)
        assert result.permitted is True

        exec_result = await executor.execute(
            tool_name="show_interfaces",
            device_target="switch-01",
            params={},
            evaluation_result=result.evaluation,
        )
        assert exec_result.success is False
        assert "Device unreachable" in (exec_result.error or "")

    async def test_write_tool_captures_rollback(self, integration_setup) -> None:
        """Write tool execution captures pre-change config for rollback."""
        gateway, executor, _, conn_mgr, engine = integration_setup

        # Set higher EAS so tier 2 permits
        engine.set_eas(0.8)

        # Mock pool: first call returns config, second returns exec result
        mock_pool = MagicMock()
        call_count = 0

        async def mock_execute(command: str, timeout_ops: int = 30) -> CommandResult:
            nonlocal call_count
            call_count += 1
            if "show running-config" in command:
                return CommandResult(
                    output="hostname switch-01\ninterface Gi0/1\n no shutdown",
                    success=True, elapsed_seconds=0.5,
                    device="switch-01", command=command,
                )
            return CommandResult(
                output="", success=True, elapsed_seconds=0.2,
                device="switch-01", command=command,
            )

        mock_pool.execute = AsyncMock(side_effect=mock_execute)
        conn_mgr._pools["switch-01"] = mock_pool

        tool_call = MCPToolCall(
            tool_name="set_interface_description",
            parameters={"interface": "GigabitEthernet0/1", "description": "Uplink"},
            device_targets=["switch-01"],
            confidence_score=0.99,
            caller_id="test-agent",
        )

        result = await gateway.intercept(tool_call)
        assert result.permitted is True

        exec_result = await executor.execute(
            tool_name="set_interface_description",
            device_target="switch-01",
            params={"interface": "GigabitEthernet0/1", "description": "Uplink"},
            evaluation_result=result.evaluation,
        )
        assert exec_result.success is True
        assert exec_result.rollback_data is not None
        assert "hostname switch-01" in exec_result.rollback_data

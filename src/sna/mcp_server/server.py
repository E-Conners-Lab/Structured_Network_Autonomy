"""FastMCP server — exposes SNA tools to AI agents via MCP protocol.

Instantiates its own PolicyEngine, MCPGateway, and Scrapli connection pool.
Each tool call flows through: MCPGateway.intercept() → if PERMIT → DeviceExecutor.execute().
"""

from __future__ import annotations

from typing import Any

import structlog
from fastmcp import FastMCP

from sna.config import Settings
from sna.db.models import Base
from sna.db.session import create_async_engine_from_url, create_session_factory
from sna.devices.command_builder import CommandValidationError, create_default_command_builder
from sna.devices.driver import ConnectionManager, DeviceConnectionError
from sna.devices.executor import DeviceExecutor
from sna.integrations.mcp import MCPGateway, MCPToolCall
from sna.validation.rules import ValidationEngine
from sna.integrations.netbox import NetBoxClient
from sna.integrations.notifier import create_notifier
from sna.mcp_server.tools.read import READ_TOOLS
from sna.mcp_server.tools.write import WRITE_TOOLS
from sna.policy.engine import PolicyEngine
from sna.policy.models import Verdict

logger = structlog.get_logger()


async def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Create and configure the MCP server with all tools registered.

    Args:
        settings: Application settings. If None, loads from environment.

    Returns:
        A configured FastMCP instance ready to serve.
    """
    if settings is None:
        from sna.config import get_settings
        settings = get_settings()

    # Initialize infrastructure
    engine = create_async_engine_from_url(
        settings.database_url,
        pool_timeout=settings.db_pool_timeout,
        connect_timeout=settings.db_connect_timeout,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = create_session_factory(engine)

    # Initialize NetBox client (optional)
    netbox_client: NetBoxClient | None = None
    if settings.netbox_url and settings.netbox_token:
        netbox_client = NetBoxClient(
            base_url=settings.netbox_url,
            token=settings.netbox_token,
            timeout=settings.httpx_timeout_seconds,
            cache_ttl=settings.netbox_cache_ttl,
        )

    # Initialize policy engine
    policy_engine = await PolicyEngine.from_config(
        policy_file_path=settings.policy_file_path,
        session_factory=session_factory,
        default_eas=settings.default_eas,
        netbox_client=netbox_client,
        enrichment_enabled=settings.enrichment_enabled,
        enrichment_criticality_default=settings.enrichment_criticality_default,
    )

    # Initialize notifier
    notifier = create_notifier(
        discord_webhook_url=str(settings.discord_webhook_url) if settings.discord_webhook_url else None,
        teams_webhook_url=str(settings.teams_webhook_url) if settings.teams_webhook_url else None,
        slack_webhook_url=str(settings.slack_webhook_url) if settings.slack_webhook_url else None,
        pagerduty_routing_key=settings.pagerduty_routing_key,
        pagerduty_api_url=settings.pagerduty_api_url,
        httpx_timeout=settings.httpx_timeout_seconds,
    )

    # Initialize validation engine
    validation_engine = ValidationEngine(pyats_enabled=settings.pyats_enabled)

    # Initialize device layer
    gateway = MCPGateway(engine=policy_engine, notifier=notifier)
    command_builder = create_default_command_builder()
    connection_manager = ConnectionManager()
    executor = DeviceExecutor(
        command_builder=command_builder,
        connection_manager=connection_manager,
        session_factory=session_factory,
        validation_engine=validation_engine,
        validation_trigger_rollback=settings.validation_trigger_rollback,
    )

    # Create MCP server
    mcp = FastMCP(
        name="Structured Network Autonomy",
        instructions=(
            "SNA governance server for network operations. "
            "All tool calls are evaluated against policy before execution. "
            "Actions may be PERMIT, ESCALATE, or BLOCK based on risk tier and confidence."
        ),
    )

    # Store references for graceful shutdown
    mcp._sna_engine = engine  # type: ignore[attr-defined]
    mcp._sna_connections = connection_manager  # type: ignore[attr-defined]

    # Register all tools
    all_tools = {**READ_TOOLS, **WRITE_TOOLS}

    for tool_name, tool_meta in all_tools.items():
        _register_tool(mcp, tool_name, tool_meta, gateway, executor)

    await logger.ainfo(
        "mcp_server_ready",
        tools_registered=len(all_tools),
        policy_version=policy_engine.policy.version,
    )

    return mcp


def _register_tool(
    mcp: FastMCP,
    tool_name: str,
    tool_meta: dict[str, Any],
    gateway: MCPGateway,
    executor: DeviceExecutor,
) -> None:
    """Register a single SNA tool on the MCP server."""

    @mcp.tool(name=tool_name, description=tool_meta["description"])
    async def tool_handler(**kwargs: Any) -> str:
        """Handle an MCP tool call through the SNA governance pipeline."""
        # Extract device target from params
        device = kwargs.pop("device", "unknown")
        actual_tool_name = tool_handler.__name__  # Closure captures tool_name

        # Build the MCP tool call
        tool_call = MCPToolCall(
            tool_name=actual_tool_name,
            parameters=kwargs,
            device_targets=[device],
            confidence_score=kwargs.pop("confidence_score", 0.5),
            context=kwargs.pop("context", {}),
            caller_id=kwargs.pop("caller_id", "mcp-agent"),
        )

        # Evaluate through policy gateway
        intercept_result = await gateway.intercept(tool_call)

        if not intercept_result.permitted:
            verdict = intercept_result.evaluation.verdict.value
            reason = intercept_result.evaluation.reason
            return f"Action {verdict}: {reason}"

        # Execute on device
        try:
            exec_result = await executor.execute(
                tool_name=actual_tool_name,
                device_target=device,
                params={k: str(v) for k, v in kwargs.items()},
                evaluation_result=intercept_result.evaluation,
            )
            if exec_result.success:
                return exec_result.output or "Command executed successfully"
            return f"Execution failed: {exec_result.error or 'Unknown error'}"
        except (CommandValidationError, DeviceConnectionError) as exc:
            return f"Execution error: {exc}"

    # Fix closure variable capture
    tool_handler.__name__ = tool_name

"""CLI entrypoint — Typer-based command interface.

Commands:
    sna serve          — Start the FastAPI server
    sna mcp-serve      — Start the MCP server
    sna evaluate       — One-shot policy evaluation
    sna migrate        — Run database migrations
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer

app = typer.Typer(
    name="sna",
    help="Structured Network Autonomy — governance framework for AI agents in enterprise networks",
)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="API server host"),
    port: int = typer.Option(8000, help="API server port"),
    reload: bool = typer.Option(False, help="Enable auto-reload for development"),
) -> None:
    """Start the SNA FastAPI API server."""
    import uvicorn

    uvicorn.run(
        "sna.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


@app.command()
def mcp_serve() -> None:
    """Start the SNA MCP server for AI agent connections."""

    async def _run() -> None:
        from sna.mcp_server.server import create_mcp_server

        mcp = await create_mcp_server()
        await mcp.run_async()

    asyncio.run(_run())


@app.command()
def evaluate(
    tool_name: str = typer.Argument(help="Tool name to evaluate"),
    confidence: float = typer.Option(0.5, help="Confidence score (0.0-1.0)"),
    devices: str = typer.Option("", help="Comma-separated device targets"),
) -> None:
    """One-shot policy evaluation — evaluate a tool call and print the verdict."""

    async def _run() -> None:
        from sna.config import get_settings
        from sna.db.models import Base
        from sna.db.session import create_async_engine_from_url, create_session_factory
        from sna.policy.engine import PolicyEngine
        from sna.policy.models import EvaluationRequest

        settings = get_settings()
        engine = create_async_engine_from_url(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = create_session_factory(engine)
        policy_engine = await PolicyEngine.from_config(
            policy_file_path=settings.policy_file_path,
            session_factory=session_factory,
            default_eas=settings.default_eas,
        )

        device_list = [d.strip() for d in devices.split(",") if d.strip()]

        request = EvaluationRequest(
            tool_name=tool_name,
            parameters={},
            device_targets=device_list,
            confidence_score=confidence,
            context={},
        )
        result = await policy_engine.evaluate(request)

        typer.echo(f"Verdict:    {result.verdict.value}")
        typer.echo(f"Risk Tier:  {result.risk_tier.value}")
        typer.echo(f"Reason:     {result.reason}")
        typer.echo(f"Confidence: {result.confidence_score:.2f} / {result.confidence_threshold:.2f}")
        typer.echo(f"Devices:    {result.device_count}")

        await engine.dispose()

    asyncio.run(_run())


@app.command()
def migrate(
    revision: str = typer.Option("head", help="Target revision (default: head)"),
) -> None:
    """Run Alembic database migrations."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic.ini")

    # Validate path to prevent traversal
    script_location = alembic_cfg.get_main_option("script_location")
    if script_location:
        resolved = Path(script_location).resolve()
        if not str(resolved).startswith(str(Path.cwd().resolve())):
            typer.echo("Error: script_location path traversal detected", err=True)
            raise typer.Exit(code=1)

    command.upgrade(alembic_cfg, revision)
    typer.echo(f"Migrations applied to: {revision}")


if __name__ == "__main__":
    app()

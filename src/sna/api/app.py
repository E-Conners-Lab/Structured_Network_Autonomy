"""FastAPI application factory, lifespan management, and middleware configuration.

Creates the FastAPI app with:
- Async lifespan (engine init, DB tables, logging)
- CORS middleware
- Rate limiting (slowapi)
- Request body size limit middleware
- All route modules registered
- Global error handlers
"""

from __future__ import annotations

import pathlib
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import FileResponse, JSONResponse

from sna.api.error_handlers import register_error_handlers
from sna.api.routes import agents, audit, batch, eas, escalation, evaluate, executions, health, inventory, metrics, policy, reports
from sna.observability.correlation import CorrelationMiddleware
from sna.config import Settings
from sna.db.models import Base
from sna.db.session import create_async_engine_from_url, create_session_factory
from sna.devices.batch import BatchExecutor
from sna.devices.command_builder import create_default_command_builder
from sna.devices.driver import ConnectionManager
from sna.devices.executor import DeviceExecutor
from sna.devices.rollback import RollbackExecutor
from sna.integrations.netbox import NetBoxClient
from sna.log_config import configure_logging
from sna.policy.engine import PolicyEngine
from sna.validation.rules import ValidationEngine

logger = structlog.get_logger()


def _create_limiter() -> Limiter:
    """Create a slowapi rate limiter keyed by remote address."""
    return Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — startup and shutdown logic.

    Startup:
        1. Configure structured logging
        2. Create async DB engine and session factory
        3. Create database tables (if they don't exist)
        4. Initialize PolicyEngine from config
        5. Store everything on app.state

    Shutdown:
        6. Dispose the database engine
    """
    settings: Settings = app.state.settings

    # 1. Logging
    configure_logging(log_level=settings.log_level, log_format=settings.log_format)

    # 2. Database engine + session factory
    engine = create_async_engine_from_url(
        settings.database_url,
        pool_timeout=settings.db_pool_timeout,
        connect_timeout=settings.db_connect_timeout,
    )
    session_factory = create_session_factory(engine)

    # 3. Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 4. NetBox client (optional)
    netbox_client: NetBoxClient | None = None
    if settings.netbox_url and settings.netbox_token:
        netbox_client = NetBoxClient(
            base_url=settings.netbox_url,
            token=settings.netbox_token,
            timeout=settings.httpx_timeout_seconds,
            cache_ttl=settings.netbox_cache_ttl,
        )

    # 5. Policy engine
    policy_engine = await PolicyEngine.from_config(
        policy_file_path=settings.policy_file_path,
        session_factory=session_factory,
        default_eas=settings.default_eas,
        netbox_client=netbox_client,
        enrichment_enabled=settings.enrichment_enabled,
        enrichment_criticality_default=settings.enrichment_criticality_default,
    )

    # 6. Validation engine
    validation_engine = ValidationEngine(pyats_enabled=settings.pyats_enabled)

    # 7. Device execution infrastructure
    command_builder = create_default_command_builder()
    connection_manager = ConnectionManager()
    device_executor = DeviceExecutor(
        command_builder=command_builder,
        connection_manager=connection_manager,
        session_factory=session_factory,
        validation_engine=validation_engine,
        validation_trigger_rollback=settings.validation_trigger_rollback,
    )
    rollback_executor = RollbackExecutor(
        connection_manager=connection_manager,
        session_factory=session_factory,
    )
    batch_executor = BatchExecutor(
        executor=device_executor,
        validation_engine=validation_engine,
        rollback_executor=rollback_executor,
        max_parallel=5,
    )

    # 8. Store on app.state
    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.engine = policy_engine
    app.state.netbox_client = netbox_client
    app.state.validation_engine = validation_engine
    app.state.device_executor = device_executor
    app.state.batch_executor = batch_executor
    app.state.connection_manager = connection_manager

    await logger.ainfo(
        "startup_complete",
        policy_version=policy_engine.policy.version,
        eas=policy_engine.get_eas(),
        database_url=settings.database_url.split("://")[0] + "://***",
    )

    yield

    # Shutdown
    if netbox_client:
        await netbox_client.close()
    await connection_manager.close_all()
    await engine.dispose()
    await logger.ainfo("shutdown_complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory — create and configure the FastAPI app.

    Args:
        settings: Optional Settings instance. If None, loads from environment.

    Returns:
        A fully configured FastAPI application.
    """
    if settings is None:
        from sna.config import get_settings
        settings = get_settings()

    app = FastAPI(
        title="Structured Network Autonomy",
        description="Governance framework for AI agents in enterprise networks",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Attach settings before lifespan runs
    app.state.settings = settings

    # --- CORS ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # --- Correlation IDs ---
    app.add_middleware(CorrelationMiddleware)

    # --- Rate limiting ---
    limiter = _create_limiter()
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
        )

    # --- Request body size limit ---
    max_body = settings.max_request_body_bytes

    @app.middleware("http")
    async def limit_request_body(request: Request, call_next: object) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > max_body:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        response = await call_next(request)  # type: ignore[operator]
        return response

    # --- Routes ---
    app.include_router(evaluate.router)
    app.include_router(escalation.router)
    app.include_router(agents.router)
    app.include_router(audit.router)
    app.include_router(executions.router)
    app.include_router(eas.router)
    app.include_router(reports.router)
    app.include_router(inventory.router)
    app.include_router(metrics.router)
    app.include_router(policy.router)
    app.include_router(batch.router)
    app.include_router(health.router)

    # --- Error handlers ---
    register_error_handlers(app)

    # --- CSP headers ---
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: object) -> Response:
        response = await call_next(request)  # type: ignore[operator]
        if request.url.path.startswith("/dashboard") or request.url.path == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            )
        return response

    # --- Dashboard static files ---
    if settings.dashboard_enabled:
        dashboard_path = pathlib.Path(settings.dashboard_static_path).resolve()
        if dashboard_path.is_dir():
            @app.get("/dashboard/{rest_of_path:path}")
            async def serve_dashboard(rest_of_path: str) -> Response:
                """Serve dashboard static files with path traversal protection."""
                # Serve index.html for SPA routes (no extension)
                if not rest_of_path or "." not in rest_of_path.split("/")[-1]:
                    index = dashboard_path / "index.html"
                    if index.is_file():
                        return FileResponse(str(index))
                    return JSONResponse({"detail": "Dashboard not built"}, status_code=404)

                # Resolve and validate path
                file_path = (dashboard_path / rest_of_path).resolve()
                if not str(file_path).startswith(str(dashboard_path)):
                    return JSONResponse({"detail": "Invalid path"}, status_code=400)
                if file_path.is_file():
                    return FileResponse(str(file_path))
                return JSONResponse({"detail": "Not found"}, status_code=404)

            app.mount("/dashboard/assets", StaticFiles(directory=str(dashboard_path / "assets")), name="dashboard-assets") if (dashboard_path / "assets").is_dir() else None

    return app

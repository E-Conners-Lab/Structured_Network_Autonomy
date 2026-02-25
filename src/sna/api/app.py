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

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse

from sna.api.error_handlers import register_error_handlers
from sna.api.routes import audit, escalation, evaluate, health, policy
from sna.config import Settings
from sna.db.models import Base
from sna.db.session import create_async_engine_from_url, create_session_factory
from sna.log_config import configure_logging
from sna.policy.engine import PolicyEngine

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

    # 4. Policy engine
    policy_engine = await PolicyEngine.from_config(
        policy_file_path=settings.policy_file_path,
        session_factory=session_factory,
        default_eas=settings.default_eas,
    )

    # 5. Store on app.state
    app.state.db_engine = engine
    app.state.session_factory = session_factory
    app.state.engine = policy_engine

    await logger.ainfo(
        "startup_complete",
        policy_version=policy_engine.policy.version,
        eas=policy_engine.get_eas(),
        database_url=settings.database_url.split("://")[0] + "://***",
    )

    yield

    # 6. Shutdown
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
    app.include_router(audit.router)
    app.include_router(policy.router)
    app.include_router(health.router)

    # --- Error handlers ---
    register_error_handlers(app)

    return app

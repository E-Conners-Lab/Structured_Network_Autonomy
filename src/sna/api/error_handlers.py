"""Global exception handlers — logs full details internally, returns sanitized errors to callers.

Never exposes stack traces, internal paths, or implementation details in API responses.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

logger = structlog.get_logger()


def register_error_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI app."""

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        await logger.awarning(
            "validation_error",
            path=request.url.path,
            errors=exc.error_count(),
        )
        return JSONResponse(
            status_code=422,
            content={"detail": "Validation error", "errors": exc.errors()},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        await logger.aerror(
            "unhandled_exception",
            path=request.url.path,
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

"""Correlation ID middleware for distributed tracing.

Generates a unique correlation ID for every request. The ID is always
server-generated (never accepted from external headers to prevent spoofing).
External X-Correlation-ID is logged as client_correlation_id separately.
"""

from __future__ import annotations

from uuid import uuid4

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

CORRELATION_HEADER = "X-Correlation-ID"
CLIENT_CORRELATION_HEADER = "X-Client-Correlation-ID"


def generate_correlation_id() -> str:
    """Generate a unique correlation ID."""
    return str(uuid4())


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware that generates and propagates correlation IDs.

    The correlation ID is:
    1. Always server-generated (never from client headers)
    2. Stored in request.state.correlation_id
    3. Added to response headers
    4. Bound to structlog context for all log entries
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Always generate server-side correlation ID
        correlation_id = generate_correlation_id()
        request.state.correlation_id = correlation_id

        # Log client's correlation ID separately (if provided)
        client_correlation = request.headers.get(CORRELATION_HEADER, "")

        # Bind to structlog context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
        )
        if client_correlation:
            structlog.contextvars.bind_contextvars(
                client_correlation_id=client_correlation,
            )

        response = await call_next(request)

        # Add correlation ID to response
        response.headers[CORRELATION_HEADER] = correlation_id

        return response


def get_correlation_id(request: Request) -> str:
    """Get the correlation ID from the current request.

    Returns empty string if not set (shouldn't happen with middleware).
    """
    return getattr(request.state, "correlation_id", "")

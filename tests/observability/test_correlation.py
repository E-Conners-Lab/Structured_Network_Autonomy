"""Tests for correlation ID validation."""

from __future__ import annotations

import structlog
from starlette.testclient import TestClient
from fastapi import FastAPI, Request

from sna.observability.correlation import CorrelationMiddleware, _CORRELATION_PATTERN


class TestCorrelationPattern:
    """Correlation ID pattern validation tests."""

    def test_valid_uuid_matches(self) -> None:
        assert _CORRELATION_PATTERN.match("550e8400-e29b-41d4-a716-446655440000")

    def test_valid_alphanumeric_matches(self) -> None:
        assert _CORRELATION_PATTERN.match("abc123_test-id")

    def test_long_correlation_rejected(self) -> None:
        """Values longer than 64 chars should not match."""
        long_value = "a" * 65
        assert _CORRELATION_PATTERN.match(long_value) is None

    def test_special_chars_rejected(self) -> None:
        """Script injection attempts should not match."""
        assert _CORRELATION_PATTERN.match("<script>alert(1)</script>") is None

    def test_empty_string_rejected(self) -> None:
        assert _CORRELATION_PATTERN.match("") is None

    def test_spaces_rejected(self) -> None:
        assert _CORRELATION_PATTERN.match("has spaces") is None


class TestCorrelationMiddleware:
    """Test that invalid correlation IDs are not bound to context."""

    def test_valid_client_correlation_bound(self) -> None:
        """Valid client correlation ID should be bound to structlog context."""
        app = FastAPI()
        app.add_middleware(CorrelationMiddleware)

        bound_vars = {}

        @app.get("/test")
        async def test_endpoint(request: Request) -> dict:
            ctx = structlog.contextvars.get_contextvars()
            bound_vars.update(ctx)
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test", headers={"X-Correlation-ID": "valid-uuid-1234"})
        assert bound_vars.get("client_correlation_id") == "valid-uuid-1234"

    def test_long_correlation_not_bound(self) -> None:
        """Oversized correlation IDs should be silently ignored."""
        app = FastAPI()
        app.add_middleware(CorrelationMiddleware)

        bound_vars = {}

        @app.get("/test")
        async def test_endpoint(request: Request) -> dict:
            ctx = structlog.contextvars.get_contextvars()
            bound_vars.update(ctx)
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        long_id = "a" * 65
        client.get("/test", headers={"X-Correlation-ID": long_id})
        assert "client_correlation_id" not in bound_vars

    def test_special_chars_not_bound(self) -> None:
        """XSS-like correlation IDs should be silently ignored."""
        app = FastAPI()
        app.add_middleware(CorrelationMiddleware)

        bound_vars = {}

        @app.get("/test")
        async def test_endpoint(request: Request) -> dict:
            ctx = structlog.contextvars.get_contextvars()
            bound_vars.update(ctx)
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        client.get("/test", headers={"X-Correlation-ID": "<script>alert(1)</script>"})
        assert "client_correlation_id" not in bound_vars

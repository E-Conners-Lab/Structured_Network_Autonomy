"""Tests for OpenTelemetry tracing integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sna.observability.tracing import (
    _NoOpSpan,
    _NoOpTracer,
    _sanitize_span_value,
    add_span_attributes,
    span,
)


class TestSanitizeSpanValue:
    """Span attribute sanitization tests."""

    def test_sanitize_password_key(self) -> None:
        """Key containing 'password' should be redacted."""
        assert _sanitize_span_value("device_password", "secret123") == "***"

    def test_sanitize_secret_key(self) -> None:
        """Key containing 'secret' should be redacted."""
        assert _sanitize_span_value("api_secret", "abc") == "***"

    def test_sanitize_token_key(self) -> None:
        """Key containing 'token' should be redacted."""
        assert _sanitize_span_value("auth_token", "tok_123") == "***"

    def test_sanitize_value_with_password(self) -> None:
        """Value containing 'password' keyword should be redacted."""
        assert _sanitize_span_value("error", "password=secret123") == "***"

    def test_normal_value_passes_through(self) -> None:
        """Normal values without secret keywords should pass through."""
        assert _sanitize_span_value("tool_name", "show_interfaces") == "show_interfaces"

    def test_non_string_value_passes_through(self) -> None:
        """Non-string values should pass through unchanged."""
        assert _sanitize_span_value("count", 42) == 42

    def test_long_value_sanitized(self) -> None:
        """Values >100 chars are run through sanitize_output."""
        long_val = "snmp-server community PUBLIC_STRING RO\n" + "x" * 100
        result = _sanitize_span_value("config", long_val)
        assert "PUBLIC_STRING" not in result


class TestNoOpFallback:
    """NoOp tracer/span tests when OTel is not installed."""

    def test_noop_tracer_creates_span(self) -> None:
        """NoOp tracer should return a NoOp span."""
        tracer = _NoOpTracer()
        s = tracer.start_as_current_span("test")
        assert isinstance(s, _NoOpSpan)

    def test_noop_span_context_manager(self) -> None:
        """NoOp span should work as context manager."""
        s = _NoOpSpan()
        with s as entered:
            assert entered is s

    def test_noop_span_set_attribute(self) -> None:
        """NoOp span set_attribute should be a no-op."""
        s = _NoOpSpan()
        s.set_attribute("key", "value")  # Should not raise


class TestSpanContextManager:
    """Tests for the span() context manager."""

    def test_noop_when_disabled(self) -> None:
        """When OTel is not initialized, span() yields None."""
        with patch("sna.observability.tracing._initialized", False):
            with span("test.span") as s:
                assert s is None

    def test_noop_when_not_installed(self) -> None:
        """When OTel packages are missing, no errors and no spans."""
        with patch("sna.observability.tracing._otel_available", False):
            with patch("sna.observability.tracing._initialized", False):
                with span("test.span") as s:
                    assert s is None

    def test_add_span_attributes_noop_when_disabled(self) -> None:
        """add_span_attributes is a no-op when not initialized."""
        with patch("sna.observability.tracing._initialized", False):
            # Should not raise
            add_span_attributes({"key": "value"})


class TestInitTracer:
    """Tests for init_tracer."""

    def test_init_tracer_without_otel(self) -> None:
        """init_tracer should log warning when OTel not available."""
        with patch("sna.observability.tracing._otel_available", False):
            from sna.observability.tracing import init_tracer

            init_tracer("test-service", None)  # Should not raise

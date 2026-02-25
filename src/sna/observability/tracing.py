"""OpenTelemetry distributed tracing — optional integration.

All functions are safe no-ops when OTel is not installed or not enabled.
Span attributes are sanitized to prevent credential leakage.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Any, Generator

import structlog

logger = structlog.get_logger()

# Try to import OTel; set flag for availability
_otel_available = False
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import StatusCode

    _otel_available = True
except ImportError:
    pass

_tracer: Any = None
_initialized = False

# Patterns that indicate a value contains secrets
_SECRET_KEYWORDS = re.compile(
    r"(?i)(password|secret|key|community|token|credential|auth)"
)


def init_tracer(service_name: str, endpoint: str | None) -> None:
    """Configure the OpenTelemetry TracerProvider with OTLP exporter.

    Args:
        service_name: The service name for traces.
        endpoint: OTLP HTTP endpoint (e.g., "http://localhost:4318").
            If None, traces are not exported.
    """
    global _tracer, _initialized

    if not _otel_available:
        logger.warning("otel_not_available", reason="opentelemetry packages not installed")
        return

    from opentelemetry.sdk.resources import Resource

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if endpoint:
        from sna.utils.url_safety import validate_webhook_url

        # Validate endpoint for SSRF — allow http://localhost for local dev
        if not endpoint.startswith("http://localhost") and not endpoint.startswith("http://127.0.0.1"):
            try:
                validate_webhook_url(endpoint)
            except ValueError:
                logger.warning("otel_endpoint_ssrf_blocked", endpoint=endpoint)
                return

        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except ImportError:
            logger.warning("otel_exporter_not_available")

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name)
    _initialized = True
    logger.info("otel_tracer_initialized", service_name=service_name, endpoint=endpoint)


def get_tracer() -> Any:
    """Return the configured tracer, or a no-op tracer."""
    global _tracer
    if _tracer is not None:
        return _tracer

    if _otel_available:
        return trace.get_tracer("sna-noop")

    return _NoOpTracer()


@contextmanager
def span(name: str, attributes: dict[str, Any] | None = None) -> Generator[Any, None, None]:
    """Create a span with sanitized attributes.

    Safe no-op when OTel is not available or not initialized.

    Args:
        name: The span name.
        attributes: Optional span attributes (will be sanitized).
    """
    if not _otel_available or not _initialized:
        yield None
        return

    tracer = get_tracer()
    sanitized = {}
    if attributes:
        sanitized = {k: _sanitize_span_value(k, v) for k, v in attributes.items()}

    with tracer.start_as_current_span(name, attributes=sanitized) as current_span:
        try:
            yield current_span
        except Exception as exc:
            if current_span is not None and hasattr(current_span, "set_status"):
                current_span.set_status(StatusCode.ERROR, str(exc))
            raise


def add_span_attributes(attributes: dict[str, Any]) -> None:
    """Add sanitized attributes to the current active span.

    No-op if OTel is not available or no active span.
    """
    if not _otel_available or not _initialized:
        return

    current_span = trace.get_current_span()
    if current_span is None:
        return

    for key, value in attributes.items():
        sanitized = _sanitize_span_value(key, value)
        current_span.set_attribute(key, sanitized)


def _sanitize_span_value(key: str, value: Any) -> Any:
    """Sanitize a span attribute value to prevent credential leakage.

    Rules:
    1. If key name contains secret-related keywords → "***"
    2. If string value contains secret-related keywords → "***"
    3. If string is >100 chars → run through sanitize_output (likely config)
    """
    if not isinstance(value, str):
        return value

    # Check key name for secret keywords
    if _SECRET_KEYWORDS.search(key):
        return "***"

    # Check value for secret keywords
    if _SECRET_KEYWORDS.search(value):
        return "***"

    # Long strings might be config output — sanitize
    if len(value) > 100:
        from sna.devices.sanitizer import sanitize_output

        return sanitize_output(value)

    return value


class _NoOpTracer:
    """Fallback tracer when OTel is not installed."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> "_NoOpSpan":
        return _NoOpSpan()


class _NoOpSpan:
    """Fallback span when OTel is not installed."""

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any) -> None:
        pass

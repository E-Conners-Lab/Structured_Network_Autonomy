"""Prometheus metrics for SNA observability.

Exposes counters, histograms, and gauges for evaluation, execution,
escalation, and EAS tracking. Served at GET /metrics (auth required).
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest

# --- Evaluation metrics ---

EVALUATION_TOTAL = Counter(
    "sna_evaluation_total",
    "Total policy evaluations",
    ["verdict", "tier"],
)

EVALUATION_LATENCY = Histogram(
    "sna_evaluation_latency_seconds",
    "Policy evaluation latency in seconds",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

# --- EAS metrics ---

EAS_CURRENT = Gauge(
    "sna_eas_current",
    "Current Earned Autonomy Score",
)

# --- Escalation metrics ---

ESCALATION_PENDING = Gauge(
    "sna_escalation_pending_count",
    "Number of pending escalations",
)

# --- Execution metrics ---

EXECUTION_TOTAL = Counter(
    "sna_execution_total",
    "Total device executions",
    ["success"],
)

EXECUTION_LATENCY = Histogram(
    "sna_execution_latency_seconds",
    "Device execution latency in seconds",
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
)

# --- Notification metrics ---

NOTIFICATION_TOTAL = Counter(
    "sna_notification_total",
    "Total notifications sent",
    ["channel"],
)

# --- Validation metrics ---

VALIDATION_TOTAL = Counter(
    "sna_validation_total",
    "Total post-change validations",
    ["status"],
)


def record_evaluation(verdict: str, tier: str) -> None:
    """Record a policy evaluation verdict."""
    EVALUATION_TOTAL.labels(verdict=verdict, tier=tier).inc()


def record_execution(success: bool) -> None:
    """Record a device execution."""
    EXECUTION_TOTAL.labels(success=str(success).lower()).inc()


def record_notification(channel: str) -> None:
    """Record a notification sent."""
    NOTIFICATION_TOTAL.labels(channel=channel).inc()


def record_validation(status: str) -> None:
    """Record a validation result."""
    VALIDATION_TOTAL.labels(status=status).inc()


def update_eas(score: float) -> None:
    """Update the current EAS gauge."""
    EAS_CURRENT.set(score)


def update_escalation_pending(count: int) -> None:
    """Update the pending escalation count gauge."""
    ESCALATION_PENDING.set(count)


def get_metrics_text() -> bytes:
    """Generate Prometheus metrics output."""
    return generate_latest()

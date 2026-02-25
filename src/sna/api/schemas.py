"""Pydantic request/response schemas for all API endpoints.

These are wire-format schemas — separate from domain models (policy/models.py)
and ORM models (db/models.py). They define what the API accepts and returns.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from sna.policy.models import RiskTier, Verdict

T = TypeVar("T")


# --- Pagination ---


class PaginationParams(BaseModel):
    """Query parameters for paginated endpoints."""

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=100)


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def create(cls, items: list[T], total: int, page: int, page_size: int) -> PaginatedResponse[T]:
        """Build a paginated response from items and counts."""
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=max(1, math.ceil(total / page_size)),
        )


# --- Evaluate endpoint ---


class EvaluateRequest(BaseModel):
    """POST /evaluate request body."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=255)
    parameters: dict[str, object] = Field(default_factory=dict, max_length=50)
    device_targets: list[str] = Field(default_factory=list, max_length=20)
    confidence_score: float = Field(ge=0.0, le=1.0)
    context: dict[str, object] = Field(default_factory=dict, max_length=50)


class EvaluateResponse(BaseModel):
    """POST /evaluate response body."""

    verdict: Verdict
    risk_tier: RiskTier
    tool_name: str
    reason: str
    confidence_score: float
    confidence_threshold: float
    device_count: int
    requires_audit: bool
    requires_senior_approval: bool
    escalation_id: UUID | None = None


# --- Escalation endpoints ---


class EscalationDecisionRequest(BaseModel):
    """POST /escalation/{id}/decision request body."""

    model_config = ConfigDict(extra="forbid")

    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    decided_by: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class EscalationResponse(BaseModel):
    """Escalation record in API responses."""

    external_id: UUID
    tool_name: str
    parameters: dict | None = None
    risk_tier: str
    confidence_score: float
    reason: str
    device_targets: list | None = None
    device_count: int
    status: str
    requires_senior_approval: bool
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    created_at: datetime


class EscalationDecisionResponse(BaseModel):
    """POST /escalation/{id}/decision response body."""

    external_id: UUID
    status: str
    decided_by: str
    decided_at: datetime


# --- Audit endpoint ---


class AuditEntryResponse(BaseModel):
    """Single audit log entry in API responses."""

    external_id: str
    timestamp: datetime
    tool_name: str
    verdict: str
    risk_tier: str
    confidence_score: float
    confidence_threshold: float
    device_count: int
    reason: str
    requires_audit: bool
    requires_senior_approval: bool
    eas_at_time: float


# --- Execution audit endpoint ---


class ExecutionLogResponse(BaseModel):
    """Single execution log entry in API responses."""

    external_id: str
    timestamp: datetime
    tool_name: str
    device_target: str
    command_sent: str
    output: str
    success: bool
    duration_seconds: float
    error: str | None = None


# --- Policy endpoint ---


class PolicyReloadResponse(BaseModel):
    """POST /policy/reload response body."""

    status: str
    version: str
    diff: str | None = None


# --- Health endpoint ---


class HealthMinimalResponse(BaseModel):
    """GET /health unauthenticated response."""

    status: str


class HealthFullResponse(BaseModel):
    """GET /health authenticated response."""

    status: str
    eas: float
    policy_loaded: bool
    policy_version: str
    db_connected: bool
    last_audit_write: datetime | None = None

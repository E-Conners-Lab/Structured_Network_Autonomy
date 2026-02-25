"""ORM models — Agent, AuditLog, EscalationRecord, EASHistory, ExecutionLog.

All API-facing identifiers use UUID4 to prevent enumeration.
AuditLog is append-only — no update or delete operations.
All timestamps are UTC.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""


class AgentStatus(str, enum.Enum):
    """Status of a registered AI agent."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class EscalationStatus(str, enum.Enum):
    """Status of an escalation record."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class Agent(Base):
    """Registered AI agent with per-agent API key and EAS.

    API key is stored as bcrypt hash — never plaintext.
    """

    __tablename__ = "agent"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    eas: Mapped[float] = mapped_column(Float, nullable=False, default=0.1)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AgentStatus.ACTIVE.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_agent_name", "name"),
        Index("ix_agent_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<Agent(id={self.id}, name={self.name}, status={self.status})>"


class AuditLog(Base):
    """Immutable record of every policy engine decision.

    Append-only — no update or delete operations are ever performed on this table.
    Every PERMIT, ESCALATE, and BLOCK decision is recorded with full context.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    # Action details
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parameters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    device_targets: Mapped[list | None] = mapped_column(JSON, nullable=True)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Decision details
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Flags
    requires_audit: Mapped[bool] = mapped_column(nullable=False, default=False)
    requires_senior_approval: Mapped[bool] = mapped_column(nullable=False, default=False)

    # EAS at time of decision
    eas_at_time: Mapped[float] = mapped_column(Float, nullable=False)

    # Agent identity (nullable — existing rows have no agent, global-key requests have no agent)
    agent_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("agent.id"), nullable=True
    )

    # Relationship to escalation (optional — only exists for ESCALATE verdicts)
    escalation: Mapped[EscalationRecord | None] = relationship(
        "EscalationRecord", back_populates="audit_log", uselist=False
    )

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_verdict", "verdict"),
        Index("ix_audit_log_tool_name", "tool_name"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id={self.id}, tool={self.tool_name}, "
            f"verdict={self.verdict}, tier={self.risk_tier})>"
        )


class EscalationRecord(Base):
    """Tracks actions that require human approval.

    Created when the Policy Engine returns an ESCALATE verdict.
    Updated when an operator approves or rejects the action.
    """

    __tablename__ = "escalation_record"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    # Action context
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    parameters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_tier: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    device_targets: Mapped[list | None] = mapped_column(JSON, nullable=True)
    device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Decision
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=EscalationStatus.PENDING.value
    )
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Flags
    requires_senior_approval: Mapped[bool] = mapped_column(nullable=False, default=False)

    # Foreign key to audit log
    audit_log_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("audit_log.id"), nullable=False
    )
    audit_log: Mapped[AuditLog] = relationship(
        "AuditLog", back_populates="escalation"
    )

    __table_args__ = (
        Index("ix_escalation_status", "status"),
        Index("ix_escalation_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<EscalationRecord(id={self.id}, tool={self.tool_name}, "
            f"status={self.status})>"
        )


class EASHistory(Base):
    """Historical record of Earned Autonomy Score changes.

    Tracks every EAS modification with the previous score, new score,
    and the reason for the change.
    """

    __tablename__ = "eas_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    eas_score: Mapped[float] = mapped_column(Float, nullable=False)
    previous_score: Mapped[float] = mapped_column(Float, nullable=False)
    change_reason: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)

    # Agent identity (nullable — global EAS changes have no agent)
    agent_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("agent.id"), nullable=True
    )

    __table_args__ = (
        Index("ix_eas_history_timestamp", "timestamp"),
        Index("ix_eas_history_agent_id", "agent_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<EASHistory(id={self.id}, score={self.eas_score}, "
            f"prev={self.previous_score})>"
        )


class AgentPolicyOverride(Base):
    """Agent-specific policy rule override.

    Overrides can only be MORE restrictive than global policy.
    An override that would relax a BLOCK is not applied.
    """

    __tablename__ = "agent_policy_override"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    agent_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("agent.id"), nullable=False
    )
    rule_type: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # "site", "role", "tag", "tool"
    rule_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_agent_policy_override_agent_id", "agent_id"),
        Index("ix_agent_policy_override_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<AgentPolicyOverride(id={self.id}, agent_id={self.agent_id}, "
            f"rule_type={self.rule_type}, active={self.is_active})>"
        )


class PolicyVersion(Base):
    """Immutable version history of every policy reload.

    Each entry represents a snapshot of the policy at a point in time.
    Rollback creates a new version entry (rollback is versioned).
    """

    __tablename__ = "policy_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    version_string: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    diff_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")

    __table_args__ = (
        Index("ix_policy_version_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<PolicyVersion(id={self.id}, version={self.version_string}, hash={self.policy_hash[:12]})>"


class ExecutionLog(Base):
    """Record of actual device command execution after PERMIT verdict.

    Captures the command sent, sanitized output, duration, success/failure,
    and rollback data for write operations.
    """

    __tablename__ = "execution_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    # Execution details
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    device_target: Mapped[str] = mapped_column(String(255), nullable=False)
    command_sent: Mapped[str] = mapped_column(Text, nullable=False)
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Rollback data (pre-change config for write tools)
    rollback_data: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Error details (if execution failed)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional FK to audit_log (nullable to prevent constraint issues)
    audit_log_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("audit_log.id"), nullable=True
    )

    __table_args__ = (
        Index("ix_execution_log_timestamp", "timestamp"),
        Index("ix_execution_log_tool_name", "tool_name"),
        Index("ix_execution_log_device_target", "device_target"),
    )

    def __repr__(self) -> str:
        return (
            f"<ExecutionLog(id={self.id}, tool={self.tool_name}, "
            f"device={self.device_target}, success={self.success})>"
        )

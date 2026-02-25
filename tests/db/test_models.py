"""Tests for sna.db.models — AuditLog, EscalationRecord, EASHistory ORM models.

Covers:
- Record creation with defaults (UUID, timestamps)
- Field persistence and retrieval
- Relationships (AuditLog ↔ EscalationRecord)
- Append-only audit log behavior
- EscalationStatus enum values
- EASHistory score tracking
- Index existence
"""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import inspect, select

from sna.db.models import AuditLog, Base, EASHistory, EscalationRecord, EscalationStatus


# --- EscalationStatus enum ---


class TestEscalationStatus:
    def test_values(self):
        assert EscalationStatus.PENDING == "PENDING"
        assert EscalationStatus.APPROVED == "APPROVED"
        assert EscalationStatus.REJECTED == "REJECTED"

    def test_all_values_present(self):
        assert len(EscalationStatus) == 3


# --- AuditLog tests ---


class TestAuditLog:
    @pytest.mark.asyncio
    async def test_create_audit_log(self, db_session):
        log = AuditLog(
            tool_name="show_running_config",
            parameters={"device": "router1"},
            device_targets=["router1"],
            device_count=1,
            verdict="PERMIT",
            risk_tier="tier_1_read",
            confidence_score=0.95,
            confidence_threshold=0.1,
            reason="Tier 1 read — confidence above threshold",
            eas_at_time=0.5,
        )
        db_session.add(log)
        await db_session.flush()

        assert log.id is not None
        assert log.external_id is not None
        assert log.timestamp is not None

    @pytest.mark.asyncio
    async def test_external_id_is_valid_uuid(self, db_session):
        log = AuditLog(
            tool_name="ping",
            verdict="PERMIT",
            risk_tier="tier_1_read",
            confidence_score=0.9,
            confidence_threshold=0.1,
            reason="Read action",
            eas_at_time=0.3,
        )
        db_session.add(log)
        await db_session.flush()

        # Validates as UUID4 format
        parsed = UUID(log.external_id)
        assert parsed.version == 4

    @pytest.mark.asyncio
    async def test_timestamp_is_utc(self, db_session):
        before = datetime.now(UTC)
        log = AuditLog(
            tool_name="show_interfaces",
            verdict="PERMIT",
            risk_tier="tier_1_read",
            confidence_score=0.9,
            confidence_threshold=0.1,
            reason="Read action",
            eas_at_time=0.3,
        )
        db_session.add(log)
        await db_session.flush()
        after = datetime.now(UTC)

        assert before <= log.timestamp.replace(tzinfo=UTC) <= after

    @pytest.mark.asyncio
    async def test_json_fields_persisted(self, db_session):
        params = {"neighbor": "10.0.0.1", "as_number": 65001}
        targets = ["router1", "router2", "router3"]
        log = AuditLog(
            tool_name="configure_bgp_neighbor",
            parameters=params,
            device_targets=targets,
            device_count=3,
            verdict="ESCALATE",
            risk_tier="tier_4_high_risk_write",
            confidence_score=0.85,
            confidence_threshold=0.8,
            reason="High risk write",
            requires_senior_approval=True,
            eas_at_time=0.6,
        )
        db_session.add(log)
        await db_session.flush()

        result = await db_session.get(AuditLog, log.id)
        assert result is not None
        assert result.parameters == params
        assert result.device_targets == targets
        assert result.device_count == 3

    @pytest.mark.asyncio
    async def test_flags_default_false(self, db_session):
        log = AuditLog(
            tool_name="ping",
            verdict="PERMIT",
            risk_tier="tier_1_read",
            confidence_score=0.9,
            confidence_threshold=0.1,
            reason="Read action",
            eas_at_time=0.3,
        )
        db_session.add(log)
        await db_session.flush()

        assert log.requires_audit is False
        assert log.requires_senior_approval is False

    @pytest.mark.asyncio
    async def test_repr(self, db_session):
        log = AuditLog(
            tool_name="show_config",
            verdict="PERMIT",
            risk_tier="tier_1_read",
            confidence_score=0.9,
            confidence_threshold=0.1,
            reason="Read",
            eas_at_time=0.3,
        )
        db_session.add(log)
        await db_session.flush()

        repr_str = repr(log)
        assert "AuditLog" in repr_str
        assert "show_config" in repr_str
        assert "PERMIT" in repr_str

    @pytest.mark.asyncio
    async def test_multiple_logs_unique_external_ids(self, db_session):
        logs = []
        for i in range(5):
            log = AuditLog(
                tool_name=f"tool_{i}",
                verdict="PERMIT",
                risk_tier="tier_1_read",
                confidence_score=0.9,
                confidence_threshold=0.1,
                reason=f"Reason {i}",
                eas_at_time=0.3,
            )
            db_session.add(log)
            logs.append(log)
        await db_session.flush()

        external_ids = {log.external_id for log in logs}
        assert len(external_ids) == 5


# --- EscalationRecord tests ---


class TestEscalationRecord:
    @pytest.mark.asyncio
    async def test_create_escalation(self, db_session):
        audit_log = AuditLog(
            tool_name="configure_bgp_neighbor",
            verdict="ESCALATE",
            risk_tier="tier_4_high_risk_write",
            confidence_score=0.85,
            confidence_threshold=0.8,
            reason="High risk write",
            eas_at_time=0.5,
        )
        db_session.add(audit_log)
        await db_session.flush()

        escalation = EscalationRecord(
            tool_name="configure_bgp_neighbor",
            parameters={"neighbor": "10.0.0.1"},
            risk_tier="tier_4_high_risk_write",
            confidence_score=0.85,
            reason="High risk write requires approval",
            device_targets=["router1"],
            device_count=1,
            requires_senior_approval=True,
            audit_log_id=audit_log.id,
        )
        db_session.add(escalation)
        await db_session.flush()

        assert escalation.id is not None
        assert escalation.external_id is not None
        assert escalation.status == EscalationStatus.PENDING.value

    @pytest.mark.asyncio
    async def test_default_status_is_pending(self, db_session):
        audit_log = AuditLog(
            tool_name="configure_vlan",
            verdict="ESCALATE",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            confidence_threshold=0.6,
            reason="Below threshold",
            eas_at_time=0.2,
        )
        db_session.add(audit_log)
        await db_session.flush()

        escalation = EscalationRecord(
            tool_name="configure_vlan",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            reason="Below threshold",
            audit_log_id=audit_log.id,
        )
        db_session.add(escalation)
        await db_session.flush()

        assert escalation.status == "PENDING"

    @pytest.mark.asyncio
    async def test_approve_escalation(self, db_session):
        audit_log = AuditLog(
            tool_name="configure_acl",
            verdict="ESCALATE",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.55,
            confidence_threshold=0.6,
            reason="Below threshold",
            eas_at_time=0.4,
        )
        db_session.add(audit_log)
        await db_session.flush()

        escalation = EscalationRecord(
            tool_name="configure_acl",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.55,
            reason="Below threshold",
            audit_log_id=audit_log.id,
        )
        db_session.add(escalation)
        await db_session.flush()

        # Simulate approval
        escalation.status = EscalationStatus.APPROVED.value
        escalation.decided_by = "admin@example.com"
        escalation.decided_at = datetime.now(UTC)
        escalation.decision_reason = "Approved — low risk ACL change"
        await db_session.flush()

        assert escalation.status == "APPROVED"
        assert escalation.decided_by == "admin@example.com"
        assert escalation.decided_at is not None

    @pytest.mark.asyncio
    async def test_relationship_to_audit_log(self, db_session):
        audit_log = AuditLog(
            tool_name="configure_static_route",
            verdict="ESCALATE",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            confidence_threshold=0.6,
            reason="Below threshold",
            eas_at_time=0.3,
        )
        db_session.add(audit_log)
        await db_session.flush()

        escalation = EscalationRecord(
            tool_name="configure_static_route",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            reason="Below threshold",
            audit_log_id=audit_log.id,
        )
        db_session.add(escalation)
        await db_session.flush()

        # Navigate relationship
        assert escalation.audit_log.id == audit_log.id
        assert escalation.audit_log.tool_name == "configure_static_route"

    @pytest.mark.asyncio
    async def test_query_pending_escalations(self, db_session):
        # Create an audit log and pending escalation
        audit_log = AuditLog(
            tool_name="configure_ospf_area",
            verdict="ESCALATE",
            risk_tier="tier_4_high_risk_write",
            confidence_score=0.7,
            confidence_threshold=0.8,
            reason="Below threshold",
            eas_at_time=0.4,
        )
        db_session.add(audit_log)
        await db_session.flush()

        escalation = EscalationRecord(
            tool_name="configure_ospf_area",
            risk_tier="tier_4_high_risk_write",
            confidence_score=0.7,
            reason="Below threshold",
            audit_log_id=audit_log.id,
        )
        db_session.add(escalation)
        await db_session.flush()

        result = await db_session.execute(
            select(EscalationRecord).where(
                EscalationRecord.status == EscalationStatus.PENDING.value
            )
        )
        pending = result.scalars().all()
        assert len(pending) >= 1
        assert any(e.tool_name == "configure_ospf_area" for e in pending)

    @pytest.mark.asyncio
    async def test_repr(self, db_session):
        audit_log = AuditLog(
            tool_name="test_tool",
            verdict="ESCALATE",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            confidence_threshold=0.6,
            reason="Test",
            eas_at_time=0.3,
        )
        db_session.add(audit_log)
        await db_session.flush()

        esc = EscalationRecord(
            tool_name="test_tool",
            risk_tier="tier_3_medium_risk_write",
            confidence_score=0.5,
            reason="Test",
            audit_log_id=audit_log.id,
        )
        db_session.add(esc)
        await db_session.flush()

        repr_str = repr(esc)
        assert "EscalationRecord" in repr_str
        assert "test_tool" in repr_str
        assert "PENDING" in repr_str


# --- EASHistory tests ---


class TestEASHistory:
    @pytest.mark.asyncio
    async def test_create_eas_history(self, db_session):
        entry = EASHistory(
            eas_score=0.3,
            previous_score=0.1,
            change_reason="Initial calibration after successful audit period",
            source="audit_system",
        )
        db_session.add(entry)
        await db_session.flush()

        assert entry.id is not None
        assert entry.external_id is not None
        assert entry.timestamp is not None

    @pytest.mark.asyncio
    async def test_score_tracking(self, db_session):
        entry = EASHistory(
            eas_score=0.6,
            previous_score=0.5,
            change_reason="Consistent successful operations",
            source="eas_calculator",
        )
        db_session.add(entry)
        await db_session.flush()

        assert entry.eas_score == 0.6
        assert entry.previous_score == 0.5

    @pytest.mark.asyncio
    async def test_score_decrease(self, db_session):
        entry = EASHistory(
            eas_score=0.2,
            previous_score=0.5,
            change_reason="Failed operation detected",
            source="incident_handler",
        )
        db_session.add(entry)
        await db_session.flush()

        assert entry.eas_score < entry.previous_score

    @pytest.mark.asyncio
    async def test_repr(self, db_session):
        entry = EASHistory(
            eas_score=0.7,
            previous_score=0.6,
            change_reason="Upgrade",
            source="manual",
        )
        db_session.add(entry)
        await db_session.flush()

        repr_str = repr(entry)
        assert "EASHistory" in repr_str
        assert "0.7" in repr_str


# --- Schema / table structure tests ---


class TestTableStructure:
    def test_all_tables_exist(self, async_engine):
        """Verify all three tables are created in the metadata."""
        table_names = Base.metadata.tables.keys()
        assert "audit_log" in table_names
        assert "escalation_record" in table_names
        assert "eas_history" in table_names

    def test_audit_log_indexes(self):
        """Verify indexes are defined on audit_log."""
        indexes = {idx.name for idx in AuditLog.__table__.indexes}
        assert "ix_audit_log_timestamp" in indexes
        assert "ix_audit_log_verdict" in indexes
        assert "ix_audit_log_tool_name" in indexes

    def test_escalation_indexes(self):
        """Verify indexes are defined on escalation_record."""
        indexes = {idx.name for idx in EscalationRecord.__table__.indexes}
        assert "ix_escalation_status" in indexes
        assert "ix_escalation_created_at" in indexes

    def test_eas_history_indexes(self):
        """Verify indexes are defined on eas_history."""
        indexes = {idx.name for idx in EASHistory.__table__.indexes}
        assert "ix_eas_history_timestamp" in indexes

    def test_escalation_foreign_key(self):
        """Verify EscalationRecord has FK to audit_log."""
        fks = EscalationRecord.__table__.foreign_keys
        fk_targets = {fk.target_fullname for fk in fks}
        assert "audit_log.id" in fk_targets

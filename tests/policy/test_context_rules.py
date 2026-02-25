"""Tests for context-aware policy rules (site, role, tag rules) and YAML backward compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sna.policy.models import (
    PolicyConfig,
    RoleRule,
    SiteRule,
    TagRule,
    MaintenanceWindowConfig,
    Verdict,
)


class TestBackwardCompatibility:
    """Old YAML without Phase 6 fields still validates."""

    def test_old_yaml_loads(self, sample_policy_path: Path) -> None:
        """Existing default.yaml (no site_rules/role_rules/maintenance_windows) loads."""
        with open(sample_policy_path) as f:
            data = yaml.safe_load(f)

        policy = PolicyConfig(**data)
        assert policy.site_rules == []
        assert policy.role_rules == []
        assert policy.tag_rules == []
        assert policy.maintenance_windows == []

    def test_yaml_with_new_fields(self, sample_policy_path: Path) -> None:
        """YAML with new Phase 6 fields loads correctly."""
        with open(sample_policy_path) as f:
            data = yaml.safe_load(f)

        data["site_rules"] = [
            {"site": "production", "verdict": "BLOCK", "applies_to": "write", "reason": "No writes to production"},
        ]
        data["role_rules"] = [
            {"role": "core-router", "verdict": "ESCALATE", "applies_to": "all", "reason": "Core router requires escalation"},
        ]
        data["tag_rules"] = [
            {"tag": "production-core", "verdict": "BLOCK", "applies_to": "write", "reason": "Tagged production-core"},
        ]
        data["maintenance_windows"] = [
            {"name": "weekly", "sites": ["hq"], "devices": [], "start": "2026-02-24T00:00:00Z", "end": "2026-02-24T06:00:00Z"},
        ]

        policy = PolicyConfig(**data)
        assert len(policy.site_rules) == 1
        assert policy.site_rules[0].site == "production"
        assert policy.site_rules[0].verdict == Verdict.BLOCK
        assert len(policy.role_rules) == 1
        assert len(policy.tag_rules) == 1
        assert len(policy.maintenance_windows) == 1
        assert policy.maintenance_windows[0].name == "weekly"


class TestSiteRule:
    """SiteRule model validation."""

    def test_valid_site_rule(self) -> None:
        rule = SiteRule(site="hq", verdict=Verdict.BLOCK, reason="No writes to HQ")
        assert rule.site == "hq"
        assert rule.verdict == Verdict.BLOCK

    def test_default_applies_to(self) -> None:
        rule = SiteRule(site="dc1", verdict=Verdict.ESCALATE)
        assert rule.applies_to == "write"


class TestRoleRule:
    """RoleRule model validation."""

    def test_valid_role_rule(self) -> None:
        rule = RoleRule(role="core-router", verdict=Verdict.ESCALATE, reason="Core needs review")
        assert rule.role == "core-router"

    def test_default_applies_to(self) -> None:
        rule = RoleRule(role="switch", verdict=Verdict.PERMIT)
        assert rule.applies_to == "write"


class TestTagRule:
    """TagRule model validation."""

    def test_valid_tag_rule(self) -> None:
        rule = TagRule(tag="production-core", verdict=Verdict.BLOCK, reason="Prod core blocked")
        assert rule.tag == "production-core"

    def test_forbids_extra(self) -> None:
        with pytest.raises(Exception):
            TagRule(tag="x", verdict=Verdict.BLOCK, extra_field="bad")


class TestMaintenanceWindowConfig:
    """MaintenanceWindowConfig model validation."""

    def test_valid_window(self) -> None:
        w = MaintenanceWindowConfig(
            name="weekly",
            sites=["hq"],
            devices=["sw1"],
            start="2026-02-24T00:00:00Z",
            end="2026-02-24T06:00:00Z",
        )
        assert w.name == "weekly"
        assert "hq" in w.sites

    def test_minimal_window(self) -> None:
        w = MaintenanceWindowConfig(name="empty")
        assert w.sites == []
        assert w.devices == []
        assert w.start is None
        assert w.end is None

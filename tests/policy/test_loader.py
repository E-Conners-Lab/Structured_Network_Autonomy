"""Tests for sna.policy.loader — YAML loading, validation, hot reload, diff logging.

Covers:
- Loading a valid policy YAML
- Rejecting malformed YAML
- Rejecting invalid policy content
- Rejecting empty files
- File not found
- Hot reload with diff computation
- Diff detection for changed and unchanged policies
"""

from pathlib import Path

import pytest
import yaml

from sna.policy.loader import compute_policy_diff, load_policy, reload_policy
from sna.policy.models import PolicyConfig, RiskTier


@pytest.fixture
def valid_policy_yaml(tmp_path: Path) -> Path:
    """Write a valid policy YAML to a temp file."""
    content = {
        "version": "1.0",
        "action_tiers": {
            "tier_1_read": {
                "description": "Read ops",
                "default_verdict": "PERMIT",
                "examples": ["show_config"],
            },
            "tier_2_low_risk_write": {
                "description": "Low risk",
                "default_verdict": "PERMIT",
                "requires_audit": True,
                "examples": ["set_description"],
            },
            "tier_3_medium_risk_write": {
                "description": "Medium risk",
                "default_verdict": "ESCALATE",
                "examples": ["configure_route"],
            },
            "tier_4_high_risk_write": {
                "description": "High risk",
                "default_verdict": "ESCALATE",
                "requires_senior_approval": True,
                "examples": ["configure_bgp"],
            },
            "tier_5_critical": {
                "description": "Critical",
                "default_verdict": "BLOCK",
                "examples": ["write_erase"],
            },
        },
        "confidence_thresholds": {
            "tier_1_read": 0.1,
            "tier_2_low_risk_write": 0.3,
            "tier_3_medium_risk_write": 0.6,
            "tier_4_high_risk_write": 0.8,
            "tier_5_critical": 1.0,
        },
        "eas_modulation": {
            "enabled": True,
            "max_threshold_reduction": 0.1,
            "min_eas_for_modulation": 0.3,
        },
        "scope_limits": {
            "max_devices_per_action": 3,
            "escalate_above": 3,
        },
        "default_tier_for_unknown": "tier_3_medium_risk_write",
        "hard_rules": {
            "always_block": ["write_erase", "factory_reset"],
            "description": "Always blocked",
        },
    }
    file_path = tmp_path / "policy.yaml"
    file_path.write_text(yaml.dump(content))
    return file_path


@pytest.fixture
def modified_policy_yaml(tmp_path: Path) -> Path:
    """Write a modified policy YAML (different thresholds)."""
    content = {
        "version": "1.1",
        "action_tiers": {
            "tier_1_read": {
                "description": "Read ops",
                "default_verdict": "PERMIT",
                "examples": ["show_config"],
            },
            "tier_2_low_risk_write": {
                "description": "Low risk",
                "default_verdict": "PERMIT",
                "requires_audit": True,
                "examples": ["set_description"],
            },
            "tier_3_medium_risk_write": {
                "description": "Medium risk",
                "default_verdict": "ESCALATE",
                "examples": ["configure_route"],
            },
            "tier_4_high_risk_write": {
                "description": "High risk",
                "default_verdict": "ESCALATE",
                "requires_senior_approval": True,
                "examples": ["configure_bgp"],
            },
            "tier_5_critical": {
                "description": "Critical",
                "default_verdict": "BLOCK",
                "examples": ["write_erase"],
            },
        },
        "confidence_thresholds": {
            "tier_1_read": 0.2,
            "tier_2_low_risk_write": 0.4,
            "tier_3_medium_risk_write": 0.7,
            "tier_4_high_risk_write": 0.85,
            "tier_5_critical": 1.0,
        },
        "eas_modulation": {
            "enabled": True,
            "max_threshold_reduction": 0.1,
            "min_eas_for_modulation": 0.3,
        },
        "scope_limits": {
            "max_devices_per_action": 3,
            "escalate_above": 3,
        },
        "default_tier_for_unknown": "tier_3_medium_risk_write",
        "hard_rules": {
            "always_block": ["write_erase", "factory_reset"],
            "description": "Always blocked",
        },
    }
    file_path = tmp_path / "policy_modified.yaml"
    file_path.write_text(yaml.dump(content))
    return file_path


class TestLoadPolicy:
    @pytest.mark.asyncio
    async def test_load_valid_policy(self, valid_policy_yaml):
        policy = await load_policy(str(valid_policy_yaml))
        assert isinstance(policy, PolicyConfig)
        assert policy.version == "1.0"
        assert len(policy.action_tiers) == 5

    @pytest.mark.asyncio
    async def test_load_default_policy(self, sample_policy_path):
        policy = await load_policy(str(sample_policy_path))
        assert policy.version == "1.0"
        assert policy.default_tier_for_unknown == RiskTier.TIER_3_MEDIUM_RISK_WRITE

    @pytest.mark.asyncio
    async def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            await load_policy("/nonexistent/path/policy.yaml")

    @pytest.mark.asyncio
    async def test_empty_file_rejected(self, tmp_path):
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        with pytest.raises(ValueError, match="empty"):
            await load_policy(str(empty_file))

    @pytest.mark.asyncio
    async def test_malformed_yaml_rejected(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{{ not: valid: yaml: [[")
        with pytest.raises(yaml.YAMLError):
            await load_policy(str(bad_file))

    @pytest.mark.asyncio
    async def test_invalid_content_rejected(self, tmp_path):
        invalid_file = tmp_path / "invalid.yaml"
        invalid_file.write_text(yaml.dump({"version": "1.0"}))
        with pytest.raises(Exception):  # ValidationError
            await load_policy(str(invalid_file))

    @pytest.mark.asyncio
    async def test_extra_field_rejected(self, tmp_path, valid_policy_yaml):
        # Load valid content, add extra field, re-write
        content = yaml.safe_load(valid_policy_yaml.read_text())
        content["unexpected_field"] = "bad"
        bad_file = tmp_path / "extra.yaml"
        bad_file.write_text(yaml.dump(content))
        with pytest.raises(Exception):  # ValidationError
            await load_policy(str(bad_file))


class TestReloadPolicy:
    @pytest.mark.asyncio
    async def test_reload_without_current(self, valid_policy_yaml):
        new_policy, diff = await reload_policy(str(valid_policy_yaml))
        assert isinstance(new_policy, PolicyConfig)
        assert diff is None

    @pytest.mark.asyncio
    async def test_reload_with_changes(self, valid_policy_yaml, modified_policy_yaml):
        current = await load_policy(str(valid_policy_yaml))
        new_policy, diff = await reload_policy(str(modified_policy_yaml), current)
        assert new_policy.version == "1.1"
        assert diff is not None
        assert "policy (before)" in diff
        assert "policy (after)" in diff

    @pytest.mark.asyncio
    async def test_reload_no_changes(self, valid_policy_yaml):
        current = await load_policy(str(valid_policy_yaml))
        new_policy, diff = await reload_policy(str(valid_policy_yaml), current)
        assert diff is None


class TestComputePolicyDiff:
    @pytest.mark.asyncio
    async def test_identical_policies_no_diff(self, valid_policy_yaml):
        policy = await load_policy(str(valid_policy_yaml))
        diff = compute_policy_diff(policy, policy)
        assert diff is None

    @pytest.mark.asyncio
    async def test_different_policies_produce_diff(
        self, valid_policy_yaml, modified_policy_yaml
    ):
        old = await load_policy(str(valid_policy_yaml))
        new = await load_policy(str(modified_policy_yaml))
        diff = compute_policy_diff(old, new)
        assert diff is not None
        assert len(diff) > 0

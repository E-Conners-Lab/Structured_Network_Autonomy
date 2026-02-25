"""Tests for EAS auto-adjustment engine."""

from __future__ import annotations

import pytest

from sna.policy.eas_adjuster import EASAdjuster, EASAdjustmentConfig
from sna.policy.models import RiskTier, Verdict


class TestEASAdjuster:
    """EAS adjuster tests."""

    def test_permit_increases_eas(self) -> None:
        adjuster = EASAdjuster()
        adjuster.record_verdict(Verdict.PERMIT, RiskTier.TIER_2_LOW_RISK_WRITE)
        new_eas = adjuster.apply_to_score(0.5)
        assert new_eas > 0.5

    def test_block_decreases_eas(self) -> None:
        adjuster = EASAdjuster()
        adjuster.record_verdict(Verdict.BLOCK, RiskTier.TIER_5_CRITICAL)
        new_eas = adjuster.apply_to_score(0.5)
        assert new_eas < 0.5

    def test_escalate_decreases_eas(self) -> None:
        adjuster = EASAdjuster()
        adjuster.record_verdict(Verdict.ESCALATE, RiskTier.TIER_3_MEDIUM_RISK_WRITE)
        new_eas = adjuster.apply_to_score(0.5)
        assert new_eas < 0.5

    def test_tier1_read_less_increase_than_tier3(self) -> None:
        """Anti-gaming: tier 1 reads contribute less than higher tiers."""
        adj_tier1 = EASAdjuster()
        adj_tier1.record_verdict(Verdict.PERMIT, RiskTier.TIER_1_READ)
        score_tier1 = adj_tier1.apply_to_score(0.5)

        adj_tier3 = EASAdjuster()
        adj_tier3.record_verdict(Verdict.PERMIT, RiskTier.TIER_3_MEDIUM_RISK_WRITE)
        score_tier3 = adj_tier3.apply_to_score(0.5)

        assert score_tier3 > score_tier1

    def test_tier5_critical_zero_increase(self) -> None:
        """Critical tier never increases EAS."""
        adjuster = EASAdjuster()
        adjuster.record_verdict(Verdict.PERMIT, RiskTier.TIER_5_CRITICAL)
        new_eas = adjuster.apply_to_score(0.5)
        assert new_eas == pytest.approx(0.5)

    def test_clamps_to_zero(self) -> None:
        """EAS should not go below 0.0."""
        adjuster = EASAdjuster()
        for _ in range(100):
            adjuster.record_verdict(Verdict.BLOCK, RiskTier.TIER_5_CRITICAL)
        new_eas = adjuster.apply_to_score(0.01)
        assert new_eas >= 0.0

    def test_clamps_to_one(self) -> None:
        """EAS should not exceed 1.0."""
        adjuster = EASAdjuster()
        for _ in range(100):
            adjuster.record_verdict(Verdict.PERMIT, RiskTier.TIER_4_HIGH_RISK_WRITE)
        new_eas = adjuster.apply_to_score(0.99)
        assert new_eas <= 1.0

    def test_max_increase_clamped(self) -> None:
        """Adjustment should not exceed max_increase_per_interval."""
        config = EASAdjustmentConfig(
            permit_increase=0.1,
            max_increase_per_interval=0.02,
        )
        adjuster = EASAdjuster(config)
        for _ in range(100):
            adjuster.record_verdict(Verdict.PERMIT, RiskTier.TIER_3_MEDIUM_RISK_WRITE)
        adjustment = adjuster.compute_adjustment()
        assert adjustment <= 0.02

    def test_max_decrease_clamped(self) -> None:
        """Adjustment should not exceed max_decrease_per_interval."""
        config = EASAdjustmentConfig(
            block_decrease=0.5,
            max_decrease_per_interval=0.05,
        )
        adjuster = EASAdjuster(config)
        for _ in range(100):
            adjuster.record_verdict(Verdict.BLOCK, RiskTier.TIER_5_CRITICAL)
        adjustment = adjuster.compute_adjustment()
        assert adjustment >= -0.05

    def test_compute_resets_accumulator(self) -> None:
        """After compute_adjustment, the accumulator resets."""
        adjuster = EASAdjuster()
        adjuster.record_verdict(Verdict.PERMIT, RiskTier.TIER_2_LOW_RISK_WRITE)
        adjuster.compute_adjustment()
        # Second call should return 0
        assert adjuster.compute_adjustment() == 0.0

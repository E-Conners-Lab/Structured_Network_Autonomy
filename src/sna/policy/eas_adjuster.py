"""Automated EAS adjustment engine — rules-based EAS tuning.

Successful PERMIT executions increase EAS (reward).
BLOCK/ESCALATE events decrease EAS (penalty).
Anti-gaming: Tier 1 reads contribute less than higher-tier permits.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from sna.policy.models import RiskTier, Verdict

logger = structlog.get_logger()

# Weight multipliers per tier — prevents gaming via bulk read requests
TIER_WEIGHTS: dict[RiskTier, float] = {
    RiskTier.TIER_1_READ: 0.2,
    RiskTier.TIER_2_LOW_RISK_WRITE: 0.5,
    RiskTier.TIER_3_MEDIUM_RISK_WRITE: 1.0,
    RiskTier.TIER_4_HIGH_RISK_WRITE: 1.5,
    RiskTier.TIER_5_CRITICAL: 0.0,  # Critical tier never increases EAS
}


@dataclass
class EASAdjustmentConfig:
    """Configuration for EAS adjustment rates."""

    permit_increase: float = 0.005
    escalate_decrease: float = 0.01
    block_decrease: float = 0.02
    max_increase_per_interval: float = 0.05
    max_decrease_per_interval: float = 0.1


class EASAdjuster:
    """Adjusts the EAS score based on policy verdicts.

    Args:
        config: Adjustment rate configuration.
    """

    def __init__(self, config: EASAdjustmentConfig | None = None) -> None:
        self._config = config or EASAdjustmentConfig()
        self._pending_adjustment: float = 0.0

    def record_verdict(self, verdict: Verdict, risk_tier: RiskTier) -> None:
        """Record a verdict for EAS adjustment.

        Args:
            verdict: The policy verdict.
            risk_tier: The risk tier of the evaluated action.
        """
        if verdict == Verdict.PERMIT:
            weight = TIER_WEIGHTS.get(risk_tier, 0.5)
            adjustment = self._config.permit_increase * weight
            self._pending_adjustment += adjustment

        elif verdict == Verdict.ESCALATE:
            self._pending_adjustment -= self._config.escalate_decrease

        elif verdict == Verdict.BLOCK:
            self._pending_adjustment -= self._config.block_decrease

    def compute_adjustment(self) -> float:
        """Compute and reset the pending EAS adjustment.

        Returns the clamped adjustment value and resets the accumulator.

        Returns:
            The adjustment to apply (positive = increase, negative = decrease).
        """
        adj = self._pending_adjustment

        # Clamp to configured limits
        if adj > 0:
            adj = min(adj, self._config.max_increase_per_interval)
        else:
            adj = max(adj, -self._config.max_decrease_per_interval)

        self._pending_adjustment = 0.0
        return adj

    def apply_to_score(self, current_eas: float) -> float:
        """Apply the pending adjustment to the current EAS.

        Clamps result to [0.0, 1.0].

        Args:
            current_eas: The current EAS score.

        Returns:
            The new EAS score after adjustment.
        """
        adjustment = self.compute_adjustment()
        new_eas = current_eas + adjustment
        return max(0.0, min(1.0, new_eas))

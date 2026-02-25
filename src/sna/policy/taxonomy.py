"""Action classification and threshold computation.

Pure functions — no I/O, no side effects. All logic derived from PolicyConfig.

Functions:
    classify_tool: Maps a tool name to its RiskTier
    get_effective_threshold: Computes confidence threshold after EAS modulation
    is_hard_blocked: Checks if a tool is in the hard-block list
    check_scope_escalation: Checks if device count exceeds scope limits
"""

from __future__ import annotations

from sna.policy.models import PolicyConfig, RiskTier


def classify_tool(tool_name: str, policy: PolicyConfig) -> RiskTier:
    """Classify a tool name into its risk tier based on policy examples.

    Scans each tier's examples list for a match. If the tool is not found
    in any tier, returns the policy's default_tier_for_unknown.

    Args:
        tool_name: The MCP tool name to classify.
        policy: The loaded policy configuration.

    Returns:
        The RiskTier for this tool.
    """
    normalized = tool_name.strip().lower()
    for tier, tier_config in policy.action_tiers.items():
        if normalized in (ex.lower() for ex in tier_config.examples):
            return tier
    return policy.default_tier_for_unknown


def get_effective_threshold(
    tier: RiskTier,
    policy: PolicyConfig,
    current_eas: float,
) -> float:
    """Compute the effective confidence threshold after EAS modulation.

    Higher EAS reduces the threshold (grants more latitude). Lower EAS
    keeps the threshold at its base value.

    The reduction formula:
        reduction = max_threshold_reduction * current_eas
        effective = base_threshold - reduction

    Modulation only applies when:
        - eas_modulation.enabled is True
        - current_eas >= eas_modulation.min_eas_for_modulation

    The effective threshold is clamped to [0.0, 1.0].

    Args:
        tier: The risk tier to get the threshold for.
        policy: The loaded policy configuration.
        current_eas: The agent's current Earned Autonomy Score (0.0–1.0).

    Returns:
        The effective confidence threshold as a float.
    """
    base_threshold = policy.confidence_thresholds.get_threshold(tier)

    if not policy.eas_modulation.enabled:
        return base_threshold

    if current_eas < policy.eas_modulation.min_eas_for_modulation:
        return base_threshold

    reduction = policy.eas_modulation.max_threshold_reduction * current_eas
    effective = base_threshold - reduction
    return max(0.0, min(1.0, effective))


def is_hard_blocked(tool_name: str, policy: PolicyConfig) -> bool:
    """Check if a tool is in the hard-block list.

    Hard-blocked tools are always BLOCK regardless of confidence, EAS, or scope.
    Cannot be unlocked at runtime.

    Args:
        tool_name: The MCP tool name to check.
        policy: The loaded policy configuration.

    Returns:
        True if the tool is hard-blocked.
    """
    normalized = tool_name.strip().lower()
    return normalized in (name.lower() for name in policy.hard_rules.always_block)


def check_scope_escalation(device_count: int, policy: PolicyConfig) -> bool:
    """Check if the number of target devices exceeds the scope escalation limit.

    Args:
        device_count: Number of devices the action targets.
        policy: The loaded policy configuration.

    Returns:
        True if the device count exceeds scope_limits.escalate_above.
    """
    return device_count > policy.scope_limits.escalate_above

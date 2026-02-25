"""Context-aware policy rule evaluation — site, role, and tag rules.

Evaluates contextual rules from PolicyConfig during engine.evaluate().
Priority: tag > role > site. Most restrictive verdict wins (BLOCK > ESCALATE > PERMIT).
Fail-closed: any exception during evaluation returns BLOCK.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from sna.policy.models import (
    PolicyConfig,
    RiskTier,
    RoleRule,
    SiteRule,
    TagRule,
    Verdict,
)

logger = structlog.get_logger()

# Verdict severity for "most restrictive wins" logic
_VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.PERMIT: 0,
    Verdict.ESCALATE: 1,
    Verdict.BLOCK: 2,
}

# Priority levels for rule types (higher = higher priority)
_RULE_PRIORITY: dict[str, int] = {
    "site": 0,
    "role": 1,
    "tag": 2,
}


@dataclass
class MatchedRule:
    """A context rule that matched the evaluation request."""

    rule_type: str  # "site", "role", "tag"
    match_value: str  # The site name, role name, or tag value
    verdict: Verdict
    reason: str
    priority: int = 0


def _tool_matches_applies_to(tool_name: str, applies_to: str, tier: RiskTier) -> bool:
    """Check if a tool matches a rule's applies_to filter.

    applies_to can be:
    - "all": matches any tool
    - "write": matches tiers 2-5 (any write tier)
    - specific tool name: exact match (case-insensitive)
    """
    if applies_to == "all":
        return True
    if applies_to == "write":
        return tier not in (RiskTier.TIER_1_READ,)
    return tool_name.strip().lower() == applies_to.strip().lower()


def evaluate_site_rules(
    site: str,
    tool_name: str,
    tier: RiskTier,
    site_rules: list[SiteRule],
) -> list[MatchedRule]:
    """Evaluate site-based context rules.

    Args:
        site: The device site from evaluation context.
        tool_name: The tool being evaluated.
        tier: The classified risk tier.
        site_rules: Site rules from policy config.

    Returns:
        List of matched rules.
    """
    matches: list[MatchedRule] = []
    normalized_site = site.strip().lower()

    for rule in site_rules:
        if rule.site.strip().lower() == normalized_site:
            if _tool_matches_applies_to(tool_name, rule.applies_to, tier):
                matches.append(MatchedRule(
                    rule_type="site",
                    match_value=rule.site,
                    verdict=rule.verdict,
                    reason=rule.reason or f"Site rule: {rule.site} → {rule.verdict.value}",
                    priority=_RULE_PRIORITY["site"],
                ))

    return matches


def evaluate_role_rules(
    role: str,
    tool_name: str,
    tier: RiskTier,
    role_rules: list[RoleRule],
) -> list[MatchedRule]:
    """Evaluate role-based context rules.

    Args:
        role: The device role from evaluation context.
        tool_name: The tool being evaluated.
        tier: The classified risk tier.
        role_rules: Role rules from policy config.

    Returns:
        List of matched rules.
    """
    matches: list[MatchedRule] = []
    normalized_role = role.strip().lower()

    for rule in role_rules:
        if rule.role.strip().lower() == normalized_role:
            if _tool_matches_applies_to(tool_name, rule.applies_to, tier):
                matches.append(MatchedRule(
                    rule_type="role",
                    match_value=rule.role,
                    verdict=rule.verdict,
                    reason=rule.reason or f"Role rule: {rule.role} → {rule.verdict.value}",
                    priority=_RULE_PRIORITY["role"],
                ))

    return matches


def evaluate_tag_rules(
    tags: list[str],
    tool_name: str,
    tier: RiskTier,
    tag_rules: list[TagRule],
) -> list[MatchedRule]:
    """Evaluate tag-based context rules.

    Args:
        tags: The device tags from evaluation context.
        tool_name: The tool being evaluated.
        tier: The classified risk tier.
        tag_rules: Tag rules from policy config.

    Returns:
        List of matched rules.
    """
    matches: list[MatchedRule] = []
    normalized_tags = {t.strip().lower() for t in tags}

    for rule in tag_rules:
        if rule.tag.strip().lower() in normalized_tags:
            if _tool_matches_applies_to(tool_name, rule.applies_to, tier):
                matches.append(MatchedRule(
                    rule_type="tag",
                    match_value=rule.tag,
                    verdict=rule.verdict,
                    reason=rule.reason or f"Tag rule: {rule.tag} → {rule.verdict.value}",
                    priority=_RULE_PRIORITY["tag"],
                ))

    return matches


def resolve_context_verdict(matches: list[MatchedRule]) -> tuple[Verdict | None, str]:
    """Resolve the final verdict from all matched context rules.

    Priority: tag > role > site. Among same priority, most restrictive wins
    (BLOCK > ESCALATE > PERMIT).

    Args:
        matches: All matched context rules.

    Returns:
        Tuple of (verdict, reason). Verdict is None if no matches.
    """
    if not matches:
        return None, ""

    # Sort by priority (desc) then severity (desc) — highest priority + most restrictive first
    sorted_matches = sorted(
        matches,
        key=lambda m: (m.priority, _VERDICT_SEVERITY[m.verdict]),
        reverse=True,
    )

    winner = sorted_matches[0]
    return winner.verdict, winner.reason


def evaluate_context_rules(
    context: dict[str, object],
    tool_name: str,
    tier: RiskTier,
    policy: PolicyConfig,
) -> tuple[Verdict | None, list[MatchedRule]]:
    """Top-level entry point for context rule evaluation.

    Evaluates site, role, and tag rules from the policy against the
    evaluation context. Fail-closed: any exception returns BLOCK.

    Args:
        context: The evaluation request context dict.
        tool_name: The tool being evaluated.
        tier: The classified risk tier.
        policy: The loaded policy configuration.

    Returns:
        Tuple of (verdict, matched_rules). Verdict is None if no rules match.
    """
    try:
        all_matches: list[MatchedRule] = []

        # Evaluate site rules
        site = context.get("site")
        if isinstance(site, str) and site.strip() and policy.site_rules:
            all_matches.extend(
                evaluate_site_rules(site, tool_name, tier, policy.site_rules)
            )

        # Evaluate role rules
        role = context.get("device_role")
        if isinstance(role, str) and role.strip() and policy.role_rules:
            all_matches.extend(
                evaluate_role_rules(role, tool_name, tier, policy.role_rules)
            )

        # Evaluate tag rules
        tags = context.get("device_tags")
        if isinstance(tags, list) and tags and policy.tag_rules:
            str_tags = [t for t in tags if isinstance(t, str)]
            if str_tags:
                all_matches.extend(
                    evaluate_tag_rules(str_tags, tool_name, tier, policy.tag_rules)
                )

        if not all_matches:
            return None, []

        verdict, _reason = resolve_context_verdict(all_matches)
        return verdict, all_matches

    except Exception:
        logger.exception("context_rule_evaluation_failed", tool_name=tool_name)
        return Verdict.BLOCK, [
            MatchedRule(
                rule_type="error",
                match_value="evaluation_failure",
                verdict=Verdict.BLOCK,
                reason="Context rule evaluation failed — failing safe",
                priority=99,
            )
        ]


def evaluate_agent_overrides(
    overrides: list[dict],
    context: dict[str, object],
    tool_name: str,
    tier: RiskTier,
) -> tuple[Verdict | None, list[MatchedRule]]:
    """Evaluate agent-specific policy overrides.

    Each override contains rule_type and rule_json with the rule details.

    Args:
        overrides: List of override dicts with rule_type, rule_json, priority.
        context: The evaluation request context dict.
        tool_name: The tool being evaluated.
        tier: The classified risk tier.

    Returns:
        Tuple of (verdict, matched_rules). Verdict is None if no overrides match.
    """
    try:
        all_matches: list[MatchedRule] = []

        for override in overrides:
            rule_type = override.get("rule_type", "")
            rule_json = override.get("rule_json", {})
            priority = override.get("priority", 0)

            if rule_type == "site":
                site_val = context.get("site")
                if isinstance(site_val, str) and site_val.strip():
                    rule = SiteRule(**rule_json)
                    matches = evaluate_site_rules(site_val, tool_name, tier, [rule])
                    for m in matches:
                        m.rule_type = "agent_override_site"
                        m.priority = priority + 10  # Agent overrides have elevated priority
                    all_matches.extend(matches)

            elif rule_type == "role":
                role_val = context.get("device_role")
                if isinstance(role_val, str) and role_val.strip():
                    rule = RoleRule(**rule_json)
                    matches = evaluate_role_rules(role_val, tool_name, tier, [rule])
                    for m in matches:
                        m.rule_type = "agent_override_role"
                        m.priority = priority + 10
                    all_matches.extend(matches)

            elif rule_type == "tag":
                tags = context.get("device_tags")
                if isinstance(tags, list) and tags:
                    str_tags = [t for t in tags if isinstance(t, str)]
                    if str_tags:
                        rule = TagRule(**rule_json)
                        matches = evaluate_tag_rules(str_tags, tool_name, tier, [rule])
                        for m in matches:
                            m.rule_type = "agent_override_tag"
                            m.priority = priority + 10
                        all_matches.extend(matches)

            elif rule_type == "tool":
                # Tool-level override: matches if tool name matches
                target_tool = rule_json.get("tool_name", "")
                verdict_str = rule_json.get("verdict", "")
                reason = rule_json.get("reason", "")
                if target_tool.strip().lower() == tool_name.strip().lower():
                    try:
                        verdict = Verdict(verdict_str)
                    except ValueError:
                        continue
                    all_matches.append(MatchedRule(
                        rule_type="agent_override_tool",
                        match_value=target_tool,
                        verdict=verdict,
                        reason=reason or f"Agent override: {target_tool} → {verdict.value}",
                        priority=priority + 10,
                    ))

        if not all_matches:
            return None, []

        verdict, _reason = resolve_context_verdict(all_matches)
        return verdict, all_matches

    except Exception:
        logger.exception("agent_override_evaluation_failed", tool_name=tool_name)
        return Verdict.BLOCK, [
            MatchedRule(
                rule_type="error",
                match_value="agent_override_failure",
                verdict=Verdict.BLOCK,
                reason="Agent override evaluation failed — failing safe",
                priority=99,
            )
        ]


def merge_verdicts(
    global_verdict: Verdict | None,
    agent_verdict: Verdict | None,
) -> Verdict | None:
    """Merge global and agent verdicts — returns the more restrictive.

    Agent overrides can only make things MORE restrictive, never less.
    BLOCK > ESCALATE > PERMIT > None.

    Args:
        global_verdict: The verdict from global context rules.
        agent_verdict: The verdict from agent-specific overrides.

    Returns:
        The more restrictive verdict, or None if both are None.
    """
    if global_verdict is None and agent_verdict is None:
        return None

    if global_verdict is None:
        return agent_verdict
    if agent_verdict is None:
        return global_verdict

    # Return whichever is more restrictive
    if _VERDICT_SEVERITY[agent_verdict] >= _VERDICT_SEVERITY[global_verdict]:
        return agent_verdict
    return global_verdict

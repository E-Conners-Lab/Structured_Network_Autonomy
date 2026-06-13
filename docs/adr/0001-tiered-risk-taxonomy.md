# ADR-0001: Five-tier risk taxonomy for agent actions

- Status: Accepted
- Date: 2026-06-12

## Context

An AI agent calling network tools needs a way to know how dangerous each action is before it runs. A flat allow/deny list does not capture the reality that reading a routing table and wiping a config are not the same kind of operation, and a binary gate forces you to either over-restrict reads or under-restrict writes. We needed a classification that the policy engine could reason about uniformly, that was data-driven rather than hardcoded, and that had a safe default for tools nobody has classified yet.

## Decision

Every action is classified into one of five risk tiers, defined as `RiskTier` in `src/sna/policy/models.py`:

- `tier_1_read` — read-only operations
- `tier_2_low_risk_write` — low-risk writes
- `tier_3_medium_risk_write` — medium-risk writes
- `tier_4_high_risk_write` — high-risk writes
- `tier_5_critical` — critical operations

Classification lives in `src/sna/policy/taxonomy.py` as pure functions with no I/O. `classify_tool` scans each tier's `examples` list from the loaded `PolicyConfig` and returns the matching tier. The tier-to-tool mapping is policy data (`policies/default.yaml`), not code, so the taxonomy can be retuned without a release.

A tool that matches no tier returns `default_tier_for_unknown`, which is set to `tier_3_medium_risk_write`. Unknown means "treat it as a medium-risk write," not "allow it." That is the conservative default that keeps a newly added tool from slipping through as a harmless read.

## Consequences

- The tier is the single input that downstream policy (confidence thresholds, scope checks, EAS modulation) keys off of, so every other rule gets simpler.
- Retuning risk is a YAML edit plus a test run, not a code change.
- Pure classification functions are trivial to unit test and have drift-guard tests binding the in-code tiers to the policy file.
- Misclassifying a genuinely dangerous tool as a lower tier is the main failure mode, which is why hard blocks (see [ADR-0002](0002-verdict-model-permit-escalate-block.md)) exist as a tier-independent backstop.

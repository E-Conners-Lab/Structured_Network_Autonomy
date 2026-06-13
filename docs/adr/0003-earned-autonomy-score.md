# ADR-0003: Earned Autonomy Score

- Status: Accepted
- Date: 2026-06-12

## Context

A static confidence threshold treats an agent on its first day the same as one with a long clean track record. That is both too strict (a proven agent keeps hitting escalations for routine work) and too blunt (nothing rewards good behavior or penalizes bad). We wanted trust to be earned and revocable, expressed as a number the policy engine could fold into its existing threshold math rather than a separate special case.

## Decision

Each agent carries an Earned Autonomy Score (EAS), a float in `[0.0, 1.0]`. The EAS modulates the confidence threshold an action must clear, rather than gating actions directly.

`get_effective_threshold` in `src/sna/policy/taxonomy.py` computes:

```
effective = base_threshold - eas_reduction + criticality_increase - history_bonus
```

clamped to `[0.0, 1.0]`. EAS reduction only applies when modulation is enabled and the agent's EAS is at or above `min_eas_for_modulation`. A trusted agent therefore needs less confidence to clear the same tier, and a distrusted one needs more.

The score itself is adjusted by `EASAdjuster` in `src/sna/policy/eas_adjuster.py`:

- Successful PERMIT executions increase EAS (reward).
- BLOCK and ESCALATE events decrease it (penalty).
- Per-interval caps (`max_increase_per_interval`, `max_decrease_per_interval`) keep any single burst from swinging trust too far.

Anti-gaming is built in through tier weights: a Tier 1 read contributes 0.2, a Tier 3 write 1.0, a Tier 4 write 1.5, and Tier 5 critical contributes 0.0 so an agent can never farm trust by spamming reads or by touching critical infrastructure.

## Consequences

- Trust is continuous and reversible. An agent that starts misbehaving loses autonomy automatically as its EAS decays.
- EAS lowers the threshold but never removes the gate. Hard blocks, scope checks, and the audit-write requirement from [ADR-0002](0002-verdict-model-permit-escalate-block.md) all still apply regardless of score.
- Tier 5 contributing nothing means the highest-risk actions can never be the path to more autonomy, which is the property we most wanted to preserve.
- EAS is observable (exported as a metric), so trust drift is something an operator can watch rather than discover after the fact.

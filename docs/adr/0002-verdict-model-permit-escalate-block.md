# ADR-0002: PERMIT / ESCALATE / BLOCK verdict model

- Status: Accepted
- Date: 2026-06-12

## Context

The policy engine has to return something the calling agent can act on without interpretation. A raw allow/deny is too coarse: a lot of real actions are not clearly safe or clearly forbidden, they are "a human should look at this first." We also needed the verdict to be auditable, and we needed a guarantee that the engine can never quietly permit something it failed to record.

## Decision

The engine returns one of three verdicts, defined as `Verdict` in `src/sna/policy/models.py`:

- `PERMIT` — the action may execute
- `ESCALATE` — hold for human approval
- `BLOCK` — refuse outright

`PolicyEngine.evaluate` in `src/sna/policy/engine.py` resolves the verdict in a fixed order:

1. Hard-block check. If the tool is on the always-block list, return `BLOCK` immediately. This is independent of tier or confidence and cannot be overridden at runtime.
2. Context rules. If a context rule resolves to `BLOCK` or `ESCALATE`, honor it.
3. Scope check. If the action touches more devices than the tier allows, `ESCALATE`.
4. Confidence check. Compare the action's confidence score to the effective threshold for its tier. Below threshold means `ESCALATE`.
5. Otherwise apply the tier's default verdict.
6. Write the audit log. If the audit write fails, the verdict is overridden to `BLOCK`.

Step 6 is the load-bearing rule: the engine never permits an action it cannot log. An action that would otherwise be permitted is blocked if it cannot be recorded.

## Consequences

- ESCALATE gives the system a first-class "ask a human" path, so the engine does not have to choose between blocking safe-ish actions and rubber-stamping risky ones.
- Ordering matters and is deliberate: hard blocks and context rules win before confidence is ever consulted, so a high-confidence agent cannot talk its way past a hard block.
- Tying PERMIT to a successful audit write means observability is not optional. Lose the audit trail and the engine fails closed.
- ESCALATE carries `requires_senior_approval` from the tier config, so the escalation target scales with the tier.

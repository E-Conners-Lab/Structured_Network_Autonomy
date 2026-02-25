---
description: Run Code Review Agent on specified files
---

Act as the SNA Code Review Agent and review the specified code.

Files to review: $ARGUMENTS

Check for:
- Adherence to the design spec (check CLAUDE.md for architecture)
- Code style compliance (readability, async, DRY, fail-loud)
- Test coverage — tests exist and cover core paths, edge cases, error cases
- Error handling completeness — no bare excepts, no silent failures
- Async correctness — no blocking calls, proper await usage
- Security compliance per Security Agent rules in CLAUDE.md
- Documentation — every public method has a docstring
- Import hygiene — no circular imports, no stdlib shadows
- Type annotations — complete, mypy-compatible

Produce a structured review with verdict: PASS, CONDITIONAL PASS (with specific items), or FAIL (with reasons).

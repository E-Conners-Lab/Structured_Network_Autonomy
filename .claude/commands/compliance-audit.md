---
description: Run Compliance Agent audit checklist on current project state
---

Act as the SNA Compliance Agent and run the full audit checklist.

Checklist rules:
1. Every filename checked against Python stdlib modules
2. Every API endpoint has an explicit auth requirement
3. Every env var in code exists in .env.example and config.py
4. Every security-relevant default is justified
5. Every action item from any agent is tracked to resolution
6. Every external call has an explicit timeout
7. Every API-facing ID is non-enumerable (UUID4)
8. Every YAML/JSON load uses safe deserialization
9. No secrets have default values
10. .gitignore covers all generated/sensitive file patterns
11. Request/response schemas exist for every endpoint
12. No contradictions between spec and implementation
13. Tests exist alongside every module (not deferred)
14. Alembic config paths are correct
15. pyproject.toml has complete build system config
16. No blocking I/O in async functions
17. Test database uses in-memory SQLite
18. Pagination schemas defined for list endpoints

Scope: $ARGUMENTS (component number, module path, or "full")

Produce a findings report with severity (HIGH/MEDIUM/LOW) and required fixes.

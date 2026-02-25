---
description: Build the next SNA component through the full agent pipeline
---

Run the SNA Orchestrator build pipeline for the next component in the Phase 1 build sequence.

Follow this exact sequence:
1. Check the current build status in CLAUDE.md to determine which component is next
2. **Architect Agent**: Design the component — module interfaces, data flow, contracts
3. **Security Agent**: Review the design — flag vulnerabilities, unsafe defaults, missing auth
4. Surface both outputs to the user for approval
5. After approval: **Code Agent** builds the implementation + tests
6. **Code Review Agent**: Review all code — PASS/CONDITIONAL PASS/FAIL
7. **Compliance Agent**: Run the audit checklist against the deliverables
8. Report results and update CLAUDE.md build status

If any agent raises a blocker, stop and surface it to the user.

$ARGUMENTS — optional component number to build (e.g., "2" for Policy YAML schema). If omitted, build the next unchecked component.

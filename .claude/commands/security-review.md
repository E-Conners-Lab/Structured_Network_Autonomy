---
description: Run Security Agent review on specified files or the entire project
---

Act as the SNA Security Agent and perform a security review.

Review scope: $ARGUMENTS (file paths, module names, or "full" for entire project)

Check for:
- Credentials or secrets in code (must use env vars)
- SQL injection / string interpolation in queries
- Input validation — all API inputs through Pydantic
- Webhook URLs in logs
- Audit log mutability (must be append-only)
- Missing timeouts on HTTP calls
- Stack traces in API responses
- yaml.load() instead of yaml.safe_load()
- Enumerable IDs exposed in APIs
- Missing auth on endpoints
- Unsafe defaults on security-relevant config
- Blocking calls in async code

Produce a structured report with PASS/FAIL per check and specific line references for any findings.

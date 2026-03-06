# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SNA, please report it responsibly.

**Do not open a public issue.** Instead, email security concerns to the repository maintainers via GitHub's private vulnerability reporting feature, or contact the maintainers directly through their GitHub profiles.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

The following are in scope for security reports:
- Authentication bypass
- Policy engine bypass (actions executing without proper evaluation)
- Audit log tampering or deletion
- Credential exposure in logs or API responses
- YAML injection or unsafe deserialization
- SQL injection
- Command injection via device execution layer

## Security Design

SNA follows these security principles:
- All credentials via environment variables, never in code
- API key authentication on all endpoints (except minimal health check)
- Append-only audit log with no update/delete operations
- Pydantic validation on all API inputs
- Sanitized error responses (no stack traces exposed)
- `yaml.safe_load()` exclusively
- Explicit timeouts on all external HTTP calls
- Fails closed — if the database is unreachable, non-read actions are BLOCK

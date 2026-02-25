# Structured Network Autonomy (SNA)

Governance framework for AI agents operating in enterprise networks. Production project.

## Project Structure

```
src/sna/           — Main package (src-layout)
  policy/          — Policy Engine domain logic (engine, models, loader, taxonomy)
  db/              — Async SQLAlchemy models and session (SQLite, swappable to Postgres)
  api/             — FastAPI application, routes, auth, schemas
  integrations/    — Notifications (Discord + Teams), MCP wrapper
  config.py        — Pydantic Settings (all config via env vars)
  log_config.py    — Structured JSON logging (structlog over stdlib)
tests/             — Mirrors src/sna/ structure
policies/          — Runtime YAML policy files
```

## Orchestrator Agent Protocol

This project uses a multi-agent build system. Claude acts as the Orchestrator managing five specialist agents:

1. **Architect Agent** — designs before code is written. Produces directory structure, module boundaries, interface contracts.
2. **Security Agent** — reviews every design and every piece of code. Has veto power. Must explicitly sign off.
3. **Code Agent** — implements from approved specs only. Does not make architectural decisions.
4. **Code Review Agent** — reviews all code. Verdicts: PASS, CONDITIONAL PASS, FAIL.
5. **Compliance Agent** — runs systematic audit checklists. Catches gaps, contradictions, oversights.

**Build sequence per component:** Architect → Security → Code → Code Review → Compliance → User approval.

## Code Style Rules — Non-Negotiable

- Readability first — meaningful names, no obscure abbreviations
- Async throughout — asyncio everywhere, no blocking calls
- Fail loud — explicit error handling, no silent failures, no bare excepts
- Test-driven — pytest tests written alongside every module
- DRY — clean architecture, no repetition
- Descriptive commit messages
- Every public method has a docstring
- Structured JSON logging via structlog (wrapping stdlib logging)
- All config via environment variables with python-dotenv
- SQLAlchemy async with SQLite (swappable to Postgres)

## Security Rules — Every Component

- No credentials or secrets in code — environment variables only
- All database writes use parameterized queries (SQLAlchemy ORM)
- All API endpoints validate input via Pydantic
- Webhook URLs (Discord, Teams) are secrets — never logged
- Audit log is append-only — no update or delete routes ever
- Policy file changes logged with before/after diff
- Every external HTTP call has explicit timeout (HTTPX_TIMEOUT_SECONDS)
- Never expose stack traces in API responses — log internally, return sanitized error
- yaml.safe_load() only — never yaml.load()
- All API-facing IDs use UUID4 to prevent enumeration
- API key auth on all endpoints except GET /health (minimal)
- Scrapli connections: always timeout_socket=10 and timeout_transport=10

## Key Dependencies

- FastAPI, Uvicorn — API layer
- SQLAlchemy async + aiosqlite — persistence
- Pydantic v2 + pydantic-settings — validation and config
- structlog — structured logging
- httpx — async HTTP client
- slowapi — rate limiting
- aiofiles — async file I/O
- Alembic — database migrations
- pytest + pytest-asyncio — testing

## Environment Setup

```bash
uv pip install -e ".[dev]"
```

Required env vars (see .env.example): SNA_API_KEY, SNA_ADMIN_API_KEY, DATABASE_URL.

## Build Status

Phase 1: Policy Engine
- [x] Component 1: Project scaffolding
- [x] Component 2: Policy YAML schema & Pydantic models + tests
- [x] Component 3: Database models + tests
- [x] Component 4: Core PolicyEngine class + tests
- [ ] Component 5: FastAPI application & routes + tests
- [ ] Component 6: Notification integrations (Discord + Teams) + tests
- [ ] Component 7: MCP integration wrapper + tests
- [ ] Component 8: Integration test suite + coverage verification

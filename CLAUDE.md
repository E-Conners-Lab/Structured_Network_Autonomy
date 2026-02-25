# Structured Network Autonomy (SNA)

Governance framework for AI agents operating in enterprise networks. Production project.

## Project Structure

```
src/sna/           — Main package (src-layout)
  policy/          — Policy Engine domain logic (engine, models, loader, taxonomy, eas_adjuster, maintenance)
  db/              — Async SQLAlchemy models and session (SQLite, swappable to Postgres)
  api/             — FastAPI application, routes, auth, schemas, error handlers
  devices/         — Scrapli driver, command builder, executor, rollback, sanitizer, registry
  integrations/    — Notifications (Discord + Teams), MCP wrapper, NetBox client
  mcp_server/      — FastMCP server with read/write tool registration
  observability/   — Prometheus metrics, correlation ID middleware
  validation/      — Post-change validators (config diff, interface up, reachability)
  config.py        — Pydantic Settings (all config via env vars)
  log_config.py    — Structured JSON logging (structlog over stdlib)
  cli.py           — Typer CLI (serve, mcp-serve, evaluate, migrate)
tests/             — Mirrors src/sna/ structure
policies/          — Runtime YAML policy files
dashboard/         — React/Vite UI (verdicts, escalations, audit, EAS, agents, policy viewer)
docker/            — Docker support files
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

### Phase 1: Policy Engine — COMPLETE
- [x] Component 1: Project scaffolding
- [x] Component 2: Policy YAML schema & Pydantic models + tests
- [x] Component 3: Database models + tests
- [x] Component 4: Core PolicyEngine class + tests
- [x] Component 5: FastAPI application & routes + tests
- [x] Component 6: Notification integrations (Discord + Teams) + tests
- [x] Component 7: MCP integration wrapper + tests
- [x] Component 8: Integration test suite + coverage verification (96% coverage)

### Phase 2: Device Execution & Operational Readiness — COMPLETE
- [x] Component 9: Device driver layer (AsyncScrapli wrapper, connection pooling, timeout enforcement)
- [x] Component 10: Command builder & sanitizer (template registry, parameter validation, injection prevention, credential redaction)
- [x] Component 11: Device executor & rollback (post-PERMIT execution, pre-change capture, automatic rollback on failure)
- [x] Component 12: Device registry (platform enum: IOS-XE, NX-OS, EOS, JUNOS; immutable driver configs)
- [x] Component 13: MCP server with tool registration (FastMCP server, 5 read tools, 6 write tools, policy intercept flow)
- [x] Component 14: Post-change validation framework (ConfigChangedValidator, InterfaceUpValidator, ReachabilityValidator)
- [x] Component 15: EAS adjuster (automatic scoring, tier weights, anti-gaming protection)
- [x] Component 16: Maintenance windows (time-based escalation overrides, device coverage)

### Phase 3: Observability, Integrations & API Expansion — COMPLETE
- [x] Component 17: Prometheus metrics (evaluation totals, latency, EAS gauge, escalation pending, execution totals)
- [x] Component 18: Correlation ID middleware (distributed tracing, structlog binding, X-Correlation-ID headers)
- [x] Component 19: NetBox integration (device inventory, TTL cache, circuit breaker)
- [x] Component 20: Extended API routes (agents, executions, inventory, metrics, reports, EAS endpoints)
- [x] Component 21: CLI interface (Typer: sna serve, sna mcp-serve, sna evaluate, sna migrate)
- [x] Component 22: Dashboard UI (React/Vite: VerdictFeed, EscalationPanel, AuditExplorer, EASMonitor, AgentManager, PolicyViewer, SummaryCards)
- [x] Component 23: Docker & deployment (multi-stage Dockerfile, docker-compose with Postgres, non-root, read-only filesystem, health checks)

### Phase 4: Context-Aware Policy & Advanced Governance — NOT STARTED
- [ ] Component 24: Context-aware policy rules (site/role/tag-based policy variations)
- [ ] Component 25: Policy versioning (audit trail of policy changes, rollback to previous versions)
- [ ] Component 26: Per-agent policy sets (different agents get different rule sets)
- [ ] Component 27: Dynamic confidence adjustment (agent history, device criticality weighting)
- [ ] Component 28: Agent reputation scoring (EAS with time-decay, peer trust signals)

### Phase 5: Advanced Validation & Network Intelligence — NOT STARTED
- [ ] Component 29: pyATS validation integration (post-change health checks, structured test cases)
- [ ] Component 30: BGP/OSPF session state validators (neighbor up, prefix count, route convergence)
- [ ] Component 31: Config diff analysis (semantic diff, compliance drift detection)
- [ ] Component 32: Batch operations (multi-device changes with dependency ordering, staged rollout)
- [ ] Component 33: Device enrichment from NetBox (role, site, criticality auto-populated into policy decisions)

### Phase 6: Enterprise Integrations & Observability — NOT STARTED
- [ ] Component 34: OpenTelemetry integration (span/trace export to Jaeger/Tempo)
- [ ] Component 35: Slack notifications
- [ ] Component 36: PagerDuty on-call routing (critical BLOCK → page, ESCALATE → notify)
- [ ] Component 37: Vault integration for device credentials (HashiCorp Vault secret engine)
- [ ] Component 38: Grafana dashboards (pre-built panels for verdict rates, EAS trends, execution latency)

### Phase 7: Scale & Multi-Tenancy — NOT STARTED
- [ ] Component 39: Multi-tenant support (org-scoped policies, isolated audit trails)
- [ ] Component 40: Kubernetes operator (CRDs for PolicyConfig, Agent, MaintenanceWindow)
- [ ] Component 41: Horizontal scaling (stateless API, shared Postgres, Redis for rate limiting)
- [ ] Component 42: Agent marketplace (pre-trained policies, rules-as-code sharing)
- [ ] Component 43: Collaborative execution (distributed multi-agent workflows with coordination)

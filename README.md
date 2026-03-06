# Structured Network Autonomy (SNA)

Governance framework for AI agents operating in enterprise networks. SNA provides policy-driven access control for autonomous network operations, intercepting every action through a tiered risk engine that returns **PERMIT**, **ESCALATE**, or **BLOCK** verdicts.

## The Problem

AI agents executing network automation need guardrails. Without governance, an autonomous agent has the same access as the engineer who deployed it — including the ability to wipe configurations, modify BGP peers, or push changes across dozens of devices simultaneously. SNA solves this by placing a Policy Engine between the agent and the network, enforcing risk-aware decision-making at every step.

## How It Works

Every MCP tool call passes through the Policy Engine before execution. The engine classifies the action, evaluates confidence and trust scores, and returns a verdict:

```
Agent -> MCP Tool Call -> Policy Engine -> Verdict -> Execute or Escalate
```

### Action Taxonomy

Actions are classified into five risk tiers:

| Tier | Risk Level | Default Verdict | Examples |
|------|-----------|----------------|----------|
| 1 | Read | PERMIT | `show` commands, `ping`, telemetry |
| 2 | Low-risk write | PERMIT + audit | Interface descriptions, logging config |
| 3 | Medium-risk write | ESCALATE | Routing, VLANs, ACLs |
| 4 | High-risk write | ESCALATE + senior | BGP, OSPF, security policy, 3+ devices |
| 5 | Critical | BLOCK | `write erase`, `reload`, factory reset |

### Earned Autonomy Score (EAS)

Every agent starts with a near-zero trust score (0.1). As the agent operates successfully, its EAS increases — granting slightly more latitude on confidence thresholds. Failed operations or policy violations decrease the score. Trust is earned, not granted.

### Escalation Workflow

When an action requires human approval:

1. The engine generates an escalation record with full context
2. The record is persisted with PENDING status
3. Notifications fire to Discord, Slack, Teams, and/or PagerDuty
4. The agent receives confirmation that approval is pending
5. An operator approves or rejects via API endpoint
6. Every decision is written to an append-only audit log

## Architecture

```
src/sna/
  policy/          Policy Engine — evaluation, taxonomy, YAML schema, context rules, versioning
    engine.py      Core evaluate(), reload_policy(), get_eas()
    models.py      Pydantic models for policy schema and evaluation
    loader.py      YAML loading with hot reload and diff logging
    taxonomy.py    Tool classification, threshold computation
    context_rules  Site/role/tag-based policy rules
    confidence.py  Dynamic confidence adjustment
    reputation.py  Agent reputation scoring
  db/              Async SQLAlchemy persistence
    models.py      AuditLog, EscalationRecord, EASHistory
    session.py     Engine and session factory with timeouts
    migrations/    Alembic migration scripts
  api/             FastAPI application
    routes/        One module per endpoint group
    auth.py        API key authentication
    schemas.py     Request/response validation
    app.py         Application factory with middleware
  devices/         Device execution layer
    driver.py      AsyncScrapli wrapper with connection pooling
    executor.py    Post-PERMIT execution with rollback
    command_builder Command templates and parameter validation
    sanitizer.py   Credential redaction, injection prevention
    registry.py    Platform configs (IOS-XE, NX-OS, EOS, JUNOS)
    inventory.py   YAML-based device inventory
  integrations/    External services
    discord.py     Webhook notifications (rich embeds)
    teams.py       Webhook notifications (Adaptive Cards)
    slack.py       Slack notifications
    pagerduty.py   On-call routing
    vault.py       HashiCorp Vault credential retrieval
    netbox.py      Device inventory with TTL cache and circuit breaker
    notifier.py    Abstract notifier interface
    mcp.py         MCP tool call interceptor
  mcp_server/      FastMCP server with read/write tool registration
  observability/   Prometheus metrics, correlation ID middleware
  validation/      Post-change validators (config diff, protocol state, compliance)
  simulator/       Scenario runner and baseline testing
  config.py        Pydantic Settings — all config via env vars
  log_config.py    Structured JSON logging (structlog)
  cli.py           Typer CLI (serve, mcp-serve, evaluate, migrate)

dashboard/         React/Vite UI (verdicts, escalations, audit, EAS, agents, policy viewer)
policies/          Runtime YAML policy files
inventory/         Device inventory files
dashboards/        Pre-built Grafana dashboard JSON
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/evaluate` | API key | Submit an action for policy evaluation |
| POST | `/escalation/{id}/decision` | API key | Approve or reject a pending escalation |
| GET | `/escalation/pending` | API key | List all pending escalations |
| GET | `/audit` | API key | Paginated audit log |
| POST | `/policy/reload` | Admin key | Hot reload policy YAML |
| GET | `/policy/versions` | API key | Policy version history |
| POST | `/policy/rollback` | Admin key | Roll back to a previous policy version |
| GET | `/agents` | API key | List registered agents |
| POST | `/agents` | Admin key | Register a new agent |
| GET | `/agents/{id}/overrides` | API key | Per-agent policy overrides |
| GET | `/eas/{agent_id}` | API key | Current EAS score and history |
| GET | `/devices` | API key | Device inventory |
| GET | `/executions` | API key | Execution history |
| POST | `/batch` | API key | Multi-device batch operations |
| GET | `/metrics` | API key | Prometheus metrics |
| GET | `/reports/summary` | API key | Verdict and execution summaries |
| GET | `/timeline` | API key | Unified activity feed |
| GET | `/health` | None/API key | Engine health (minimal unauthenticated, full with key) |

## Policy Configuration

Policy is defined in YAML and validated with Pydantic on load. Invalid policy fails loudly — the engine will not start with a malformed configuration.

```yaml
# policies/default.yaml
version: "1.0"

action_tiers:
  tier_1_read:
    description: "Show commands, telemetry, health checks"
    default_verdict: "PERMIT"
    examples:
      - "show_running_config"
      - "show_interfaces"

confidence_thresholds:
  tier_1_read: 0.1
  tier_3_medium_risk_write: 0.6
  tier_5_critical: 1.0

eas_modulation:
  enabled: true
  max_threshold_reduction: 0.1
  min_eas_for_modulation: 0.3

scope_limits:
  max_devices_per_action: 3
  escalate_above: 3

hard_rules:
  always_block:
    - "write_erase"
    - "factory_reset"
    - "delete_startup_config"
```

## Quick Start

### Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation

```bash
git clone https://github.com/E-Conners-Lab/Structured_Network_Autonomy.git
cd Structured_Network_Autonomy

# Create venv and install
uv venv
uv pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env — set SNA_API_KEY and SNA_ADMIN_API_KEY (required)
```

### Run Tests

```bash
python -m pytest tests/ -v
```

### Start the API

```bash
uvicorn sna.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

### Dashboard (optional)

The dashboard is a React/Vite app that provides a UI for monitoring verdicts, escalations, audit logs, EAS scores, and policy configuration.

```bash
cd dashboard
npm install
npm run dev      # Development server on http://localhost:5173
npm run build    # Production build to dashboard/dist/
```

The dashboard expects the API to be running on `http://localhost:8000`.

### Docker Deployment

```bash
# 1. Create secrets directory
mkdir -p secrets
echo "your-db-password" > secrets/db_password.txt
echo "your-api-key" > secrets/api_key.txt
echo "your-admin-key" > secrets/admin_key.txt

# 2. Start the stack
docker compose up -d
```

This starts a Postgres database and the SNA API in a hardened container (non-root, read-only filesystem, all capabilities dropped).

### Device Inventory

Copy the example inventory and update with your device IPs:

```bash
cp inventory/example.yaml inventory/my-lab.yaml
# Edit inventory/my-lab.yaml with your device management IPs
# Set INVENTORY_FILE_PATH=./inventory/my-lab.yaml in .env
```

Device credentials are set via environment variables (see `.env.example`).

## Security Model

- All configuration via environment variables — no secrets in code
- API key authentication on all endpoints (except minimal health check)
- Append-only audit log — no update or delete operations, ever
- All API-facing identifiers use UUID4 to prevent enumeration
- Pydantic validation on every API input
- Sanitized error responses — stack traces logged internally, never exposed
- Rate limiting on all endpoints
- YAML loaded exclusively with `safe_load()`
- Explicit timeouts on all external HTTP calls
- Webhook URLs treated as secrets — never logged
- Fails closed — if the database is unreachable, all non-read actions are BLOCK

## Infrastructure Context

SNA is built for environments running:

- **MCP server** (FastMCP/Python) for network automation tooling
- **Cisco IOS-XE** routers (C8000V) and **Cat9kv** switches
- **ContainerLab** or **EVE-NG** for network topology
- **Async Scrapli** for device connections
- **NetBox** as source of truth
- **pyATS** for validation testing
- **Docker stack**: Postgres, Grafana, InfluxDB, FreeRADIUS

## Build Status

### Phase 1: Policy Engine -- Complete
- [x] Policy YAML schema and Pydantic validation models
- [x] Database models (AuditLog, EscalationRecord, EASHistory)
- [x] Core PolicyEngine class
- [x] FastAPI application and routes
- [x] Notification integrations (Discord + Teams)
- [x] MCP integration wrapper
- [x] Integration test suite

### Phase 2: Device Execution & Operational Readiness -- Complete
- [x] Device driver layer (AsyncScrapli wrapper, connection pooling, timeout enforcement)
- [x] Command builder and sanitizer (template registry, injection prevention, credential redaction)
- [x] Device executor with rollback (pre-change capture, automatic rollback on failure)
- [x] Device registry (IOS-XE, NX-OS, EOS, JUNOS platform configs)
- [x] MCP server with tool registration (5 read tools, 6 write tools, policy intercept)
- [x] Post-change validation framework
- [x] EAS adjuster (automatic scoring, tier weights, anti-gaming)
- [x] Maintenance windows (time-based escalation overrides)

### Phase 3: Observability, Integrations & API Expansion -- Complete
- [x] Prometheus metrics
- [x] Correlation ID middleware
- [x] NetBox integration (device inventory, TTL cache, circuit breaker)
- [x] Extended API routes (agents, executions, inventory, metrics, reports, EAS, timeline)
- [x] CLI interface (Typer: serve, mcp-serve, evaluate, migrate)
- [x] Dashboard UI (React/Vite)
- [x] Docker and deployment

### Phase 4: Context-Aware Policy & Advanced Governance -- Complete
- [x] Context-aware policy rules (site/role/tag evaluation, priority resolution)
- [x] Policy versioning (immutable version history, SHA-256 hashing, rollback)
- [x] Per-agent policy overrides
- [x] Dynamic confidence adjustment (device criticality, agent history)
- [x] Agent reputation scoring

### Phase 5: Advanced Validation & Network Intelligence -- Planned
- [ ] pyATS validation integration
- [ ] BGP/OSPF session state validators
- [ ] Config diff analysis (semantic diff, compliance drift)
- [ ] Batch operations (multi-device with dependency ordering)
- [ ] Device enrichment from NetBox

### Phase 6: Enterprise Integrations & Observability -- Planned
- [ ] OpenTelemetry integration
- [ ] Slack notifications
- [ ] PagerDuty on-call routing
- [ ] Vault integration for device credentials
- [ ] Grafana dashboards

### Phase 7: Scale & Multi-Tenancy -- Planned
- [ ] Multi-tenant support
- [ ] Kubernetes operator
- [ ] Horizontal scaling
- [ ] Agent marketplace
- [ ] Collaborative execution

## License

MIT License. See [LICENSE](LICENSE) for details.

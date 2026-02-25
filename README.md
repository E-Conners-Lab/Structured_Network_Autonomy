# Structured Network Autonomy (SNA)

Governance framework for AI agents operating in enterprise networks. SNA provides policy-driven access control for autonomous network operations, intercepting every action through a tiered risk engine that returns **PERMIT**, **ESCALATE**, or **BLOCK** verdicts.

## The Problem

AI agents executing network automation need guardrails. Without governance, an autonomous agent has the same access as the engineer who deployed it — including the ability to wipe configurations, modify BGP peers, or push changes across dozens of devices simultaneously. SNA solves this by placing a Policy Engine between the agent and the network, enforcing risk-aware decision-making at every step.

## How It Works

Every MCP tool call passes through the Policy Engine before execution. The engine classifies the action, evaluates confidence and trust scores, and returns a verdict:

```
Agent → MCP Tool Call → Policy Engine → Verdict → Execute or Escalate
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
3. Notifications fire to Discord and/or Microsoft Teams
4. The agent receives confirmation that approval is pending
5. An operator approves or rejects via API endpoint
6. Every decision is written to an append-only audit log

## Architecture

```
src/sna/
├── policy/          Policy Engine — evaluation, taxonomy, YAML schema
│   ├── engine.py    Core evaluate(), reload_policy(), get_eas()
│   ├── models.py    Pydantic models for policy schema and evaluation
│   ├── loader.py    YAML loading with hot reload and diff logging
│   └── taxonomy.py  Tool classification, threshold computation
├── db/              Async SQLAlchemy persistence
│   ├── models.py    AuditLog, EscalationRecord, EASHistory
│   └── session.py   Engine and session factory with timeouts
├── api/             FastAPI application
│   ├── routes/      One module per endpoint group
│   ├── auth.py      API key authentication
│   ├── schemas.py   Request/response validation
│   └── app.py       Application factory with middleware
├── integrations/    External services
│   ├── discord.py   Webhook notifications (rich embeds)
│   ├── teams.py     Webhook notifications (Adaptive Cards)
│   ├── notifier.py  Abstract notifier interface
│   └── mcp.py       MCP tool call interceptor
├── config.py        Pydantic Settings — all config via env vars
└── log_config.py    Structured JSON logging (structlog)
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/evaluate` | API key | Submit an action for policy evaluation |
| POST | `/escalation/{id}/decision` | API key | Approve or reject a pending escalation |
| GET | `/escalation/pending` | API key | List all pending escalations |
| GET | `/audit` | API key | Paginated audit log |
| POST | `/policy/reload` | Admin key | Hot reload policy YAML |
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
uvicorn sna.api.app:app --host 127.0.0.1 --port 8000
```

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
- **ContainerLab** for network topology
- **Async Scrapli** for device connections
- **NetBox** as source of truth
- **pyATS** for validation testing
- **Docker stack**: InfluxDB, Grafana, FreeRADIUS

## Build Status

Phase 1: Policy Engine

- [x] Project scaffolding and directory structure
- [x] Policy YAML schema and Pydantic validation models
- [x] Database models (AuditLog, EscalationRecord, EASHistory)
- [ ] Core PolicyEngine class
- [ ] FastAPI application and routes
- [ ] Notification integrations (Discord + Teams)
- [ ] MCP integration wrapper
- [ ] Integration test suite

## License

Proprietary. All rights reserved.

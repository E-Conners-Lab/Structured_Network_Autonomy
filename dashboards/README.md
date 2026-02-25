# SNA Grafana Dashboards

Pre-built Grafana dashboards for monitoring Structured Network Autonomy operations.

## Dashboards

- **sna-overview.json** — High-level overview: verdict distribution, EAS score, execution success rate, latency, escalations, validation results, notification delivery
- **sna-devices.json** — Device-focused: executions by device, execution latency by tool, validation failures

## Setup

### 1. Configure Prometheus Scrape Target

Add the SNA metrics endpoint to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'sna'
    metrics_path: '/metrics'
    scheme: 'http'
    authorization:
      credentials: '<your-sna-api-key>'
    static_configs:
      - targets: ['localhost:8000']
```

### 2. Add Prometheus Data Source in Grafana

1. Go to **Configuration > Data Sources**
2. Add a **Prometheus** data source
3. Set the URL to your Prometheus server (e.g., `http://localhost:9090`)

### 3. Import Dashboards

1. Go to **Dashboards > Import**
2. Upload the JSON file or paste its contents
3. Select the Prometheus data source
4. Click **Import**

## Available Metrics

All metrics are exposed at `GET /metrics` (requires API key authentication):

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sna_evaluation_total` | Counter | verdict, tier | Total policy evaluations |
| `sna_evaluation_latency_seconds` | Histogram | — | Policy evaluation latency |
| `sna_eas_current` | Gauge | — | Current Earned Autonomy Score |
| `sna_escalation_pending_count` | Gauge | — | Pending escalations |
| `sna_execution_total` | Counter | success | Total device executions |
| `sna_execution_latency_seconds` | Histogram | — | Device execution latency |
| `sna_notification_total` | Counter | channel | Notifications sent |
| `sna_validation_total` | Counter | status | Post-change validations |

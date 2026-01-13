# Cerebro Quick Reference

## CLI Commands

```bash
cerebro serve                       # Start API server
cerebro sync                        # Sync all sources
cerebro sync --source aws           # Sync specific source
cerebro policy list                 # List loaded policies
cerebro policy validate             # Validate policy files
cerebro policy test <id> <asset>    # Test policy
cerebro query "<sql>"               # Execute SQL
cerebro query --format json "<sql>" # Output as JSON
cerebro bootstrap                   # Initialize database
```

## API Endpoints Cheat Sheet

### Health
```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl http://localhost:8080/metrics
```

### Query
```bash
# List tables
curl http://localhost:8080/api/v1/tables

# Execute query
curl -X POST http://localhost:8080/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM aws_s3_buckets LIMIT 10"}'
```

### Assets
```bash
# List assets from table
curl "http://localhost:8080/api/v1/assets/aws_s3_buckets?limit=100"

# Get specific asset
curl http://localhost:8080/api/v1/assets/aws_s3_buckets/{id}
```

### Policies
```bash
# List policies
curl http://localhost:8080/api/v1/policies

# Get policy
curl http://localhost:8080/api/v1/policies/{id}

# Evaluate
curl -X POST http://localhost:8080/api/v1/policies/evaluate \
  -H "Content-Type: application/json" \
  -d '{"resource": {...}}'
```

### Findings
```bash
# List findings
curl "http://localhost:8080/api/v1/findings?severity=critical&status=open"

# Stats
curl http://localhost:8080/api/v1/findings/stats

# Scan
curl -X POST http://localhost:8080/api/v1/findings/scan \
  -H "Content-Type: application/json" \
  -d '{"table": "aws_s3_buckets", "limit": 100}'

# Resolve
curl -X POST http://localhost:8080/api/v1/findings/{id}/resolve
```

### Compliance
```bash
# List frameworks
curl http://localhost:8080/api/v1/compliance/frameworks

# Get framework
curl http://localhost:8080/api/v1/compliance/frameworks/soc2

# Generate report
curl http://localhost:8080/api/v1/compliance/frameworks/soc2/report

# Pre-audit check
curl http://localhost:8080/api/v1/compliance/frameworks/soc2/pre-audit
```

### AI Agents
```bash
# List agents
curl http://localhost:8080/api/v1/agents

# Create session
curl -X POST http://localhost:8080/api/v1/agents/sessions \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "security-analyst", "user_id": "user@example.com"}'

# Send message
curl -X POST http://localhost:8080/api/v1/agents/sessions/{id}/messages \
  -H "Content-Type: application/json" \
  -d '{"content": "Analyze the S3 findings"}'

# Get messages
curl http://localhost:8080/api/v1/agents/sessions/{id}/messages
```

### Identity
```bash
# Stale access
curl http://localhost:8080/api/v1/identity/stale-access

# Identity report
curl http://localhost:8080/api/v1/identity/report

# Create review
curl -X POST http://localhost:8080/api/v1/identity/reviews \
  -H "Content-Type: application/json" \
  -d '{"name": "Q1 Review", "type": "user_access"}'

# Record decision
curl -X POST http://localhost:8080/api/v1/identity/reviews/{id}/items/{itemId}/decide \
  -H "Content-Type: application/json" \
  -d '{"action": "approve", "reviewer": "manager@example.com"}'
```

### Webhooks
```bash
# List webhooks
curl http://localhost:8080/api/v1/webhooks

# Create webhook
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/hook", "events": ["finding.created"]}'

# Delete webhook
curl -X DELETE http://localhost:8080/api/v1/webhooks/{id}
```

### Scheduler
```bash
# Status
curl http://localhost:8080/api/v1/scheduler/status

# List jobs
curl http://localhost:8080/api/v1/scheduler/jobs

# Run job manually
curl -X POST http://localhost:8080/api/v1/scheduler/jobs/policy-scan/run
```

### Admin
```bash
# Health dashboard
curl http://localhost:8080/api/v1/admin/health

# Sync status
curl http://localhost:8080/api/v1/admin/sync/status
```

## Environment Variables

```bash
# Required
export SNOWFLAKE_CONNECTION_STRING="user:pass@account/db/schema"

# Optional
export API_PORT=8080
export LOG_LEVEL=info
export POLICIES_PATH=policies
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export JIRA_BASE_URL=https://company.atlassian.net
export JIRA_API_TOKEN=...
export LINEAR_API_KEY=...
export SLACK_WEBHOOK_URL=https://hooks.slack.com/...
export PAGERDUTY_ROUTING_KEY=...
export SCAN_INTERVAL=1h
export SCAN_TABLES=aws_s3_buckets,aws_iam_users
export RATE_LIMIT_ENABLED=true
export RATE_LIMIT_REQUESTS=1000
export RATE_LIMIT_WINDOW=1h
```

## Policy Format

```json
{
    "id": "unique-id",
    "name": "Human Name",
    "description": "What this checks",
    "effect": "forbid",
    "conditions": ["field != value"],
    "severity": "critical",
    "tags": ["compliance", "category"]
}
```

### Severity Levels
- `critical` - Immediate risk
- `high` - Significant risk
- `medium` - Best practice
- `low` - Improvement

### Condition Syntax
```
field == value    # Equality
field != value    # Inequality (violation)
```

## Common Tables

### AWS
- `aws_s3_buckets`
- `aws_iam_users`
- `aws_iam_roles`
- `aws_iam_credential_reports`
- `aws_ec2_instances`
- `aws_ec2_security_groups`
- `aws_rds_instances`
- `aws_lambda_functions`

### GCP
- `gcp_storage_buckets`
- `gcp_compute_instances`
- `gcp_iam_service_accounts`

### Azure
- `azure_storage_accounts`
- `azure_compute_virtual_machines`

### Kubernetes
- `k8s_core_pods`
- `k8s_core_services`
- `k8s_rbac_roles`

## Webhook Events

| Event | Description |
|-------|-------------|
| `finding.created` | New finding detected |
| `finding.resolved` | Finding resolved |
| `finding.suppressed` | Finding suppressed |
| `scan.completed` | Scan job finished |
| `review.started` | Access review started |
| `review.completed` | Access review completed |
| `attack_path.found` | New attack path discovered |
| `ticket.created` | Ticket created |

## Compliance Frameworks

| ID | Name |
|----|------|
| `soc2` | SOC 2 Type II |
| `cis-aws` | CIS AWS Foundations |
| `cis-gcp` | CIS GCP Foundations |
| `pci-dss` | PCI DSS v4.0 |
| `hipaa` | HIPAA Security Rule |
| `nist-800-53` | NIST 800-53 Rev 5 |

## Review Decision Actions

| Action | Description |
|--------|-------------|
| `approve` | Approve access |
| `revoke` | Remove access |
| `modify` | Change access level |
| `escalate` | Escalate for review |
| `defer` | Defer decision |

## Make Targets

```bash
make dev            # Run with hot reload
make test           # Run tests
make build          # Build binary
make docker-build   # Build Docker image
make lint           # Run linters
make policy-list    # List policies
make policy-validate # Validate policies
```

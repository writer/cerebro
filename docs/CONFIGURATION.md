# Cerebro Configuration Guide

## Overview

Cerebro is configured entirely through environment variables, following the 12-factor app methodology. This guide documents all configuration options, their defaults, and usage patterns.

## Environment Variables

For the complete, source-of-truth env var list generated directly from code, see [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md).

### Core Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_PORT` | HTTP server port | `8080` | No |
| `LOG_LEVEL` | Logging verbosity | `info` | No |

**Log Levels:**
- `debug` - Verbose debugging information
- `info` - General operational information
- `warn` - Warning conditions
- `error` - Error conditions only

### Snowflake Connection

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SNOWFLAKE_ACCOUNT` | Snowflake account identifier (for example `myaccount.us-east-1`) | - | Yes* |
| `SNOWFLAKE_USER` | Snowflake service user | - | Yes* |
| `SNOWFLAKE_PRIVATE_KEY` | PEM-encoded private key (RSA) | - | Yes* |
| `SNOWFLAKE_ROLE` | Snowflake role | - | No |
| `SNOWFLAKE_DATABASE` | Database name | `CEREBRO` | No |
| `SNOWFLAKE_SCHEMA` | Schema name | `CEREBRO` | No |
| `SNOWFLAKE_WAREHOUSE` | Compute warehouse | `COMPUTE_WH` | No |

*Required for full functionality. Cerebro will start without Snowflake but with degraded capabilities.

**Key-Pair Authentication Notes:**
```
- `SNOWFLAKE_PRIVATE_KEY` supports escaped newlines (`\n`) and multiline PEM values.
- Use a dedicated least-privilege role/user for Cerebro.
```

**Example:**
```bash
export SNOWFLAKE_ACCOUNT="myaccount.us-east-1"
export SNOWFLAKE_USER="CEREBRO_APP"
export SNOWFLAKE_PRIVATE_KEY="<private-key-pem-with-escaped-newlines>"
export SNOWFLAKE_ROLE="CEREBRO_ROLE"
export SNOWFLAKE_DATABASE="CEREBRO"
export SNOWFLAKE_SCHEMA="CEREBRO"
export SNOWFLAKE_WAREHOUSE="COMPUTE_WH"
```

### Policy Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `POLICIES_PATH` | Path to policy files | `policies` | No |
| `CEDAR_POLICIES_PATH` | Alias for POLICIES_PATH | `policies` | No |
| `QUERY_POLICY_ROW_LIMIT` | Max rows processed per query policy scan | `1000` | No |

### LLM Providers (AI Agents)

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key | - | No |
| `OPENAI_API_KEY` | OpenAI API key | - | No |

**Notes:**
- At least one key required for AI agent functionality
- Anthropic creates "security-analyst" agent
- OpenAI creates "incident-responder" agent

### Ticketing Integrations

#### Jira

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `JIRA_BASE_URL` | Jira instance URL | - | No |
| `JIRA_EMAIL` | Jira user email | - | No |
| `JIRA_API_TOKEN` | Jira API token | - | No |
| `JIRA_PROJECT` | Default project key | `SEC` | No |
| `JIRA_CLOSE_TRANSITIONS` | Comma-separated Jira transition names attempted when closing issues | `Done,Closed,Resolve Issue` | No |

**Example:**
```bash
export JIRA_BASE_URL="https://mycompany.atlassian.net"
export JIRA_EMAIL="security@company.com"
export JIRA_API_TOKEN="ATATT3xFfGF..."
export JIRA_PROJECT="SECURITY"
export JIRA_CLOSE_TRANSITIONS="Done,Closed,Resolve Issue"
```

#### Linear

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LINEAR_API_KEY` | Linear API key | - | No |
| `LINEAR_TEAM_ID` | Linear team ID | - | No |

### Custom Data Providers

#### CrowdStrike

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `CROWDSTRIKE_CLIENT_ID` | CrowdStrike OAuth client ID | - | No |
| `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike OAuth secret | - | No |

#### Okta

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `OKTA_DOMAIN` | Okta domain (e.g., `mycompany.okta.com`) | - | No |
| `OKTA_API_TOKEN` | Okta API token | - | No |

### Notifications

#### Slack

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL | - | No |

**Example:**
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/XXXX"
```

#### PagerDuty

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PAGERDUTY_ROUTING_KEY` | PagerDuty Events API routing key | - | No |

### Scheduler

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SCAN_INTERVAL` | Policy scan interval | - | No |
| `SCAN_TABLES` | Tables to scan (comma-separated) | See below | No |

**Default Scan Tables:**
- `aws_s3_buckets`
- `aws_ec2_instances`
- `aws_iam_users`

**Interval Format:**
- `30m` - 30 minutes
- `1h` - 1 hour
- `24h` - 24 hours

**Example:**
```bash
export SCAN_INTERVAL="1h"
export SCAN_TABLES="aws_s3_buckets,aws_iam_users,gcp_storage_buckets"
```

### Rate Limiting

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `false` | No |
| `RATE_LIMIT_REQUESTS` | Requests per window | `1000` | No |
| `RATE_LIMIT_WINDOW` | Time window | `1h` | No |

**Window Format:** Go duration string (e.g., `1h`, `30m`, `24h`)

---

## Configuration Examples

### Minimal Production Configuration

```bash
# Required
export SNOWFLAKE_ACCOUNT="myaccount.us-east-1"
export SNOWFLAKE_USER="CEREBRO_APP"
export SNOWFLAKE_PRIVATE_KEY="<pem-private-key>"

# Recommended
export API_PORT="8080"
export LOG_LEVEL="info"
export SCAN_INTERVAL="1h"
```

### Full Production Configuration

```bash
# Core
export API_PORT="8080"
export LOG_LEVEL="info"

# Snowflake
export SNOWFLAKE_ACCOUNT="myaccount.us-east-1"
export SNOWFLAKE_USER="CEREBRO_APP"
export SNOWFLAKE_PRIVATE_KEY="$SNOWFLAKE_PRIVATE_KEY"
export SNOWFLAKE_ROLE="CEREBRO_ROLE"
export SNOWFLAKE_DATABASE="CEREBRO"
export SNOWFLAKE_SCHEMA="CEREBRO"
export SNOWFLAKE_WAREHOUSE="COMPUTE_WH"

# Policies
export POLICIES_PATH="/app/policies"
export QUERY_POLICY_ROW_LIMIT="1000"

# AI Agents
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."

# Ticketing
export JIRA_BASE_URL="https://company.atlassian.net"
export JIRA_EMAIL="security-bot@company.com"
export JIRA_API_TOKEN="$JIRA_TOKEN"
export JIRA_PROJECT="SEC"

# Notifications
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export PAGERDUTY_ROUTING_KEY="$PD_KEY"

# Scheduler
export SCAN_INTERVAL="1h"
export SCAN_TABLES="aws_s3_buckets,aws_iam_users,aws_ec2_instances,gcp_storage_buckets"

# Rate Limiting
export RATE_LIMIT_ENABLED="true"
export RATE_LIMIT_REQUESTS="1000"
export RATE_LIMIT_WINDOW="1h"
```

### Development Configuration

```bash
export LOG_LEVEL="debug"
export API_PORT="8080"
export POLICIES_PATH="./policies"
export QUERY_POLICY_ROW_LIMIT="1000"

# Optional: Snowflake key-pair (leave unset to run in local SQLite mode)
# export SNOWFLAKE_ACCOUNT="myaccount.us-east-1"
# export SNOWFLAKE_USER="CEREBRO_APP"
# export SNOWFLAKE_PRIVATE_KEY="<pem-private-key>"

# Optional: Enable AI for testing
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Docker Configuration

```yaml
# docker-compose.yml
version: '3.8'
services:
  cerebro:
    build: .
    ports:
      - "8080:8080"
    environment:
      - API_PORT=8080
      - LOG_LEVEL=info
      - SNOWFLAKE_ACCOUNT=${SNOWFLAKE_ACCOUNT}
      - SNOWFLAKE_USER=${SNOWFLAKE_USER}
      - SNOWFLAKE_PRIVATE_KEY=${SNOWFLAKE_PRIVATE_KEY}
      - SNOWFLAKE_ROLE=${SNOWFLAKE_ROLE}
      - SNOWFLAKE_DATABASE=${SNOWFLAKE_DATABASE:-CEREBRO}
      - SNOWFLAKE_SCHEMA=${SNOWFLAKE_SCHEMA:-CEREBRO}
      - SNOWFLAKE_WAREHOUSE=${SNOWFLAKE_WAREHOUSE:-COMPUTE_WH}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - SCAN_INTERVAL=1h
    volumes:
      - ./policies:/app/policies:ro
```

### Kubernetes Configuration

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cerebro-config
data:
  API_PORT: "8080"
  LOG_LEVEL: "info"
  SNOWFLAKE_DATABASE: "CEREBRO"
  SNOWFLAKE_SCHEMA: "CEREBRO"
  POLICIES_PATH: "/app/policies"
  QUERY_POLICY_ROW_LIMIT: "1000"
  SCAN_INTERVAL: "1h"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_REQUESTS: "1000"
  RATE_LIMIT_WINDOW: "1h"

---
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: cerebro-secrets
type: Opaque
stringData:
  SNOWFLAKE_ACCOUNT: "myaccount.us-east-1"
  SNOWFLAKE_USER: "CEREBRO_APP"
  SNOWFLAKE_PRIVATE_KEY: "<private-key-pem-with-escaped-newlines>"
  SNOWFLAKE_ROLE: "CEREBRO_ROLE"
  ANTHROPIC_API_KEY: "sk-ant-..."
  JIRA_API_TOKEN: "..."
  SLACK_WEBHOOK_URL: "https://hooks.slack.com/..."
  PAGERDUTY_ROUTING_KEY: "..."

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: cerebro
          image: cerebro:latest
          envFrom:
            - configMapRef:
                name: cerebro-config
            - secretRef:
                name: cerebro-secrets
          volumeMounts:
            - name: policies
              mountPath: /app/policies
              readOnly: true
      volumes:
        - name: policies
          configMap:
            name: cerebro-policies
```

---

## Policy Configuration

### Policy Directory Structure

```
policies/
├── aws/
│   ├── s3-public-access.json
│   ├── s3-encryption.json
│   ├── iam-mfa.json
│   └── ec2-public-ip.json
├── gcp/
│   ├── storage-public.json
│   └── compute-external-ip.json
├── azure/
│   ├── storage-https.json
│   └── vm-managed-identity.json
└── kubernetes/
    ├── privileged-containers.json
    └── host-network.json
```

### Policy File Format

```json
{
    "id": "aws-s3-bucket-no-public-access",
    "name": "S3 Bucket Public Access",
    "description": "S3 buckets should not allow public access",
    "effect": "forbid",
    "conditions": [
        "block_public_acls != true"
    ],
    "severity": "critical",
    "tags": ["cis-aws-2.1.5", "security", "s3", "data-protection"]
}
```

### Policy Fields

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `id` | string | Unique policy identifier | Yes |
| `name` | string | Human-readable name | Yes |
| `description` | string | Policy description | Yes |
| `effect` | string | `permit` or `forbid` | Yes |
| `conditions` | array | Condition expressions | Yes |
| `severity` | string | `critical`, `high`, `medium`, `low` | Yes |
| `tags` | array | Classification tags | No |
| `principal` | string | Principal pattern | No |
| `action` | string | Action pattern | No |
| `resource` | string | Resource pattern | No |

### Condition Syntax

**Equality:**
```json
"conditions": ["field == value"]
```

**Inequality (violation):**
```json
"conditions": ["field != expected_value"]
```

**Examples:**
```json
// Bucket versioning disabled
"conditions": ["versioning_status != Enabled"]

// Public access not blocked
"conditions": ["block_public_acls != true"]

// Encryption not enabled
"conditions": ["encryption_type == null"]

// MFA not enabled
"conditions": ["mfa_active != true"]
```

---

## Native Sync Configuration

Cerebro syncs data with native scanners configured via environment variables and CLI flags.

Examples:

```bash
# AWS (default)
cerebro sync --region us-east-1

# GCP
cerebro sync --gcp --gcp-project my-project

# Azure
cerebro sync --azure --azure-subscription <subscription-id>
```

---

## Feature Flags

Cerebro uses presence-based feature flags. Features are enabled when their configuration is present:

| Feature | Enabled When |
|---------|--------------|
| Snowflake queries | `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, and `SNOWFLAKE_PRIVATE_KEY` are set |
| AI Agents (Claude) | `ANTHROPIC_API_KEY` is set |
| AI Agents (GPT) | `OPENAI_API_KEY` is set |
| Jira ticketing | `JIRA_BASE_URL` and `JIRA_API_TOKEN` are set |
| Linear ticketing | `LINEAR_API_KEY` is set |
| CrowdStrike provider | `CROWDSTRIKE_CLIENT_ID` is set |
| Okta provider | `OKTA_DOMAIN` is set |
| Slack notifications | `SLACK_WEBHOOK_URL` is set |
| PagerDuty alerts | `PAGERDUTY_ROUTING_KEY` is set |
| Scheduled scanning | `SCAN_INTERVAL` is set |
| Rate limiting | `RATE_LIMIT_ENABLED=true` |

---

## Security Best Practices

### Secrets Management

1. **Never commit secrets to version control**
2. **Use a secrets manager** (AWS Secrets Manager, HashiCorp Vault, etc.)
3. **Rotate credentials regularly**
4. **Use least-privilege service accounts**

### Snowflake Security

```sql
-- Create dedicated role
CREATE ROLE CEREBRO_ROLE;

-- Grant minimal permissions
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE CEREBRO_ROLE;
GRANT USAGE ON DATABASE CEREBRO TO ROLE CEREBRO_ROLE;
GRANT USAGE ON SCHEMA CEREBRO.CEREBRO TO ROLE CEREBRO_ROLE;
GRANT SELECT ON ALL TABLES IN SCHEMA CEREBRO.CEREBRO TO ROLE CEREBRO_ROLE;

-- Create service user
CREATE USER cerebro_svc PASSWORD = '...' DEFAULT_ROLE = CEREBRO_ROLE;
GRANT ROLE CEREBRO_ROLE TO USER cerebro_svc;
```

### Network Security

1. **Deploy behind a reverse proxy** with TLS termination
2. **Enable rate limiting** for public endpoints
3. **Use VPC peering** for Snowflake connection
4. **Restrict egress** to only required destinations

### API Security

1. **Add authentication middleware** (OAuth2, API keys, etc.)
2. **Implement RBAC** for sensitive endpoints
3. **Audit all administrative actions**
4. **Monitor for anomalous access patterns**

# Cerebro

**Security Data Platform for Cloud and SaaS Posture Management**

Cerebro is a comprehensive security platform that combines cloud asset discovery, policy evaluation, compliance reporting, AI-powered investigation, and automated remediation workflows.

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Features

- **Cloud Asset Discovery** - Ingest configurations from AWS, GCP, Azure, and Kubernetes via native scanners
- **Policy Engine** - Cedar-style policies for security evaluation with custom condition support
- **Parallel Scanning** - High-performance scanning with configurable worker pools
- **Compliance Frameworks** - Pre-built mappings for SOC 2, CIS, PCI DSS, HIPAA, NIST 800-53
- **AI Agents** - LLM-powered security investigation with Anthropic Claude and OpenAI GPT
- **Deep Research Agent** - Code-to-cloud security analysis bridging source code and live cloud inspection
- **Distributed Job Queue** - SQS + DynamoDB based job system for scalable distributed processing
- **Identity Governance** - Access reviews, stale access detection, and risk scoring
- **Attack Path Analysis** - Graph-based visualization of potential attack paths
- **Integrations** - Jira, Linear, Slack, PagerDuty, and custom webhooks
- **Scheduled Operations** - Automated scanning with configurable intervals

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CEREBRO PLATFORM                                │
│                                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐  │
│  │   CLI    │   │ REST API │   │ Webhooks │   │Scheduler │   │  Agents  │  │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘  │
│       └──────────────┴──────────────┴──────────────┴──────────────┘        │
│                                     │                                       │
│                       ┌─────────────▼─────────────┐                        │
│                       │    Application Container   │                        │
│                       │  Policy│Scanner│Findings  │                        │
│                       └─────────────┬─────────────┘                        │
│                                     │                                       │
└─────────────────────────────────────┼───────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
  ┌───────────┐              ┌───────────────┐              ┌───────────┐
  │ Snowflake │◀─────────────│  Native Sync │              │ External  │
  │ (Storage) │              │ (Ingestion)  │              │   APIs    │
  └───────────┘              └──────────────┘              └───────────┘
        │                           │                             │
  AWS/GCP/Azure              Cloud Providers             Jira/Slack/PD
  Kubernetes                  SaaS Apps                  Anthropic/OpenAI
```

---

## Quick Start

### Prerequisites

- Go 1.23+
- Snowflake account

### Installation

```bash
# Clone repository
git clone https://github.com/writer/cerebro.git
cd cerebro

# Install dependencies
make setup

# Build
make build
```

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Required: Snowflake connection
export SNOWFLAKE_CONNECTION_STRING="user:pass@account/CEREBRO/CEREBRO"

# Optional: AI agents
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: Notifications
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Optional: Ticketing
export JIRA_BASE_URL="https://company.atlassian.net"
export JIRA_API_TOKEN="..."
```

### Local mode (no Snowflake)

For local development, you can run Cerebro without Snowflake credentials:

```bash
unset SNOWFLAKE_PRIVATE_KEY SNOWFLAKE_ACCOUNT SNOWFLAKE_USER
export CEREBRO_DB_PATH=.cerebro/cerebro.db
make serve
```

In local mode, findings are persisted to SQLite. Snowflake-backed capabilities (for example direct data-lake query endpoints and security graph population) are reduced or unavailable.

### Running

```bash
# Start API server
./bin/cerebro serve

# Or with make
make serve

# Development mode
make dev
```

---

## CLI Commands

```bash
# Start API server
cerebro serve

# Start distributed job worker
cerebro worker

# Run code-to-cloud security analysis
cerebro agent run --repo-url https://github.com/org/repo
cerebro agent run --resource arn:aws:s3:::my-bucket --aws-region us-east-1

# Run distributed analysis (enqueue jobs to SQS)
cerebro agent run --repo-url https://github.com/org/repo --distributed --wait

# Sync cloud data via native scanners
cerebro sync
cerebro sync --gcp --gcp-project my-project
cerebro sync --azure

# Policy management
cerebro policy list
cerebro policy validate
cerebro policy test <policy-id> <asset.json>

# Query Snowflake
cerebro query "SELECT * FROM aws_s3_buckets LIMIT 10"
cerebro query --format json "SELECT * FROM aws_iam_users"

# Bootstrap database
cerebro bootstrap
```

---

## API Overview

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /ready` | Readiness with dependency status |
| `GET /metrics` | Prometheus metrics |
| `GET /api/v1/tables` | List Snowflake tables |
| `POST /api/v1/query` | Execute SQL query |
| `GET /api/v1/policies` | List loaded policies |
| `POST /api/v1/policies/evaluate` | Evaluate policy |
| `GET /api/v1/findings` | List findings |
| `POST /api/v1/findings/scan` | Trigger policy scan |
| `GET /api/v1/compliance/frameworks` | List frameworks |
| `GET /api/v1/compliance/frameworks/{id}/pre-audit` | Pre-audit check |
| `POST /api/v1/agents/sessions` | Create agent session |
| `POST /api/v1/agents/sessions/{id}/messages` | Send message to agent |
| `GET /api/v1/identity/stale-access` | Detect stale access |
| `POST /api/v1/attack-paths/analyze` | Analyze attack paths |
| `POST /api/v1/webhooks` | Register webhook |

See [API Reference](docs/API_REFERENCE.md) for complete documentation.

---

## Policies

Policies are JSON files defining security checks:

```json
{
    "id": "aws-s3-bucket-no-public-access",
    "name": "S3 Bucket Public Access",
    "description": "S3 buckets should not allow public access",
    "effect": "forbid",
    "conditions": ["block_public_acls != true"],
    "severity": "critical",
    "tags": ["cis-aws-2.1.5", "security", "s3"]
}
```

### Policy Directory

```
policies/
├── aws/           # AWS policies (S3, IAM, EC2, RDS)
├── gcp/           # GCP policies (Storage, Compute, IAM)
├── azure/         # Azure policies (Storage, VM)
└── kubernetes/    # Kubernetes policies (Pods, RBAC)
```

See [Policy Documentation](docs/POLICIES.md) for writing custom policies.

---

## Compliance

### Supported Frameworks

- **SOC 2 Type II** - Trust Services Criteria
- **CIS AWS Foundations** - v1.4.0 Benchmark
- **CIS GCP Foundations** - v1.3.0 Benchmark
- **PCI DSS** - v4.0
- **HIPAA** - Security Rule
- **NIST 800-53** - Rev 5

### Pre-Audit Check

```bash
curl http://localhost:8080/api/v1/compliance/frameworks/soc2/pre-audit
```

Returns estimated audit outcome, failing controls, and remediation recommendations.

---

## AI Agents

Cerebro includes AI-powered security investigation agents:

### Available Agents

| Agent | Provider | Purpose |
|-------|----------|---------|
| `security-analyst` | Anthropic Claude | Security finding investigation |
| `incident-responder` | OpenAI GPT | Incident triage and response |

### Usage

```bash
# Create session
curl -X POST http://localhost:8080/api/v1/agents/sessions \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "security-analyst", "user_id": "analyst@company.com"}'

# Send message
curl -X POST http://localhost:8080/api/v1/agents/sessions/{id}/messages \
  -H "Content-Type: application/json" \
  -d '{"content": "Investigate the public S3 bucket findings"}'
```

### Agent Tools

- `query_snowflake` - Execute SQL queries
- `list_findings` - List security findings
- `get_asset` - Get asset details
- `evaluate_policy` - Test policy against asset
- `search_logs` - Search audit logs

---

## Identity & Access Review

### Stale Access Detection

```bash
curl http://localhost:8080/api/v1/identity/stale-access
```

Detects:
- Inactive users (90+ days)
- Unused access keys
- Stale service accounts

### Access Reviews

```bash
# Create review
curl -X POST http://localhost:8080/api/v1/identity/reviews \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 2024 Access Review",
    "type": "user_access",
    "scope": {"providers": ["aws", "gcp"]}
  }'
```

---

## Webhooks

Register webhooks for real-time event notifications:

```bash
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/webhook",
    "events": ["finding.created", "scan.completed"],
    "secret": "webhook-secret"
  }'
```

### Event Types

- `finding.created` / `finding.resolved` / `finding.suppressed`
- `scan.completed`
- `review.started` / `review.completed`
- `attack_path.found`
- `ticket.created`

---

## Distributed Job System

Cerebro includes a distributed job queue for scalable security analysis across large repositories and cloud environments.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DISTRIBUTED JOB SYSTEM                               │
│                                                                              │
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────┐          │
│  │  API/CLI     │───────▶│    SQS       │◀───────│   Workers    │          │
│  │ (Orchestrator)│       │   Queue      │        │  (N instances)│          │
│  └──────────────┘        └──────────────┘        └──────┬───────┘          │
│         │                       │                        │                   │
│         │                       ▼                        │                   │
│         │               ┌──────────────┐                │                   │
│         └──────────────▶│  DynamoDB    │◀───────────────┘                   │
│                         │  Job Store   │                                     │
│                         └──────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

- **Job Manager**: Enqueues inspection jobs and tracks batch completion
- **SQS Queue**: Distributes work with visibility timeout and dead-letter queue
- **DynamoDB Store**: Persists job state with lease-based claiming for exactly-once execution
- **Workers**: Poll SQS, claim jobs, execute inspections, update results

### Usage

```bash
# Set up infrastructure (via Pulumi)
cd infra && pulumi up --stack prod

# Run orchestrator to enqueue jobs
cerebro agent run --repo-url https://github.com/org/repo --distributed

# Run workers (scale horizontally)
cerebro worker --concurrency 4

# Or wait for completion
cerebro agent run --repo-url https://github.com/org/repo --distributed --wait
```

### Infrastructure (Pulumi)

The distributed job infrastructure is managed via Pulumi in `infra/`:

- SQS queue with dead-letter queue for failed jobs
- DynamoDB table with GSI for group/status queries
- Worker ECS service with auto-scaling based on queue depth
- CloudWatch alarms for DLQ messages and queue backlog

---

## Development

```bash
# Run tests
make test

# Run with coverage
go test -v -cover ./...

# Lint
make lint

# Build Docker image
make docker-build
```

See [Development Guide](docs/DEVELOPMENT.md) for detailed instructions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | System architecture and design |
| [API Reference](docs/API_REFERENCE.md) | Complete API documentation |
| [Packages](docs/PACKAGES.md) | Internal package documentation |
| [Configuration](docs/CONFIGURATION.md) | Environment variables and setup |
| [Policies](docs/POLICIES.md) | Policy authoring guide |
| [Development](docs/DEVELOPMENT.md) | Development guide |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_PORT` | Server port | `8080` |
| `LOG_LEVEL` | Log verbosity | `info` |
| `SNOWFLAKE_CONNECTION_STRING` | Snowflake DSN | - |
| `POLICIES_PATH` | Policy directory | `policies` |
| `ANTHROPIC_API_KEY` | Claude API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `JIRA_BASE_URL` | Jira instance | - |
| `SLACK_WEBHOOK_URL` | Slack webhook | - |
| `SCAN_INTERVAL` | Scan frequency | - |
| `JOB_QUEUE_URL` | SQS queue URL for distributed jobs | - |
| `JOB_TABLE_NAME` | DynamoDB table for job state | - |
| `JOB_REGION` | AWS region for job infrastructure | - |
| `JOB_WORKER_CONCURRENCY` | Concurrent jobs per worker | `4` |

See [Configuration](docs/CONFIGURATION.md) for all options.

---

## Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| API Framework | Chi |
| Database | Snowflake |
| Data Ingestion | Native scanners |
| Policy Engine | Cedar-style JSON |
| CLI | Cobra |
| Metrics | Prometheus |
| AI | Anthropic, OpenAI |

---

## License

Apache 2.0

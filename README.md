# Cerebro

**Operations Data Platform for Cloud, SaaS, and Business Signal Management**

Cerebro is a unified operations platform that combines data ingestion from cloud providers and SaaS tools, policy evaluation, compliance reporting, AI-powered investigation, business signal analysis, and automated remediation workflows. It works across security, revenue operations, support, and any domain where you need to detect, triage, and act on operational signals.

> **Origin:** Cerebro was originally developed at [Writer](https://github.com/writer/cerebro) as a security-focused cloud posture management tool. This fork generalizes the platform to handle any operational signal — from cloud misconfigurations to stale deals, SLA breaches, payment failures, and business entity drift.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Features

### Core Platform
- **Multi-Source Data Ingestion** — Ingest configurations and events from AWS, GCP, Azure, Kubernetes, and SaaS providers (Salesforce, HubSpot, Stripe, Zendesk, and more) via native scanners
- **Policy Engine** — Cedar-style JSON policies for evaluation with custom condition support, applicable to any domain
- **Parallel Scanning** — High-performance scanning with configurable worker pools
- **Findings Lifecycle** — Generalized signal detection, filtering, suppression, and dashboard views
- **Distributed Job Queue** — SQS + DynamoDB based job system for scalable distributed processing
- **Scheduled Operations** — Automated scanning and digest notifications with configurable intervals

### Security
- **Compliance Frameworks** — Pre-built mappings for SOC 2, CIS, PCI DSS, HIPAA, NIST 800-53
- **Identity Governance** — Access reviews, stale access detection, and risk scoring
- **Attack Path Analysis** — Graph-based visualization of potential attack paths

### Business Operations
- **Business Signal Graph** — Ingest events from Ensemble/NATS streams and map them into a business entity graph with computed policy fields
- **Impact Path Analysis** — Churn, revenue, and incident scenario analysis with aggregate business metrics and chokepoints
- **Business Cohort Analysis** — MinHash-based entity clustering with outlier scoring
- **Composite Posture Scoring** — Per-entity risk scoring with trend/change detection across security and business domains
- **Cross-System Toxic Combinations** — Detect compound risks spanning security and business systems (e.g., churn risk + elevated access)

### AI & Integrations
- **AI Agents** — LLM-powered investigation with Anthropic Claude and OpenAI GPT
- **Deep Research Agent** — Code-to-cloud analysis bridging source code and live cloud inspection
- **Remote Tool Proxy** — Ensemble NATS-based remote tool execution for distributed agent capabilities
- **Integrations** — Jira, Linear, Slack, PagerDuty, and custom webhooks
- **Entity Lineage** — End-to-end provenance tracking and drift detection across business entities

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
│                       │  Graph │Lineage│Remediate │                        │
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
  Kubernetes                 SaaS (SF/HubSpot/           Anthropic/OpenAI
  NATS/Ensemble              Stripe/Zendesk)             NATS Remote Tools
```

---

## Quick Start

### Prerequisites

- Go 1.25+
- Snowflake account (or use local SQLite mode)

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

# Required: Snowflake key-pair auth
export SNOWFLAKE_ACCOUNT="myaccount.us-east-1"
export SNOWFLAKE_USER="CEREBRO_APP"
export SNOWFLAKE_PRIVATE_KEY="<paste-pem-private-key>"
export SNOWFLAKE_WAREHOUSE="COMPUTE_WH"

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

In local mode, findings are persisted to SQLite. Snowflake-backed capabilities (data-lake queries, graph population) are reduced or unavailable.

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

## Policies

Policies are JSON files defining evaluation checks across any domain:

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

```json
{
    "id": "hubspot-stale-deal",
    "name": "Stale HubSpot Deal",
    "description": "Open deals with no activity in 30+ days",
    "effect": "forbid",
    "conditions": ["days_since_last_activity > 30", "stage != closedwon"],
    "severity": "high",
    "tags": ["revops", "hubspot", "pipeline-hygiene"]
}
```

### Policy Directory

```
policies/
├── aws/           # AWS policies (S3, IAM, EC2, RDS)
├── gcp/           # GCP policies (Storage, Compute, IAM)
├── azure/         # Azure policies (Storage, VM)
├── kubernetes/    # Kubernetes policies (Pods, RBAC)
├── hubspot/       # HubSpot deal hygiene policies
├── salesforce/    # Salesforce opportunity policies
├── stripe/        # Stripe payment and billing policies
├── zendesk/       # Zendesk SLA and resolution policies
└── compliance/    # Cross-system compliance policies
```

See [Policy Documentation](docs/POLICIES.md) for writing custom policies.

---

## CLI Commands

```bash
# Start API server
cerebro serve

# Start distributed job worker
cerebro worker

# Run code-to-cloud analysis
cerebro agent run --repo-url https://github.com/org/repo
cerebro agent run --resource arn:aws:s3:::my-bucket --aws-region us-east-1

# Run distributed analysis (enqueue jobs to SQS)
cerebro agent run --repo-url https://github.com/org/repo --distributed --wait

# Sync data via native scanners
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
| `GET /api/v1/entities/{id}/cohort` | Business entity cohort analysis |
| `GET /api/v1/entities/{id}/outlier-score` | Entity outlier scoring |
| `POST /api/v1/impact-analysis` | Business impact path analysis |
| `POST /api/v1/webhooks` | Register webhook |

See [API Reference](docs/API_REFERENCE.md) for complete documentation.

---

## Distributed Job System

Cerebro includes a distributed job queue for scalable analysis across large repositories and cloud environments.

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

```bash
# Set up infrastructure (via Pulumi)
cd infra && pulumi up --stack prod

# Run orchestrator to enqueue jobs
cerebro agent run --repo-url https://github.com/org/repo --distributed

# Run workers (scale horizontally)
cerebro worker --concurrency 4
```

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
| `SNOWFLAKE_ACCOUNT` | Snowflake account identifier | - |
| `SNOWFLAKE_USER` | Snowflake service user | - |
| `SNOWFLAKE_PRIVATE_KEY` | Snowflake PEM private key | - |
| `SNOWFLAKE_DATABASE` | Snowflake database | `CEREBRO` |
| `SNOWFLAKE_SCHEMA` | Snowflake schema | `CEREBRO` |
| `SNOWFLAKE_WAREHOUSE` | Snowflake warehouse | `COMPUTE_WH` |
| `POLICIES_PATH` | Policy directory | `policies` |
| `ANTHROPIC_API_KEY` | Claude API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `API_AUTH_ENABLED` | Require API key auth | `false`* |
| `API_KEYS` | Comma-separated API keys | - |
| `RATE_LIMIT_ENABLED` | Enable API rate limiting | `false` |
| `RATE_LIMIT_REQUESTS` | Requests per rate limit window | `1000` |
| `RATE_LIMIT_WINDOW` | Rate limit duration window | `1h` |
| `JIRA_BASE_URL` | Jira instance | - |
| `SLACK_WEBHOOK_URL` | Slack webhook | - |
| `SCAN_INTERVAL` | Scan frequency | - |
| `SECURITY_DIGEST_INTERVAL` | Security digest frequency | - |
| `JOB_QUEUE_URL` | SQS queue URL for distributed jobs | - |
| `JOB_TABLE_NAME` | DynamoDB table for job state | - |
| `JOB_REGION` | AWS region for job infrastructure | - |
| `JOB_WORKER_CONCURRENCY` | Concurrent jobs per worker | `4` |
| `NATS_URL` | NATS server URL for event streaming | - |

`*` When `API_KEYS` is set, API auth auto-enables unless explicitly overridden.

See [Configuration](docs/CONFIGURATION.md) for all options.

---

## Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.25+ |
| API Framework | Chi |
| Database | Snowflake / SQLite (local) |
| Event Streaming | NATS JetStream |
| Data Ingestion | Native scanners |
| Policy Engine | Cedar-style JSON |
| CLI | Cobra |
| Metrics | Prometheus |
| AI | Anthropic, OpenAI |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Originally developed at [Writer](https://github.com/writer/cerebro).

# Cerebro

Security data platform for cloud and SaaS posture management.

## Architecture

```
┌─────────────────┐     ┌─────────────┐     ┌─────────────┐
│   CloudQuery    │────▶│  Snowflake  │◀────│  Cerebro    │
│  (ingestion)    │     │  (storage)  │     │  (API/CLI)  │
└─────────────────┘     └─────────────┘     └─────────────┘
        │                      │                   │
   AWS/GCP/Azure          Raw tables         Policy engine
   SaaS providers         Analytics            REST API
```

## Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Ingestion | CloudQuery | Sync cloud/SaaS config to Snowflake |
| Storage | Snowflake | Single source of truth |
| Policy | Cedar-style JSON | Security rule evaluation |
| API | Go + Chi | Query interface |
| CLI | Cobra | Management commands |

## Quick Start

```bash
# Install dependencies
make setup

# Configure credentials
cp .env.example .env
# Edit .env with your Snowflake and cloud credentials

# Start the API server
make serve

# Or run in development mode
make dev
```

## CLI Commands

```bash
# Start API server
cerebro serve

# Sync cloud assets via CloudQuery
cerebro sync
cerebro sync --source aws  # Sync only AWS

# Policy management
cerebro policy list
cerebro policy validate
cerebro policy test <policy-id> <asset.json>

# Query Snowflake directly
cerebro query "SELECT * FROM aws_s3_buckets LIMIT 10"
cerebro query --format json "SELECT * FROM aws_iam_users"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check (tests Snowflake) |
| `/api/v1/tables` | GET | List available tables |
| `/api/v1/query` | POST | Execute SQL query |
| `/api/v1/assets/{table}` | GET | List assets from table |
| `/api/v1/assets/{table}/{id}` | GET | Get asset by ID |
| `/api/v1/policies` | GET | List policies |
| `/api/v1/policies/{id}` | GET | Get policy |
| `/api/v1/policies` | POST | Create policy |
| `/api/v1/policies/evaluate` | POST | Evaluate policy |
| `/api/v1/findings/scan` | POST | Scan assets for violations |

## Project Structure

```
cerebro/
├── cmd/cerebro/          # CLI entrypoint
├── internal/
│   ├── api/              # REST API server
│   ├── cli/              # CLI commands
│   ├── config/           # Configuration
│   ├── policy/           # Policy engine
│   └── snowflake/        # Snowflake client
├── config/
│   └── cloudquery.yml    # CloudQuery sync config
├── policies/             # Security policies (JSON)
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## Policies

Policies are JSON files in the `policies/` directory:

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

## Development

```bash
make dev            # Run API with hot reload
make test           # Run tests
make build          # Build binary
make docker-build   # Build Docker image
make policy-list    # List all policies
make policy-validate # Validate policy files
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_PORT` | API server port | 8080 |
| `LOG_LEVEL` | Log level | info |
| `SNOWFLAKE_CONNECTION_STRING` | Snowflake DSN | - |
| `SNOWFLAKE_DATABASE` | Database name | CEREBRO |
| `SNOWFLAKE_SCHEMA` | Schema name | RAW |
| `CEDAR_POLICIES_PATH` | Policies directory | policies |

# Cerebro Quickstart

This guide walks through the minimum steps to run Cerebro locally. For dependency management details, see [UV setup](UV_SETUP.md).

## Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+

## 1. Clone and Install

```bash
git clone https://github.com/WriterInternal/cerebro.git
cd cerebro
uv sync
```

## 2. Configure Environment

```bash
cp .env.example .env
# Update .env with local credentials and API keys
```

## 3. Initialize the Database

```bash
make db-migrate
```

## 4. Start Services

```bash
# API (FastAPI)
make serve

# Worker (Celery, optional)
make worker

# Frontend (Next.js)
cd frontend
npm install
npm run dev
```

## 5. Ingest Sample Data

```bash
# Create an organization
uv run python -m cerebro.cli org create --name "My Company"

# Collect AWS configuration
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
uv run python -m cerebro.cli collect "My Company" --provider aws

# Generate findings
uv run python -m cerebro.cli findings generate --org-name "My Company"
```

## 6. Access the UI

Open <http://localhost:3000>. Development authentication is enabled by default; adjust `.env` if you need stricter settings.

## Interfaces

Cerebro exposes the same security engine through three interfaces.

### CLI

```bash
# List critical findings
cerebro findings list --severity critical --provider aws

# Run SQL queries
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"

# Update a finding
cerebro findings update {finding_id} --status resolved
```

### REST API

```bash
# List findings
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Execute SQL
curl -X POST "http://localhost:8000/api/v1/query/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"sql": "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"}'
```

### AI Agents

```bash
# Create a session
cerebro agents create --type security_analyst --title "AWS Security Review"

# Converse in the web UI at http://localhost:3000/agents
```

Sample prompts:

- "What are the most critical security issues in AWS?"
- "Show me all users without MFA across all providers."
- "Give me a timeline of IAM changes in the last 24 hours."
- "Suggest remediation steps for finding {id}."

All interfaces use the same audited toolchain, PostgreSQL backend, and authorization model.

## Common Operations

### Add a Provider

```bash
# GitHub
export GITHUB_TOKEN=your_token
uv run python -m cerebro.cli providers add github --org "My Company"

# Okta
export OKTA_API_TOKEN=your_token
export OKTA_DOMAIN=company.okta.com
uv run python -m cerebro.cli providers add okta --org "My Company"
```

### Create a Custom Rule

```bash
uv run python -m cerebro.cli rules create \
  --name "Public S3 Buckets" \
  --expression "resource.type == 'aws.s3.bucket' && config.public_read" \
  --severity critical
```

### Generate Reports

```bash
uv run python -m cerebro.cli reports executive --org "My Company" --format pdf
uv run python -m cerebro.cli reports compliance --framework soc2 --org "My Company"
```

## Advanced Configuration

### High-Throughput Collection

```bash
uv run python -m cerebro.cli collect "My Company" \
  --provider aws github okta gcp \
  --parallel 4 \
  --batch-size 1000
```

### Temporal Query Example

```sql
SELECT principal, resource, granted_at
FROM iam_edges
WHERE granted_at BETWEEN '2024-10-01' AND '2024-10-31'
  AND principal LIKE '%admin%';
```

## Next Steps

- [API Reference](../user-guide/API.md)
- [Agents Guide](../agents/README.md)
- [Development Guide](../developer-guide/DEVELOPMENT.md)
- [Deployment Guide](../developer-guide/DEPLOYMENT.md)

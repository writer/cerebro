# Cerebro Quickstart Guide

## 🚀 Get Running in 5 Minutes

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 6+

### 1. Clone and Setup
```bash
git clone https://github.com/WriterInternal/cerebro.git
cd cerebro
uv sync
```

### 2. Environment Configuration
```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Database Setup
```bash
make db-init
uv run alembic upgrade head
```

### 4. Start Services
```bash
# Terminal 1: API Server
make serve

# Terminal 2: Worker (optional)
make worker

# Terminal 3: Frontend
cd ../cerebro-frontend
npm install
npm run dev
```

### 5. First Collection
```bash
# Create organization
uv run python -m cerebro.cli org create --name "My Company"

# Collect AWS data
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
uv run python -m cerebro.cli collect "My Company" --provider aws

# Generate findings
uv run python -m cerebro.cli findings generate --org-name "My Company"
```

### 6. Access Dashboard
Open http://localhost:3000 - development auth enabled by default (see `.env` overrides)

## 🎯 Three Ways to Use Cerebro

Cerebro provides **three first-class interfaces** to the same security engine. Choose what fits your workflow:

### 1️⃣ CLI - Command Line
```bash
# List critical findings
cerebro findings list --severity critical --provider aws

# Run SQL security queries
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"

# Update finding status
cerebro findings update {finding_id} --status resolved
```

### 2️⃣ REST API - Programmatic
```bash
# List findings
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Execute SQL query
curl -X POST "http://localhost:8000/api/v1/query/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"sql": "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"}'
```

### 3️⃣ AI Agents - Conversational (NEW!)
```bash
# Create an agent session via CLI
cerebro agents create --type security_analyst --title "AWS Security Review"

# Or use the web UI at http://localhost:3000/agents
# Then ask questions in natural language:
"What are the most critical security issues in AWS?"
"Show me all users without MFA across all providers"
"Give me a timeline of IAM changes in the last 24 hours"
"Suggest remediation steps for finding {id}"
```

**Key Insight:** All three interfaces use the **same audited toolchain**, query the **same database**, and write to the **same audit trail**. When an agent lists findings, it's using the exact same engine as the CLI and API.

## 🎯 Key Capabilities

### Security Findings
- **Real-time detection** across AWS, GCP, GitHub, Okta
- **Risk-prioritized** with compliance impact mapping
- **Automated remediation** with one-click fixes

### Identity Analysis
- **Cross-provider correlation** (admin@company.com across 4 systems)
- **Privilege escalation detection** (GitHub OIDC → AWS Admin)
- **Stale credential identification** with auto-cleanup

### Compliance Automation
- **SOC 2, ISO 27001, NIST CSF** automated testing
- **Evidence collection** with cryptographic integrity
- **Audit trails** with temporal query capabilities

### Forensic Analysis
- **"Who had access when"** queries with sub-2s response
- **Configuration change timeline** with risk impact
- **Attack path analysis** with blast radius calculation

## 🛠️ Common Operations

### Add New Provider
```bash
# GitHub
export GITHUB_TOKEN=your_token
uv run python -m cerebro.cli providers add github --org "My Company"

# Okta  
export OKTA_API_TOKEN=your_token
export OKTA_DOMAIN=company.okta.com
uv run python -m cerebro.cli providers add okta --org "My Company"
```

### Create Custom Rules
```bash
# CEL-based security rule
uv run python -m cerebro.cli rules create \
  --name "Public S3 Buckets" \
  --expression "resource.type == 'aws.s3.bucket' && config.public_read" \
  --severity critical
```

### Generate Reports
```bash
# Executive summary
uv run python -m cerebro.cli reports executive --org "My Company" --format pdf

# Compliance report
uv run python -m cerebro.cli reports compliance --framework soc2 --org "My Company"
```

## 🔧 Advanced Configuration

### High-Performance Collection
```bash
# Concurrent collection across providers
uv run python -m cerebro.cli collect "My Company" \
  --provider aws github okta gcp \
  --parallel 4 \
  --batch-size 1000
```

### Temporal Analysis
```sql
-- SQL temporal queries
SELECT principal, resource, granted_at 
FROM iam_edges 
WHERE granted_at BETWEEN '2024-10-01' AND '2024-10-31'
  AND principal LIKE '%admin%';
```

## 📚 Next Steps
- [Complete API Reference](./API.md)
- [AI Agents Guide](./agents/README.md)
- [Development Guide](./DEVELOPMENT.md)
- [Deployment Guide](./DEPLOYMENT.md)

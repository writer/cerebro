# Cerebro Quickstart Guide

## 🚀 Get Running in 5 Minutes

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 6+

### 1. Clone and Setup
```bash
git clone https://github.com/haasonsaas/cerebro.git
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
Open http://localhost:3000 - dev auth enabled by default

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
- [Complete API Reference](./API_REFERENCE.md)
- [Architecture Guide](./ARCHITECTURE.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Security Best Practices](./SECURITY.md)

# Cerebro API Reference

## Overview
The Cerebro Security System of Record provides comprehensive REST APIs for security data collection, analysis, and compliance automation.

## Base URL
```
Production: https://api.cerebro.com
Development: http://localhost:8000
```

## Authentication
All API endpoints require JWT authentication:

```bash
curl -H "Authorization: Bearer <token>" https://api.cerebro.com/api/v1/findings
```

## Core Endpoints

### 🔍 Findings Management
```bash
# List findings with filtering
GET /api/v1/findings?severity=critical&provider=aws&limit=50

# Get specific finding
GET /api/v1/findings/{finding_id}

# Suppress finding with reason
POST /api/v1/findings/{finding_id}/suppress
{
  "reason": "False positive - internal testing bucket"
}

# Get MTTR metrics
GET /api/v1/findings/mttr?severity=critical&timeframe_days=30
```

### 👥 Identity Governance  
```bash
# Get identity risk metrics
GET /api/v1/identity-governance/risk-metrics

# Create access review campaign
POST /api/v1/identity-governance/access-reviews
{
  "name": "Q4 2024 Admin Review",
  "scope": {"providers": ["aws", "okta"]},
  "due_date": "2024-12-31"
}
```

### 📊 Analytics Dashboard
```bash
# Get comprehensive dashboard
GET /api/v1/analytics/organizations/{org_id}/dashboard

# Get executive summary (board-ready)
GET /api/v1/analytics/organizations/{org_id}/executive-summary

# Get risk scoring
GET /api/v1/analytics/organizations/{org_id}/risk-score
```

### 🔍 Temporal Queries (Forensic Analysis)
```bash
# Execute SQL with temporal analysis
POST /api/v1/query/execute
{
  "sql": "SELECT principal, resource FROM iam_edges WHERE granted_at > NOW() - INTERVAL '7 days'"
}

# Get forensic timeline
GET /api/v1/analysis/forensic-timeline?hours=24
```

### 🏢 Vendor Management
```bash
# List vendors with risk assessment
GET /api/v1/vendors/organizations/{org_id}/vendors

# Get vendor risk report
GET /api/v1/vendors/organizations/{org_id}/vendors/risk-report

# Review discovered vendor
POST /api/v1/vendors/organizations/{org_id}/vendors/discovered/{id}/review
```

### 🧪 Security Testing
```bash
# List security tests
GET /api/v1/tests/organizations/{org_id}/tests

# Create custom security test
POST /api/v1/tests/organizations/{org_id}/tests
{
  "name": "Admin Group Audit",
  "test_type": "automated",
  "sql_query": "SELECT * FROM *_user WHERE is_admin = true",
  "frequency": "weekly",
  "risk_level": "high"
}

# Execute threat simulation
POST /api/v1/tests/threat-simulation
{
  "simulation_id": "insider_privilege_escalation",
  "org_id": "uuid",
  "parameters": {"target_provider": "aws"}
}

# Run security benchmark
POST /api/v1/tests/security-benchmark
{
  "org_id": "uuid",
  "include_tests": ["penetration_testing", "configuration_assessment"]
}

# Get test results with evidence
GET /api/v1/tests/results/{execution_id}
```

### 🏗️ Enhanced Provider Support
```bash
# Google Cloud with GAM patterns
POST /api/v1/collection/accounts
{
  "provider": "gcp_enhanced",
  "config": {
    "project_id": "my-project-123",
    "service_account_file": "/path/to/service-account.json"
  }
}

# Google Workspace with domain-wide delegation
POST /api/v1/collection/accounts  
{
  "provider": "google_workspace",
  "config": {
    "domain": "company.com",
    "service_account_file": "/path/to/service-account.json", 
    "delegate_user": "admin@company.com"
  }
}

# Enhanced wildcard queries across providers
POST /api/v1/query/execute
{
  "sql": "SELECT * FROM aws_* WHERE is_public = true UNION ALL SELECT * FROM gcp_* WHERE is_public = true"
}
```

## Advanced Security Testing

### Threat Simulation Scenarios
Available threat simulation scenarios for automated red team testing:

| Scenario ID | Description | Complexity | Threat Type |
|-------------|-------------|------------|-------------|
| `insider_privilege_escalation` | Simulates insider attempting privilege escalation | Advanced | Insider Threat |
| `cloud_lateral_movement` | Simulates lateral movement across cloud resources | Advanced | External Attack |
| `supply_chain_compromise` | Simulates compromise through third-party integrations | Expert | Supply Chain |

### Security Benchmarks
Automated security benchmarks for continuous validation:

```bash
# Run comprehensive security benchmark
POST /api/v1/tests/security-benchmark
{
  "org_id": "uuid",
  "include_tests": [
    "excessive_permissions_test",
    "stale_accounts_test", 
    "unencrypted_storage_test",
    "public_access_test",
    "weak_authentication_test",
    "privilege_escalation_test"
  ]
}

# Response includes security posture scoring
{
  "overall_score": 0.85,
  "security_posture": "good", 
  "test_results": {...},
  "recommendations": [
    "Review and reduce admin user count",
    "Enable encryption for all storage resources"
  ]
}
```

### Wildcard Query Engine
Enhanced query engine supports UNION ALL across multiple provider tables:

```sql
-- Query all user tables across providers
SELECT email, is_admin, provider FROM *_user WHERE is_admin = true

-- Query all storage resources
SELECT bucket_name, is_public, provider FROM *_storage_* 

-- Cross-provider security analysis
SELECT provider, COUNT(*) as admin_count 
FROM aws_iam, gcp_iam, okta_user 
WHERE is_admin = true 
GROUP BY provider
```

## WebSocket Events

Connect to real-time updates:
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/events?org_id=org-123');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'new_finding') {
    // Handle new security finding
  }
};
```

## Response Formats

All responses follow consistent format:
```json
{
  "success": true,
  "message": "Operation completed",
  "data": { /* response data */ }
}
```

Error responses:
```json
{
  "success": false,
  "message": "Error description",
  "error_code": "VALIDATION_ERROR"
}
```

## Rate Limits
- 1000 requests per hour per API key
- 100 concurrent connections for WebSocket
- Batch operations: 500 items max per request

## SDKs Available
- Python SDK: `pip install cerebro-sdk`
- TypeScript SDK: `npm install @cerebro/sdk`
- CLI Tool: `pip install cerebro-cli`

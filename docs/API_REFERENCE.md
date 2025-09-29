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

# Run security tests
POST /api/v1/tests/run

# Get test results
GET /api/v1/tests/results
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

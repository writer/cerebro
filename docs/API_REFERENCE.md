# Cerebro API Reference

Base URL: `http://localhost:8080`

## Table of Contents

- [Health & Status](#health--status)
- [Query & Assets](#query--assets)
- [Policies](#policies)
- [Findings](#findings)
- [Compliance](#compliance)
- [AI Agents](#ai-agents)
- [Ticketing](#ticketing)
- [Identity & Access Review](#identity--access-review)
- [Attack Paths](#attack-paths)
- [Providers](#providers)
- [Webhooks](#webhooks)
- [Scheduler](#scheduler)
- [Notifications](#notifications)
- [Admin](#admin)

---

## Health & Status

### GET /health
Health check endpoint.

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### GET /ready
Readiness check with dependency status.

**Response:**
```json
{
    "ready": true,
    "checks": {
        "snowflake": "healthy",
        "policies": "15 loaded",
        "agents": "2 registered",
        "providers": "2 registered"
    }
}
```

### GET /metrics
Prometheus metrics endpoint.

---

## Query & Assets

### GET /api/v1/tables
List all available Snowflake tables.

**Response:**
```json
{
    "tables": ["aws_s3_buckets", "aws_iam_users", "gcp_storage_buckets"],
    "count": 150
}
```

### POST /api/v1/query
Execute a SQL query against Snowflake.

**Request:**
```json
{
    "query": "SELECT * FROM aws_s3_buckets WHERE region = 'us-east-1' LIMIT 10",
    "limit": 10
}
```

**Response:**
```json
{
    "columns": ["name", "arn", "region", "creation_date"],
    "rows": [
        {"name": "my-bucket", "arn": "arn:aws:s3:::my-bucket", ...}
    ],
    "count": 5
}
```

### GET /api/v1/assets/{table}
List assets from a specific table.

**Query Parameters:**
- `limit` (int): Maximum results (default: 100)
- `account` (string): Filter by account
- `region` (string): Filter by region

**Response:**
```json
{
    "assets": [{...}, {...}],
    "count": 50
}
```

### GET /api/v1/assets/{table}/{id}
Get a specific asset by ID.

---

## Policies

### GET /api/v1/policies
List all loaded policies.

**Response:**
```json
{
    "policies": [
        {
            "id": "aws-s3-bucket-no-public-access",
            "name": "S3 Bucket Public Access",
            "description": "S3 buckets should not allow public access",
            "effect": "forbid",
            "severity": "critical",
            "tags": ["cis-aws-2.1.5", "security", "s3"]
        }
    ],
    "count": 15
}
```

### GET /api/v1/policies/{id}
Get a specific policy by ID.

### POST /api/v1/policies
Create a new policy.

**Request:**
```json
{
    "id": "custom-policy-1",
    "name": "Custom Policy",
    "description": "Description",
    "effect": "forbid",
    "conditions": ["field == value"],
    "severity": "high",
    "tags": ["custom"]
}
```

### POST /api/v1/policies/evaluate
Evaluate a policy request.

**Request:**
```json
{
    "principal": {"type": "user", "id": "user123"},
    "action": "s3:GetObject",
    "resource": {"type": "s3_bucket", "name": "my-bucket"},
    "context": {}
}
```

**Response:**
```json
{
    "decision": "deny",
    "matched": ["aws-s3-bucket-no-public-access"],
    "reasons": ["policy aws-s3-bucket-no-public-access: S3 buckets should not allow public access"]
}
```

---

## Findings

### GET /api/v1/findings
List all findings.

**Query Parameters:**
- `severity` (string): Filter by severity (critical, high, medium, low)
- `status` (string): Filter by status (open, resolved, suppressed)
- `policy_id` (string): Filter by policy ID

**Response:**
```json
{
    "findings": [
        {
            "id": "finding-123",
            "policy_id": "aws-s3-bucket-no-public-access",
            "policy_name": "S3 Bucket Public Access",
            "severity": "critical",
            "status": "open",
            "resource_id": "arn:aws:s3:::public-bucket",
            "resource_type": "aws_s3_buckets",
            "description": "S3 bucket allows public access",
            "first_seen": "2024-01-10T08:00:00Z",
            "last_seen": "2024-01-15T10:30:00Z"
        }
    ],
    "count": 25
}
```

### GET /api/v1/findings/stats
Get finding statistics.

**Response:**
```json
{
    "total": 100,
    "by_severity": {
        "critical": 5,
        "high": 20,
        "medium": 50,
        "low": 25
    },
    "by_status": {
        "open": 75,
        "resolved": 20,
        "suppressed": 5
    },
    "by_policy": {
        "aws-s3-bucket-no-public-access": 10,
        "aws-iam-user-no-mfa": 15
    }
}
```

### GET /api/v1/findings/{id}
Get a specific finding.

### POST /api/v1/findings/scan
Trigger a policy scan on assets.

**Request:**
```json
{
    "table": "aws_s3_buckets",
    "limit": 100
}
```

**Response:**
```json
{
    "scanned": 100,
    "violations": 5,
    "duration": "1.5s",
    "findings": [{...}]
}
```

### POST /api/v1/findings/{id}/resolve
Mark a finding as resolved.

### POST /api/v1/findings/{id}/suppress
Suppress a finding.

---

## Compliance

### GET /api/v1/compliance/frameworks
List available compliance frameworks.

**Response:**
```json
{
    "frameworks": [
        {
            "id": "soc2",
            "name": "SOC 2 Type II",
            "version": "2017",
            "controls": 64
        },
        {
            "id": "cis-aws",
            "name": "CIS AWS Foundations",
            "version": "1.4.0",
            "controls": 53
        }
    ],
    "count": 6
}
```

### GET /api/v1/compliance/frameworks/{id}
Get framework details with controls.

### GET /api/v1/compliance/frameworks/{id}/report
Generate a compliance report.

**Response:**
```json
{
    "framework_id": "soc2",
    "framework_name": "SOC 2 Type II",
    "generated_at": "2024-01-15T10:30:00Z",
    "summary": {
        "total_controls": 64,
        "passing_controls": 58,
        "failing_controls": 6,
        "compliance_score": 90.6
    },
    "controls": [
        {"control_id": "CC6.1", "status": "passing"},
        {"control_id": "CC6.2", "status": "failing"}
    ]
}
```

### GET /api/v1/compliance/frameworks/{id}/pre-audit
Pre-audit health check.

**Response:**
```json
{
    "framework_id": "soc2",
    "estimated_outcome": "PASS WITH 2 EXCEPTIONS",
    "summary": {
        "total_controls": 64,
        "passing": 62,
        "failing": 2,
        "at_risk": 0,
        "compliance_score": "96.9%"
    },
    "controls": [
        {
            "control_id": "CC6.1",
            "title": "Logical Access Security",
            "status": "failing",
            "issues": ["2 findings for policy aws-iam-user-no-mfa"],
            "remediation": "Review and remediate findings before audit"
        }
    ],
    "recommendations": [
        "Remediate 2 failing controls before audit"
    ]
}
```

### GET /api/v1/compliance/frameworks/{id}/export
Export audit package with evidence.

---

## AI Agents

### GET /api/v1/agents
List registered AI agents.

**Response:**
```json
{
    "agents": [
        {
            "id": "security-analyst",
            "name": "Security Analyst",
            "description": "AI-powered security analyst for investigating findings",
            "tools": 5
        }
    ],
    "count": 2
}
```

### GET /api/v1/agents/{id}
Get agent details including available tools.

**Response:**
```json
{
    "id": "security-analyst",
    "name": "Security Analyst",
    "description": "...",
    "tools": [
        {
            "name": "query_snowflake",
            "description": "Execute SQL queries against Snowflake",
            "requires_approval": false
        }
    ]
}
```

### POST /api/v1/agents/sessions
Create a new investigation session.

**Request:**
```json
{
    "agent_id": "security-analyst",
    "user_id": "user@example.com",
    "finding_ids": ["finding-123"],
    "context": {
        "priority": "high"
    }
}
```

**Response:**
```json
{
    "id": "session-456",
    "agent_id": "security-analyst",
    "user_id": "user@example.com",
    "status": "active",
    "messages": [],
    "created_at": "2024-01-15T10:30:00Z"
}
```

### GET /api/v1/agents/sessions/{id}
Get session details.

### POST /api/v1/agents/sessions/{id}/messages
Send a message to the agent.

**Request:**
```json
{
    "content": "Investigate the S3 bucket public access findings"
}
```

**Response:**
```json
{
    "role": "assistant",
    "content": "I'll investigate the S3 bucket findings. Let me query the relevant data..."
}
```

### GET /api/v1/agents/sessions/{id}/messages
Get all messages in a session.

---

## Ticketing

### GET /api/v1/tickets
List tickets.

**Query Parameters:**
- `status` (string): Filter by status
- `priority` (string): Filter by priority

### POST /api/v1/tickets
Create a ticket from findings.

**Request:**
```json
{
    "title": "Critical S3 Public Access",
    "description": "Multiple S3 buckets have public access enabled",
    "priority": "high",
    "finding_ids": ["finding-123", "finding-124"]
}
```

### GET /api/v1/tickets/{id}
Get ticket details.

### PUT /api/v1/tickets/{id}
Update a ticket.

**Request:**
```json
{
    "status": "in_progress",
    "assignee": "security-team"
}
```

### POST /api/v1/tickets/{id}/comments
Add a comment to a ticket.

**Request:**
```json
{
    "body": "Investigating this issue"
}
```

### POST /api/v1/tickets/{id}/close
Close a ticket.

**Request:**
```json
{
    "resolution": "Fixed by enabling block_public_acls"
}
```

---

## Identity & Access Review

### GET /api/v1/identity/reviews
List access reviews.

**Query Parameters:**
- `status` (string): draft, scheduled, in_progress, completed, canceled

### POST /api/v1/identity/reviews
Create a new access review.

**Request:**
```json
{
    "name": "Q1 2024 User Access Review",
    "description": "Quarterly review of user access",
    "type": "user_access",
    "scope": {
        "providers": ["aws", "gcp"],
        "accounts": ["production"]
    },
    "reviewers": ["manager@example.com"],
    "due_at": "2024-02-15T00:00:00Z"
}
```

### GET /api/v1/identity/reviews/{id}
Get review details.

### POST /api/v1/identity/reviews/{id}/start
Start an access review.

### GET /api/v1/identity/reviews/{id}/items
List items in a review.

### POST /api/v1/identity/reviews/{id}/items
Add an item to a review.

**Request:**
```json
{
    "type": "user",
    "principal": {
        "id": "user123",
        "type": "user",
        "name": "John Doe",
        "email": "john@example.com",
        "provider": "aws"
    },
    "access": [
        {
            "resource": "arn:aws:s3:::production-data",
            "permission": "s3:*",
            "role": "admin"
        }
    ]
}
```

### POST /api/v1/identity/reviews/{id}/items/{itemId}/decide
Record a review decision.

**Request:**
```json
{
    "action": "approve",
    "reviewer": "manager@example.com",
    "comment": "Access is required for job function"
}
```

**Actions:** `approve`, `revoke`, `modify`, `escalate`, `defer`

### GET /api/v1/identity/stale-access
Detect stale access across providers.

**Response:**
```json
{
    "findings": [
        {
            "type": "inactive_user",
            "principal": "user@example.com",
            "provider": "aws",
            "last_activity": "2023-06-15T00:00:00Z",
            "days_inactive": 180,
            "risk_score": 75,
            "recommendation": "Review and potentially disable account"
        }
    ],
    "count": 15,
    "summary": {
        "inactive_users": 10,
        "unused_keys": 3,
        "stale_service_accts": 2
    }
}
```

### GET /api/v1/identity/report
Generate comprehensive identity report.

---

## Attack Paths

### GET /api/v1/attack-paths
List discovered attack paths.

### POST /api/v1/attack-paths/analyze
Analyze attack paths to high-value targets.

**Request:**
```json
{
    "high_value_targets": ["production-database", "customer-data-bucket"],
    "max_depth": 10
}
```

**Response:**
```json
{
    "paths": [
        {
            "id": "path-123",
            "severity": "critical",
            "steps": 3,
            "nodes": ["public-ec2", "iam-role", "production-database"]
        }
    ],
    "count": 2,
    "analyzed_at": "2024-01-15T10:30:00Z"
}
```

### GET /api/v1/attack-paths/{id}
Get attack path details.

### GET /api/v1/attack-paths/graph
Get the full asset relationship graph.

### POST /api/v1/attack-paths/graph/nodes
Add a node to the graph.

### POST /api/v1/attack-paths/graph/edges
Add an edge (relationship) to the graph.

---

## Providers

### GET /api/v1/providers
List registered data providers.

**Response:**
```json
{
    "providers": [
        {
            "name": "crowdstrike",
            "type": "security",
            "tables": 5
        },
        {
            "name": "okta",
            "type": "identity",
            "tables": 8
        }
    ],
    "count": 2
}
```

### GET /api/v1/providers/{name}
Get provider details with schema.

### POST /api/v1/providers/{name}/configure
Configure a provider.

**Request:**
```json
{
    "client_id": "...",
    "client_secret": "..."
}
```

### POST /api/v1/providers/{name}/sync
Trigger a data sync.

### GET /api/v1/providers/{name}/schema
Get provider table schema.

### POST /api/v1/providers/{name}/test
Test provider connectivity.

---

## Webhooks

### GET /api/v1/webhooks
List registered webhooks.

### POST /api/v1/webhooks
Register a new webhook.

**Request:**
```json
{
    "url": "https://example.com/webhook",
    "events": ["finding.created", "scan.completed"],
    "secret": "webhook-secret-123"
}
```

**Response:**
```json
{
    "id": "webhook-456",
    "url": "https://example.com/webhook",
    "events": ["finding.created", "scan.completed"],
    "enabled": true,
    "created_at": "2024-01-15T10:30:00Z"
}
```

### GET /api/v1/webhooks/{id}
Get webhook details.

### DELETE /api/v1/webhooks/{id}
Delete a webhook.

### GET /api/v1/webhooks/{id}/deliveries
Get delivery history for a webhook.

### POST /api/v1/webhooks/test
Send a test webhook.

**Request:**
```json
{
    "url": "https://example.com/webhook"
}
```

**Webhook Payload:**
```json
{
    "id": "event-123",
    "type": "finding.created",
    "timestamp": "2024-01-15T10:30:00Z",
    "data": {
        "finding_id": "finding-123",
        "policy_id": "aws-s3-bucket-no-public-access",
        "severity": "critical"
    }
}
```

**Webhook Headers:**
- `Content-Type: application/json`
- `X-Cerebro-Event: finding.created`
- `X-Cerebro-Delivery: event-123`
- `X-Cerebro-Signature: sha256=...` (if secret configured)

---

## Scheduler

### GET /api/v1/scheduler/status
Get scheduler status.

### GET /api/v1/scheduler/jobs
List scheduled jobs.

**Response:**
```json
{
    "jobs": [
        {
            "name": "policy-scan",
            "interval": "1h",
            "enabled": true,
            "running": false,
            "next_run": "2024-01-15T11:00:00Z",
            "last_run": "2024-01-15T10:00:00Z"
        }
    ],
    "count": 1
}
```

### POST /api/v1/scheduler/jobs/{name}/run
Trigger a job manually.

### POST /api/v1/scheduler/jobs/{name}/enable
Enable a job.

### POST /api/v1/scheduler/jobs/{name}/disable
Disable a job.

---

## Notifications

### GET /api/v1/notifications
List configured notifiers.

**Response:**
```json
{
    "notifiers": ["slack", "pagerduty"],
    "count": 2
}
```

### POST /api/v1/notifications/test
Send a test notification.

**Request:**
```json
{
    "message": "Test notification",
    "severity": "info"
}
```

---

## Admin

### GET /api/v1/admin/health
Comprehensive health dashboard.

**Response:**
```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "snowflake": {
        "status": "healthy",
        "latency_ms": 45
    },
    "findings": {
        "total": 100,
        "open": 75,
        "critical": 5,
        "high": 20,
        "medium": 40,
        "low": 10
    },
    "cache": {
        "size": 1500,
        "hits": 45000,
        "misses": 500
    },
    "policies": {"loaded": 15},
    "agents": {"registered": 2},
    "providers": {"registered": 2},
    "scheduler": {"configured": true}
}
```

### GET /api/v1/admin/sync/status
Get data freshness status by provider.

**Response:**
```json
{
    "sources": {
        "aws": {
            "last_sync": "2024-01-15T08:00:00Z",
            "status": "fresh",
            "age": "2h30m"
        },
        "gcp": {
            "last_sync": "2024-01-14T20:00:00Z",
            "status": "stale",
            "age": "14h30m"
        }
    },
    "stale_threshold": "6h",
    "checked_at": "2024-01-15T10:30:00Z"
}
```

---

## Error Responses

All error responses follow this format:

```json
{
    "error": "Error message description"
}
```

**HTTP Status Codes:**
- `200` - Success
- `201` - Created
- `204` - No Content (successful deletion)
- `400` - Bad Request
- `404` - Not Found
- `500` - Internal Server Error
- `503` - Service Unavailable

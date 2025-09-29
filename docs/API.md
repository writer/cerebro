# 📡 Cerebro API Reference

Complete API reference for Cerebro Security System of Record.

## 🔐 Authentication

All API endpoints require JWT authentication except for login endpoints.

### **Get Access Token**

```bash
POST /api/v1/auth/token
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123!"
}

# Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### **Use Token in Requests**

```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🏢 Organizations

### **Create Organization**
```bash
POST /api/v1/organizations
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Acme Corporation"
}
```

### **List Organizations**
```bash
GET /api/v1/organizations?skip=0&limit=100
Authorization: Bearer <token>
```

## 🔗 Accounts

### **Create Account**
```bash
POST /api/v1/accounts
Authorization: Bearer <token>
Content-Type: application/json

{
  "org_id": "123e4567-e89b-12d3-a456-426614174000",
  "provider": "github",
  "external_id": "acme-corp",
  "display_name": "Acme Corp GitHub"
}
```

### **List Accounts**
```bash
GET /api/v1/accounts?org_id={org_id}&provider=github
Authorization: Bearer <token>
```

## 📊 Data Collection

### **Start Collection (Background)**
```bash
POST /api/v1/collectors/organizations/{org_id}/collect/background
Authorization: Bearer <token>
Content-Type: application/json

{
  "providers": ["github", "aws"],
  "resource_types": ["github.repo", "aws.s3.bucket"]
}

# Response
{
  "message": "Collection started in background",
  "task_id": "abc123...",
  "org_id": "123e4567...",
  "providers": ["github", "aws"]
}
```

### **Monitor Task Progress**
```bash
GET /api/v1/collectors/tasks/{task_id}
Authorization: Bearer <token>

# Response
{
  "task_id": "abc123...",
  "status": "PROGRESS",
  "result": null,
  "info": {
    "status": "Collecting data",
    "progress": 45,
    "resources_collected": 150,
    "principals_collected": 25
  }
}
```

## 📋 Resources

### **List Resources**
```bash
GET /api/v1/resources?account_id={account_id}&provider=aws&resource_type=aws.s3.bucket
Authorization: Bearer <token>
```

### **Get Resource Configuration History**
```bash
GET /api/v1/resources/{resource_id}/configurations?limit=10
Authorization: Bearer <token>

# Response
[
  {
    "snapshot_id": "456e7890...",
    "captured_at": "2024-01-15T10:30:00Z",
    "normalized_config": {
      "visibility": "public",
      "encryption": {"enabled": false},
      "policy": {...}
    },
    "collector_version": "1.0.0"
  }
]
```

## 👤 Principals & Permissions

### **List Principals**
```bash
GET /api/v1/principals?account_id={account_id}&is_human=true
Authorization: Bearer <token>
```

### **Get Principal Permissions**
```bash
GET /api/v1/principals/{principal_id}/permissions?active_only=true
Authorization: Bearer <token>

# Response
{
  "principal_id": "789e0123...",
  "principal_info": {
    "external_id": "john.doe@acme.com",
    "display_name": "John Doe",
    "email": "john.doe@acme.com",
    "principal_type": "user",
    "provider": "github"
  },
  "permissions": [
    {
      "edge_id": "abc456...",
      "permission": "github.repo.admin",
      "via": "direct_collaboration",
      "effective_at": "2024-01-01T00:00:00Z",
      "expires_at": null,
      "is_admin": true,
      "resource": {
        "resource_id": "def789...",
        "external_id": "acme-corp/sensitive-repo",
        "name": "sensitive-repo",
        "resource_type": "github.repo"
      }
    }
  ],
  "total_permissions": 15,
  "active_only": true
}
```

## 🔍 Security Findings

### **List Findings**
```bash
GET /api/v1/findings?org_id={org_id}&status=open&severity=critical
Authorization: Bearer <token>

# Response
[
  {
    "finding_id": "bcd567...",
    "title": "GitHub: Public Repository Without Branch Protection",
    "summary": "Repository acme-corp/public-api is public but lacks required branch protection",
    "severity": "high",
    "status": "open",
    "provider": "github",
    "first_seen": "2024-01-15T10:00:00Z",
    "last_seen": "2024-01-15T18:00:00Z",
    "evidence": {
      "repository": "public-api",
      "visibility": "public",
      "branch_protection": {"enabled": false},
      "default_branch": "main"
    }
  }
]
```

### **Generate Findings (Background)**
```bash
POST /api/v1/findings/organizations/{org_id}/generate
Authorization: Bearer <token>
Content-Type: application/json

{
  "provider": "aws",
  "resource_types": ["aws.s3.bucket"]
}

# Response
{
  "message": "Finding generation started",
  "task_id": "xyz789...",
  "org_id": "123e4567...",
  "provider": "aws"
}
```

### **Update Finding Status**
```bash
PUT /api/v1/findings/{finding_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "suppressed"
}
```

### **Get Finding Statistics**
```bash
GET /api/v1/findings/organizations/{org_id}/stats
Authorization: Bearer <token>

# Response
{
  "total": 156,
  "by_status": {
    "open": 89,
    "suppressed": 12,
    "fixed": 55
  },
  "by_severity": {
    "critical": 8,
    "high": 45,
    "medium": 78,
    "low": 25
  },
  "by_provider": {
    "github": 34,
    "aws": 122
  }
}
```

## ⚙️ Rules Management

### **List Rules**
```bash
GET /api/v1/rules?provider=github&severity=high&is_active=true
Authorization: Bearer <token>
```

### **Create Custom Rule**
```bash
POST /api/v1/rules
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Custom S3 Security Rule",
  "description": "Detects S3 buckets with specific security issues",
  "provider": ["aws"],
  "resource_types": ["aws.s3.bucket"],
  "expression": "resource.resource_type == 'aws.s3.bucket' && config.encryption.enabled == false",
  "severity": "medium",
  "cis": ["2.1.1"],
  "nist_800_53": ["SC-28"]
}
```

### **Test Rule Compilation**
```bash
POST /api/v1/rules/{rule_id}/test
Authorization: Bearer <token>

# Response
{
  "rule_id": "def456...",
  "status": "success",
  "message": "Rule compiled successfully"
}
```

## 🔒 User Management

### **Create User**
```bash
POST /api/v1/users
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "username": "security_analyst",
  "email": "analyst@acme.com",
  "password": "SecurePassword123!",
  "scopes": ["read:findings", "read:rules", "read:resources"]
}
```

### **Get Current User Info**
```bash
GET /api/v1/auth/me
Authorization: Bearer <token>

# Response
{
  "username": "admin",
  "email": "admin@cerebro.local",
  "is_admin": true,
  "scopes": ["admin", "read:findings", "write:rules", "collect:data"]
}
```

## 🕐 Temporal Queries

### **Resource Configuration History**
```bash
GET /api/v1/resources/{resource_id}/configurations?limit=20
Authorization: Bearer <token>
```

### **Permission History**
```bash
GET /api/v1/principals/{principal_id}/permissions?active_only=false
Authorization: Bearer <token>
```

### **Audit Trail**
```bash
GET /api/v1/audit/events?start_time=2024-01-01T00:00:00Z&end_time=2024-01-15T23:59:59Z
Authorization: Bearer <token>
```

## 📊 System Status

### **Health Checks**
```bash
# Basic health
GET /health

# Database connectivity  
GET /health/db

# Collection system status
GET /api/v1/collectors/status
Authorization: Bearer <token>
```

### **Provider Status**
```bash
GET /api/v1/collectors/providers
Authorization: Bearer <token>

# Response
{
  "providers": [
    {
      "name": "github",
      "display_name": "GitHub",
      "description": "GitHub repositories, users, and permissions",
      "resource_types": ["github.repo", "github.team", "github.user"],
      "status": "implemented"
    },
    {
      "name": "aws",
      "display_name": "Amazon Web Services", 
      "description": "AWS resources, IAM, and configurations",
      "resource_types": ["aws.s3.bucket", "aws.ec2.instance", "aws.iam.user"],
      "status": "implemented"
    }
  ]
}
```

## 🔧 Error Handling

### **Standard Error Response**
```json
{
  "detail": "Resource not found",
  "error_code": "RESOURCE_NOT_FOUND",
  "timestamp": "2024-01-15T10:30:00Z",
  "path": "/api/v1/resources/123"
}
```

### **Validation Errors**
```json
{
  "detail": [
    {
      "loc": ["body", "severity"],
      "msg": "value is not a valid enumeration member",
      "type": "type_error.enum",
      "ctx": {"enum_values": ["critical", "high", "medium", "low", "info"]}
    }
  ]
}
```

## 📈 Rate Limits

| Endpoint Category | Rate Limit | Burst |
|------------------|------------|-------|
| Authentication   | 10/minute  | 20    |
| Collection       | 5/minute   | 10    |
| Findings         | 100/minute | 200   |
| General API      | 1000/hour  | 100   |

## 🔌 Webhooks (Coming Soon)

Cerebro will support webhooks for real-time notifications:

```bash
POST /api/v1/webhooks
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://your-app.com/webhooks/cerebro",
  "events": ["finding.created", "finding.status_changed"],
  "secret": "webhook_secret_key"
}
```

## 🧪 Testing API

Use the interactive documentation at `http://localhost:8000/docs` to explore all endpoints with real-time testing capabilities.

### **Example Test Workflow**
1. Get authentication token
2. Create organization and accounts
3. Start background collection
4. Monitor task progress
5. Generate and review findings
6. Update finding statuses
7. Export compliance reports

---

**For complete deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md)**

# 🗄️ Database Schema Reference

Complete reference for Cerebro's database schema with entity relationships and migration patterns.

## 🏗️ Schema Overview

Cerebro uses an **append-only architecture** for auditability and temporal queries, with PostgreSQL as the primary database.

## 📊 Entity Relationship Diagram

<function_calls>
<invoke name="mermaid">
<parameter name="code">erDiagram
    organizations {
        uuid id PK
        string name
        string slug
        timestamp created_at
        timestamp updated_at
        boolean is_active
    }
    
    accounts {
        uuid id PK
        uuid org_id FK
        string provider
        string external_id
        string display_name
        jsonb credentials_encrypted
        timestamp created_at
        timestamp updated_at
    }
    
    resources {
        uuid id PK
        uuid account_id FK
        string external_id
        string name
        string resource_type
        string provider
        string region
        jsonb tags
        timestamp created_at
        timestamp updated_at
    }
    
    config_snapshots {
        uuid id PK
        uuid resource_id FK
        timestamp captured_at
        jsonb normalized_config
        string config_hash
        string collector_version
        jsonb metadata
    }
    
    principals {
        uuid id PK
        uuid account_id FK
        string external_id
        string display_name
        string email
        string principal_type
        boolean is_human
        jsonb attributes
        timestamp created_at
        timestamp updated_at
    }
    
    iam_edges {
        uuid id PK
        uuid principal_id FK
        uuid resource_id FK
        string permission
        string via
        timestamp effective_at
        timestamp expires_at
        boolean is_admin
        jsonb metadata
    }
    
    identity_clusters {
        uuid id PK
        uuid org_id FK
        jsonb principal_ids
        string cluster_type
        float confidence_score
        jsonb correlation_evidence
        timestamp created_at
        timestamp updated_at
    }
    
    rules {
        uuid id PK
        string name
        text description
        jsonb providers
        jsonb resource_types
        text expression
        string severity
        jsonb framework_mappings
        boolean is_active
        timestamp created_at
        timestamp updated_at
    }
    
    findings {
        uuid id PK
        uuid resource_id FK
        uuid rule_id FK
        uuid principal_id FK
        string title
        text summary
        string severity
        string status
        timestamp first_seen
        timestamp last_seen
        jsonb evidence
        uuid created_by FK
        timestamp created_at
    }
    
    users {
        uuid id PK
        string username
        string email
        string password_hash
        jsonb scopes
        boolean is_admin
        timestamp last_login
        timestamp created_at
        timestamp updated_at
    }
    
    audit_events {
        uuid id PK
        uuid user_id FK
        string action
        string resource_type
        uuid resource_id FK
        jsonb metadata
        string ip_address
        string user_agent
        timestamp created_at
    }
    
    organizations ||--o{ accounts : "has many"
    organizations ||--o{ identity_clusters : "has many"
    accounts ||--o{ resources : "has many"
    accounts ||--o{ principals : "has many"
    resources ||--o{ config_snapshots : "has many"
    resources ||--o{ iam_edges : "resource access"
    resources ||--o{ findings : "security issues"
    principals ||--o{ iam_edges : "permissions"
    principals ||--o{ findings : "user findings"
    rules ||--o{ findings : "generates"
    users ||--o{ audit_events : "performed by"
    users ||--o{ findings : "created by"

## 📋 Core Tables

### Organizations (`organizations`)

Multi-tenant isolation for companies or business units.

```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);
```

**Key Features:**
- **Multi-tenancy**: All data is scoped to an organization
- **Slug**: URL-friendly identifier for API endpoints
- **Soft deletion**: `is_active` flag instead of hard deletes

### Accounts (`accounts`)

Provider-specific accounts within organizations.

```sql
CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'aws', 'github', 'okta'
    external_id VARCHAR(255) NOT NULL, -- Provider account ID
    display_name VARCHAR(255),
    credentials_encrypted JSONB, -- Encrypted API tokens/keys
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, provider, external_id)
);
```

**Key Features:**
- **Provider abstraction**: Supports multiple cloud/SaaS providers
- **Encrypted credentials**: Fernet encryption for API tokens
- **External mapping**: Links to provider-specific account IDs

### Resources (`resources`)

Cloud and SaaS resources across all providers.

```sql
CREATE TABLE resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    external_id VARCHAR(500) NOT NULL, -- Provider resource ID
    name VARCHAR(255),
    resource_type VARCHAR(100) NOT NULL, -- 'aws.s3.bucket', 'github.repo'
    provider VARCHAR(50) NOT NULL,
    region VARCHAR(100), -- Geographic region
    tags JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(account_id, external_id)
);

CREATE INDEX idx_resources_type ON resources(resource_type);
CREATE INDEX idx_resources_provider ON resources(provider);
CREATE INDEX idx_resources_tags ON resources USING GIN(tags);
```

**Key Features:**
- **Polymorphic resources**: Handles any provider resource type
- **Tagging support**: Flexible metadata storage
- **Geographic awareness**: Region-based organization

## 📈 Append-Only Tables

### Configuration Snapshots (`config_snapshots`)

**Immutable configuration history** - the cornerstone of Cerebro's auditability.

```sql
CREATE TABLE config_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
    captured_at TIMESTAMPTZ NOT NULL,
    normalized_config JSONB NOT NULL,
    config_hash VARCHAR(64) NOT NULL, -- SHA-256 of normalized_config
    collector_version VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_config_snapshots_captured ON config_snapshots(captured_at DESC);
CREATE INDEX idx_config_snapshots_hash ON config_snapshots(config_hash);
CREATE INDEX idx_config_snapshots_resource ON config_snapshots(resource_id, captured_at DESC);
```

**Key Features:**
- **Append-only**: Configurations are never updated, only inserted
- **Deduplication**: SHA-256 hash prevents storing identical configs
- **Temporal queries**: Full configuration history for any resource
- **Normalized format**: Standardized across providers for rule evaluation

### IAM Edges (`iam_edges`)

**Permission relationships** between principals and resources over time.

```sql  
CREATE TABLE iam_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID REFERENCES principals(id) ON DELETE CASCADE,
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
    permission VARCHAR(255) NOT NULL, -- 'github.repo.admin', 'aws.s3.read'
    via VARCHAR(100), -- 'direct', 'group_membership', 'role_assignment'
    effective_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ, -- NULL for permanent permissions
    is_admin BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_iam_edges_principal ON iam_edges(principal_id, effective_at DESC);
CREATE INDEX idx_iam_edges_resource ON iam_edges(resource_id, effective_at DESC);
CREATE INDEX idx_iam_edges_active ON iam_edges(effective_at, expires_at) WHERE expires_at IS NULL;
```

**Key Features:**
- **Temporal permissions**: Track when permissions were granted/revoked
- **Permission granularity**: Detailed permission strings per provider
- **Admin detection**: Flag high-privilege permissions
- **Expiration tracking**: Support for time-limited access

### Findings (`findings`)

**Security violations** with complete lifecycle tracking.

```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_id UUID REFERENCES resources(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES rules(id),
    principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    severity VARCHAR(20) NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
    status VARCHAR(20) DEFAULT 'open', -- 'open', 'suppressed', 'fixed'
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_status ON findings(status, severity);
CREATE INDEX idx_findings_resource ON findings(resource_id);
CREATE INDEX idx_findings_dates ON findings(first_seen DESC, last_seen DESC);
```

**Key Features:**
- **Lifecycle tracking**: First seen, last seen, status changes
- **Evidence preservation**: Complete context for each finding
- **Severity classification**: Risk-based prioritization
- **Audit trail**: Track who created or modified findings

## 🔐 Identity Management

### Principals (`principals`)

**Identities across providers** - users, service accounts, applications.

```sql
CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL, -- Provider principal ID
    display_name VARCHAR(255),
    email VARCHAR(255),
    principal_type VARCHAR(50) NOT NULL, -- 'user', 'service_account', 'group', 'application'
    is_human BOOLEAN DEFAULT false,
    attributes JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(account_id, external_id)
);

CREATE INDEX idx_principals_type ON principals(principal_type);
CREATE INDEX idx_principals_email ON principals(email);
CREATE INDEX idx_principals_human ON principals(is_human);
```

**Key Features:**
- **Cross-provider identity**: Unified view across AWS, GitHub, Okta, etc.
- **Human vs. non-human**: Critical distinction for security policies
- **Email correlation**: Key field for identity stitching
- **Flexible attributes**: Provider-specific metadata storage

### Identity Clusters (`identity_clusters`)

**Cross-provider identity correlation** with confidence scoring.

```sql
CREATE TABLE identity_clusters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    principal_ids JSONB NOT NULL, -- Array of principal UUIDs
    cluster_type VARCHAR(50), -- 'email_match', 'name_similarity', 'manual'
    confidence_score FLOAT CHECK (confidence_score >= 0 AND confidence_score <= 1),
    correlation_evidence JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_identity_clusters_org ON identity_clusters(org_id);
CREATE INDEX idx_identity_clusters_confidence ON identity_clusters(confidence_score DESC);
```

**Key Features:**
- **Identity stitching**: Links same person across providers
- **Confidence scoring**: ML-based correlation strength
- **Evidence tracking**: Detailed rationale for correlations
- **Manual override**: Support for admin-confirmed matches

## ⚙️ System Tables

### Rules (`rules`)

**Security rule definitions** with framework mappings.

```sql
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    providers JSONB NOT NULL, -- ['aws', 'github']
    resource_types JSONB NOT NULL, -- ['aws.s3.bucket']
    expression TEXT NOT NULL, -- CEL expression
    severity VARCHAR(20) NOT NULL,
    framework_mappings JSONB DEFAULT '{}', -- CIS, NIST, etc.
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_rules_active ON rules(is_active);
CREATE INDEX idx_rules_providers ON rules USING GIN(providers);
CREATE INDEX idx_rules_severity ON rules(severity);
```

### Users (`users`)

**Application users** with role-based access control.

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    scopes JSONB DEFAULT '[]', -- ['read:findings', 'write:rules']
    is_admin BOOLEAN DEFAULT false,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Audit Events (`audit_events`)

**Complete audit trail** of all user actions.

```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- 'CREATE_FINDING', 'UPDATE_RULE'
    resource_type VARCHAR(100),
    resource_id UUID,
    metadata JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_events_user ON audit_events(user_id, created_at DESC);
CREATE INDEX idx_audit_events_action ON audit_events(action, created_at DESC);
```

## 🔄 Migration Patterns

### Adding New Providers

When adding a new provider (e.g., Azure), follow this pattern:

```sql
-- 1. No schema changes needed - providers are dynamic
-- 2. Add sample resources
INSERT INTO resources (account_id, external_id, name, resource_type, provider)
VALUES (account_uuid, 'azure-resource-id', 'resource-name', 'azure.vm', 'azure');

-- 3. Add provider-specific rules
INSERT INTO rules (name, providers, resource_types, expression, severity)
VALUES (
    'Azure VM Without Encryption',
    '["azure"]',
    '["azure.vm"]', 
    'resource.resource_type == "azure.vm" && !config.encryption.enabled',
    'high'
);
```

### Schema Versioning

```sql
-- Migrations are handled by Alembic
-- Example: Adding new compliance framework

-- Migration: add_pci_dss_mappings.py
def upgrade():
    # Add PCI DSS column to rules table
    op.add_column('rules', sa.Column('pci_dss', sa.JSON(), nullable=True))

def downgrade():
    op.drop_column('rules', 'pci_dss')
```

## 🚀 Performance Optimizations

### Indexing Strategy

```sql
-- Time-based queries (most common)
CREATE INDEX idx_config_snapshots_time ON config_snapshots(captured_at DESC);
CREATE INDEX idx_findings_time ON findings(first_seen DESC);

-- Provider filtering
CREATE INDEX idx_resources_provider_type ON resources(provider, resource_type);

-- GIN indexes for JSON columns
CREATE INDEX idx_resources_tags ON resources USING GIN(tags);
CREATE INDEX idx_config_normalized ON config_snapshots USING GIN(normalized_config);

-- Partial indexes for active data
CREATE INDEX idx_findings_open ON findings(resource_id) WHERE status = 'open';
CREATE INDEX idx_rules_active ON rules(name) WHERE is_active = true;
```

### Partitioning Strategy

For large deployments, partition by time:

```sql
-- Partition config_snapshots by month
CREATE TABLE config_snapshots (
    LIKE config_snapshots INCLUDING DEFAULTS INCLUDING CONSTRAINTS
) PARTITION BY RANGE (captured_at);

CREATE TABLE config_snapshots_2024_01 PARTITION OF config_snapshots
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

## 🧪 Common Queries

### Temporal Analysis

```sql
-- Configuration drift detection
WITH config_changes AS (
    SELECT resource_id, captured_at, config_hash,
           LAG(config_hash) OVER (PARTITION BY resource_id ORDER BY captured_at) as prev_hash
    FROM config_snapshots
    WHERE captured_at >= NOW() - INTERVAL '30 days'
)
SELECT r.name, cc.captured_at
FROM config_changes cc
JOIN resources r ON cc.resource_id = r.id
WHERE cc.config_hash != cc.prev_hash;

-- Permission escalation detection  
SELECT p.email, ie.permission, ie.effective_at
FROM iam_edges ie
JOIN principals p ON ie.principal_id = p.id
WHERE ie.effective_at >= NOW() - INTERVAL '24 hours'
  AND ie.is_admin = true;
```

### Security Analysis

```sql
-- High-severity findings by provider
SELECT r.provider, f.severity, COUNT(*) as finding_count
FROM findings f
JOIN resources r ON f.resource_id = r.id  
WHERE f.status = 'open'
GROUP BY r.provider, f.severity
ORDER BY finding_count DESC;

-- Identity correlation analysis
SELECT ic.confidence_score, COUNT(*) as cluster_count
FROM identity_clusters ic
WHERE ic.confidence_score >= 0.8
GROUP BY ic.confidence_score
ORDER BY ic.confidence_score DESC;
```

This schema enables Cerebro to provide comprehensive security monitoring with full auditability and temporal analysis capabilities.

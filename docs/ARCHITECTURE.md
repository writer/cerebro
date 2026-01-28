# Cerebro Architecture

## Overview

Cerebro is a comprehensive security data platform for cloud and SaaS posture management. It combines data ingestion (native sync), storage (Snowflake), policy evaluation (Cedar-style), and intelligent security analysis (AI agents) into a unified platform.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CEREBRO PLATFORM                                      │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │
│  │   CLI       │    │   REST API  │    │  Webhooks   │    │ Scheduler   │               │
│  │  (Cobra)    │    │   (Chi)     │    │  Service    │    │  Service    │               │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘               │
│         │                  │                  │                  │                       │
│         └──────────────────┴──────────────────┴──────────────────┘                       │
│                                       │                                                  │
│                            ┌──────────▼──────────┐                                       │
│                            │    Application      │                                       │
│                            │    Container        │                                       │
│                            │   (internal/app)    │                                       │
│                            └──────────┬──────────┘                                       │
│                                       │                                                  │
│    ┌──────────────────────────────────┼──────────────────────────────────┐              │
│    │                                  │                                   │              │
│    ▼                                  ▼                                   ▼              │
│  ┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐              │
│  │  CORE SERVICES  │    │  FEATURE SERVICES   │    │  DATA LAYER         │              │
│  ├─────────────────┤    ├─────────────────────┤    ├─────────────────────┤              │
│  │ • Policy Engine │    │ • AI Agents         │    │ • Snowflake Client  │              │
│  │ • Scanner       │    │ • Ticketing (Jira,  │    │ • Finding Store     │              │
│  │ • Findings      │    │   Linear)           │    │ • Repositories      │              │
│  │ • Cache         │    │ • Identity/Access   │    │ • Assets            │              │
│  │                 │    │ • Attack Path       │    │                     │              │
│  │                 │    │ • Compliance        │    │                     │              │
│  │                 │    │ • Notifications     │    │                     │              │
│  └─────────────────┘    └─────────────────────┘    └─────────────────────┘              │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
           ▼                           ▼                           ▼
    ┌─────────────┐           ┌─────────────────┐          ┌─────────────┐
    │  Snowflake  │           │  Native Sync   │          │  External   │
    │  (Storage)  │◀──────────│  (Ingestion)   │          │  APIs       │
    └─────────────┘           └────────────────┘          └─────────────┘
           │                          │                           │
           │                          │                           │
    ┌──────┴──────┐           ┌───────┴────────┐          ┌───────┴───────┐
    │ Raw Tables  │           │ AWS/GCP/Azure  │          │ • Jira        │
    │ • aws_*     │           │ K8s            │          │ • Linear      │
    │ • gcp_*     │           │ SaaS (Okta,    │          │ • Slack       │
    │ • azure_*   │           │ CrowdStrike)   │          │ • PagerDuty   │
    │ • k8s_*     │           └────────────────┘          │ • Anthropic   │
    └─────────────┘                                       │ • OpenAI      │
                                                          └───────────────┘
```

## Component Deep Dive

### 1. Application Container (`internal/app`)

The `App` struct is the central dependency injection container that wires together all services:

```go
type App struct {
    Config *Config
    Logger *slog.Logger

    // Core services
    Snowflake *snowflake.Client
    Policy    *policy.Engine
    Findings  *findings.Store
    Scanner   *scanner.Scanner
    Cache     *cache.PolicyCache

    // Feature services
    Agents        *agents.AgentRegistry
    Ticketing     *ticketing.Service
    Identity      *identity.Service
    AttackPath    *attackpath.Graph
    Providers     *providers.Registry
    Webhooks      *webhooks.Service
    Notifications *notifications.Manager
    Scheduler     *scheduler.Scheduler

    // Repositories
    FindingsRepo      *snowflake.FindingRepository
    TicketsRepo       *snowflake.TicketRepository
    AuditRepo         *snowflake.AuditRepository
    SnowflakeFindings *findings.SnowflakeStore
}
```

**Initialization Flow:**
1. Load configuration from environment variables
2. Initialize Snowflake connection (optional - graceful degradation if unavailable)
3. Load policies from filesystem
4. Initialize all feature services with their dependencies
5. Start scheduled jobs if configured

### 2. Policy Engine (`internal/policy`)

The policy engine evaluates Cedar-style JSON policies against cloud assets.

**Policy Structure:**
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

**Key Operations:**
- `LoadPolicies(dir)` - Load all JSON policy files from a directory
- `Evaluate(ctx, req)` - Evaluate a principal/action/resource request
- `EvaluateAsset(ctx, asset)` - Check an asset against all policies

### 3. Scanner (`internal/scanner`)

High-performance parallel scanner for evaluating policies against large asset sets.

**Features:**
- Worker pool pattern with configurable concurrency
- Batch processing for memory efficiency
- Streaming mode for very large datasets
- Atomic counters for accurate statistics

```go
scanner := scanner.NewScanner(engine, scanner.ScanConfig{
    Workers:   10,    // Parallel workers
    BatchSize: 100,   // Assets per batch
}, logger)

result := scanner.ScanAssets(ctx, assets)
// result.Scanned, result.Violations, result.Findings
```

### 4. AI Agents (`internal/agents`)

LLM-powered security investigation agents with tool execution capabilities.

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                     Agent Registry                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
│  │   Agent     │   │   Agent     │   │   Agent     │       │
│  │ "security-  │   │ "incident-  │   │   ...       │       │
│  │  analyst"   │   │  responder" │   │             │       │
│  └──────┬──────┘   └──────┬──────┘   └─────────────┘       │
│         │                 │                                  │
│  ┌──────▼──────┐   ┌──────▼──────┐                          │
│  │  Anthropic  │   │   OpenAI    │  (LLM Providers)         │
│  │  Provider   │   │  Provider   │                          │
│  └─────────────┘   └─────────────┘                          │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    Security Tools                        ││
│  │  • query_snowflake  • list_findings  • get_asset        ││
│  │  • evaluate_policy  • search_logs    • ...              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

**Session Management:**
- Sessions track conversation history and context
- Memory system for agent context retention
- Tool execution with approval workflows

### 5. Identity & Access Review (`internal/identity`)

Comprehensive identity governance and access review system.

**Review Types:**
- User Access Reviews
- Service Account Reviews
- Privileged Access Reviews
- Entitlement Reviews
- Application Access Reviews

**Workflow:**
```
Draft → Scheduled → In Progress → Completed
                         ↓
                   [Review Items]
                         ↓
            Approve | Revoke | Modify | Escalate
```

**Risk Calculation:**
The `RiskCalculator` scores each review item based on:
- Admin/privileged access (+30)
- No MFA enabled (+20)
- No recent login (+15)
- Service account (+10)
- Cross-account access (+10)
- Long-standing access (+10)

### 6. Webhooks (`internal/webhooks`)

Event-driven webhook system for integrations.

**Event Types:**
- `finding.created` / `finding.resolved` / `finding.suppressed`
- `scan.completed`
- `review.started` / `review.completed`
- `attack_path.found`
- `ticket.created`

**Features:**
- HMAC-SHA256 signature verification
- Parallel delivery to multiple endpoints
- Delivery tracking and retry history
- Secret management for signed payloads

### 7. Compliance Framework (`internal/compliance`)

Pre-built compliance framework mappings.

**Supported Frameworks:**
- SOC 2 Type II
- CIS AWS Foundations
- CIS GCP Foundations
- PCI DSS
- HIPAA
- NIST 800-53

**Pre-Audit Capabilities:**
- Real-time compliance scoring
- Control status tracking (passing/failing/at-risk)
- Audit package export with evidence

## Data Flow

### 1. Asset Ingestion Flow
```
Native Sync → Snowflake Tables → Cerebro API → Policy Evaluation
```

### 2. Scan Flow
```
1. Scheduler triggers scan (or manual via API)
2. Fetch assets from Snowflake by table
3. Scanner evaluates all policies in parallel
4. Findings upserted to in-memory store
5. Sync to Snowflake for persistence
6. Notifications sent for critical/high findings
7. Webhooks emitted for integrations
```

### 3. Investigation Flow
```
1. User creates agent session with finding context
2. Agent receives messages via API
3. LLM generates responses with tool calls
4. Tools query Snowflake, findings, policies
5. Results returned to user through session
```

## Security Considerations

### Authentication & Authorization
- API does not include authentication by default (add via middleware)
- Rate limiting available via configuration
- Webhook signatures for payload verification

### Secrets Management
- All secrets via environment variables
- Webhook secrets never exposed in API responses
- API tokens for external services stored securely

### Data Protection
- Snowflake handles encryption at rest
- TLS for all external API calls
- No sensitive data in logs (structured logging)

## Scalability

### Horizontal Scaling
- Stateless API servers behind load balancer
- Shared Snowflake backend
- Redis/external cache for multi-instance deployments (future)

### Performance Optimizations
- Worker pool pattern for scanning
- Batch processing for large datasets
- In-memory caching for policies
- Connection pooling for Snowflake

## Extension Points

### Custom Providers
Implement the `Provider` interface:
```go
type Provider interface {
    Name() string
    Type() string
    Configure(ctx context.Context, config map[string]interface{}) error
    Schema() []Table
    Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error)
    Test(ctx context.Context) error
}
```

### Custom Policies
Add JSON files to the policies directory:
```
policies/
├── aws/
├── gcp/
├── azure/
└── kubernetes/
```

### Custom Notifiers
Implement the `Notifier` interface:
```go
type Notifier interface {
    Name() string
    Send(ctx context.Context, event Event) error
}
```

### Custom Tools for Agents
```go
tool := agents.Tool{
    Name:        "custom_tool",
    Description: "Description for LLM",
    Parameters:  map[string]interface{}{...},
    Handler:     func(ctx context.Context, args json.RawMessage) (string, error) {...},
}
```

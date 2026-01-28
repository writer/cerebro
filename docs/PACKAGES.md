# Cerebro Package Documentation

## Package Overview

```
cerebro/
├── cmd/cerebro/          # Application entrypoint
├── internal/
│   ├── agents/           # AI-powered security agents
│   │   └── providers/    # LLM provider implementations
│   ├── api/              # REST API server
│   ├── app/              # Application container & DI
│   ├── attackpath/       # Attack path analysis
│   ├── cache/            # Policy caching
│   ├── cli/              # CLI commands
│   ├── compliance/       # Compliance frameworks
│   ├── config/           # Configuration loading
│   ├── findings/         # Security findings store
│   ├── identity/         # Identity & access review
│   ├── metrics/          # Prometheus metrics
│   ├── notifications/    # Slack, PagerDuty notifications
│   ├── policy/           # Cedar-style policy engine
│   ├── providers/        # Custom data providers
│   ├── scanner/          # Parallel policy scanner
│   ├── scheduler/        # Job scheduler
│   ├── snowflake/        # Snowflake database client
│   ├── ticketing/        # Jira, Linear integration
│   └── webhooks/         # Webhook management
├── config/               # Optional configuration files
└── policies/             # Security policy definitions
```

---

## Core Packages

### `internal/app`

**Purpose:** Central application container with dependency injection.

**Key Types:**
```go
type App struct {
    Config    *Config
    Logger    *slog.Logger
    Snowflake *snowflake.Client
    Policy    *policy.Engine
    Findings  *findings.Store
    Scanner   *scanner.Scanner
    Cache     *cache.PolicyCache
    Agents    *agents.AgentRegistry
    // ... other services
}

type Config struct {
    Port                      int
    LogLevel                  string
    SnowflakeConnectionString string
    PoliciesPath              string
    AnthropicAPIKey           string
    // ... other config
}
```

**Functions:**
- `New(ctx context.Context) (*App, error)` - Create and initialize application
- `LoadConfig() *Config` - Load configuration from environment
- `(a *App) Close() error` - Graceful shutdown

**Usage:**
```go
app, err := app.New(context.Background())
if err != nil {
    log.Fatal(err)
}
defer app.Close()
```

---

### `internal/policy`

**Purpose:** Cedar-style policy engine for security evaluation.

**Key Types:**
```go
type Engine struct {
    policies map[string]*Policy
    mu       sync.RWMutex
}

type Policy struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Effect      string   `json:"effect"`      // "permit" or "forbid"
    Conditions  []string `json:"conditions"`  // e.g., "field != value"
    Severity    string   `json:"severity"`    // critical, high, medium, low
    Tags        []string `json:"tags"`
}

type EvalRequest struct {
    Principal map[string]interface{} `json:"principal"`
    Action    string                 `json:"action"`
    Resource  map[string]interface{} `json:"resource"`
    Context   map[string]interface{} `json:"context"`
}

type Finding struct {
    ID          string
    PolicyID    string
    PolicyName  string
    Severity    string
    Resource    map[string]interface{}
    Description string
}
```

**Functions:**
- `NewEngine() *Engine` - Create new policy engine
- `(e *Engine) LoadPolicies(dir string) error` - Load JSON policies from directory
- `(e *Engine) AddPolicy(p *Policy)` - Add a policy programmatically
- `(e *Engine) Evaluate(ctx, req) (*EvalResponse, error)` - Evaluate access request
- `(e *Engine) EvaluateAsset(ctx, asset) ([]Finding, error)` - Check asset against policies
- `(e *Engine) ListPolicies() []*Policy` - Get all policies
- `(e *Engine) GetPolicy(id) (*Policy, bool)` - Get policy by ID

**Condition Syntax:**
```
field == value   # Equality check
field != value   # Inequality check (violation)
```

---

### `internal/scanner`

**Purpose:** High-performance parallel policy scanner.

**Key Types:**
```go
type Scanner struct {
    engine    *policy.Engine
    workers   int
    batchSize int
    logger    *slog.Logger
}

type ScanConfig struct {
    Workers   int  // Default: 10
    BatchSize int  // Default: 100
}

type ScanResult struct {
    Findings   []policy.Finding
    Scanned    int64
    Violations int64
    Duration   time.Duration
    Errors     []string
}
```

**Functions:**
- `NewScanner(engine, cfg, logger) *Scanner` - Create scanner
- `(s *Scanner) ScanAssets(ctx, assets) *ScanResult` - Scan asset slice
- `(s *Scanner) StreamScan(ctx, assetCh, resultCh) *ScanResult` - Stream scanning

**Usage:**
```go
scanner := scanner.NewScanner(policyEngine, scanner.ScanConfig{
    Workers:   20,
    BatchSize: 200,
}, logger)

result := scanner.ScanAssets(ctx, assets)
fmt.Printf("Scanned %d, found %d violations\n", result.Scanned, result.Violations)
```

---

### `internal/findings`

**Purpose:** Security findings storage and management.

**Key Types:**
```go
type Finding struct {
    ID           string
    PolicyID     string
    PolicyName   string
    Severity     string
    Status       string  // open, resolved, suppressed
    ResourceID   string
    ResourceType string
    Resource     map[string]interface{}
    Description  string
    FirstSeen    time.Time
    LastSeen     time.Time
    ResolvedAt   *time.Time
}

type Store struct {
    findings map[string]*Finding
    mu       sync.RWMutex
}

type FindingFilter struct {
    Severity string
    Status   string
    PolicyID string
}

type Stats struct {
    Total      int
    BySeverity map[string]int
    ByStatus   map[string]int
    ByPolicy   map[string]int
}
```

**Interface:**
```go
type FindingStore interface {
    Upsert(ctx context.Context, pf policy.Finding) *Finding
    Get(id string) (*Finding, bool)
    List(filter FindingFilter) []*Finding
    Resolve(id string) bool
    Suppress(id string) bool
    Stats() Stats
    Sync(ctx context.Context) error
}
```

**Functions:**
- `NewStore() *Store` - Create in-memory store
- `NewSnowflakeStore(db, database, schema) *SnowflakeStore` - Create persistent store

---

### `internal/snowflake`

**Purpose:** Snowflake database client and repositories.

**Key Types:**
```go
type Client struct {
    db       *sql.DB
    database string
    schema   string
}

type QueryResult struct {
    Columns []string
    Rows    []map[string]interface{}
    Count   int
}

type AssetFilter struct {
    Limit   int
    Account string
    Region  string
}
```

**Functions:**
- `NewClient(connStr, database, schema) (*Client, error)` - Create client
- `(c *Client) Ping(ctx) error` - Test connection
- `(c *Client) Query(ctx, sql, args...) (*QueryResult, error)` - Execute query
- `(c *Client) ListTables(ctx) ([]string, error)` - List available tables
- `(c *Client) GetAssets(ctx, table, filter) ([]map[string]interface{}, error)` - Get assets
- `(c *Client) GetAssetByID(ctx, table, id) (map[string]interface{}, error)` - Get single asset
- `(c *Client) DB() *sql.DB` - Get underlying connection
- `(c *Client) Close() error` - Close connection

**Repositories:**
```go
type FindingRepository struct { /* Snowflake finding persistence */ }
type TicketRepository struct { /* Ticket persistence */ }
type AuditRepository struct { /* Audit log persistence */ }
```

---

## Feature Packages

### `internal/agents`

**Purpose:** AI-powered security investigation agents.

**Key Types:**
```go
type Agent struct {
    ID          string
    Name        string
    Description string
    Provider    LLMProvider
    Tools       []Tool
    Memory      *Memory
}

type LLMProvider interface {
    Complete(ctx, messages, tools) (*Response, error)
    Stream(ctx, messages, tools) (<-chan StreamEvent, error)
}

type Tool struct {
    Name             string
    Description      string
    Parameters       map[string]interface{}
    Handler          ToolHandler
    RequiresApproval bool
}

type Session struct {
    ID        string
    AgentID   string
    UserID    string
    Status    string  // active, completed, pending_approval
    Messages  []Message
    Context   SessionContext
    CreatedAt time.Time
}

type Message struct {
    Role      string  // system, user, assistant, tool
    Content   string
    ToolCalls []ToolCall
}
```

**Registry Functions:**
- `NewAgentRegistry() *AgentRegistry`
- `(r *AgentRegistry) RegisterAgent(agent *Agent)`
- `(r *AgentRegistry) GetAgent(id) (*Agent, bool)`
- `(r *AgentRegistry) ListAgents() []*Agent`
- `(r *AgentRegistry) CreateSession(agentID, userID, ctx) (*Session, error)`
- `(r *AgentRegistry) GetSession(id) (*Session, bool)`
- `(r *AgentRegistry) UpdateSession(session)`

**Providers (`internal/agents/providers`):**
```go
// Anthropic Claude
type AnthropicProvider struct { /* ... */ }
func NewAnthropicProvider(cfg AnthropicConfig) *AnthropicProvider

// OpenAI GPT
type OpenAIProvider struct { /* ... */ }
func NewOpenAIProvider(cfg OpenAIConfig) *OpenAIProvider
```

---

### `internal/identity`

**Purpose:** Identity governance and access review management.

**Key Types:**
```go
type AccessReview struct {
    ID          string
    Name        string
    Type        ReviewType      // user_access, service_account, privileged, etc.
    Status      ReviewStatus    // draft, scheduled, in_progress, completed
    Scope       ReviewScope
    Reviewers   []string
    Items       []ReviewItem
    Stats       ReviewStats
    DueAt       *time.Time
}

type ReviewItem struct {
    ID          string
    Principal   Principal
    Access      []AccessGrant
    RiskScore   int
    RiskFactors []string
    Decision    *ReviewDecision
}

type Principal struct {
    ID        string
    Type      string  // user, service_account, group
    Name      string
    Email     string
    Provider  string
    LastLogin *time.Time
}

type ReviewDecision struct {
    Action    DecisionAction  // approve, revoke, modify, escalate, defer
    Reviewer  string
    Comment   string
    DecidedAt time.Time
}
```

**Service Functions:**
- `NewService() *Service`
- `(s *Service) CreateReview(ctx, review) (*AccessReview, error)`
- `(s *Service) GetReview(ctx, id) (*AccessReview, bool)`
- `(s *Service) ListReviews(ctx, status) []*AccessReview`
- `(s *Service) StartReview(ctx, id) error`
- `(s *Service) AddReviewItem(ctx, reviewID, item) error`
- `(s *Service) RecordDecision(ctx, itemID, decision) error`

**Stale Access Detection (`stale_access.go`):**
```go
type StaleAccessDetector struct { /* ... */ }
type StaleAccessFinding struct {
    Type           StaleAccessType
    Principal      string
    Provider       string
    LastActivity   time.Time
    DaysInactive   int
    RiskScore      int
    Recommendation string
}

func NewStaleAccessDetector(thresholds) *StaleAccessDetector
func (d *Detector) DetectStaleUsers(ctx, users) []StaleAccessFinding
func (d *Detector) DetectUnusedAccessKeys(ctx, creds) []StaleAccessFinding
func (d *Detector) DetectStaleServiceAccounts(ctx, accounts) []StaleAccessFinding
```

**Report Generation (`report.go`):**
```go
type ReportGenerator struct { /* ... */ }
type IdentityReport struct {
    Summary         IdentitySummary
    UsersByProvider map[string]int
    RiskDistribution map[string]int
    // ...
}

func NewReportGenerator() *ReportGenerator
func (g *Generator) GenerateReport(ctx, data) (*IdentityReport, error)
```

---

### `internal/webhooks`

**Purpose:** Event-driven webhook delivery system.

**Key Types:**
```go
type EventType string
const (
    EventFindingCreated    EventType = "finding.created"
    EventFindingResolved   EventType = "finding.resolved"
    EventScanCompleted     EventType = "scan.completed"
    EventReviewStarted     EventType = "review.started"
    EventAttackPathFound   EventType = "attack_path.found"
    EventTicketCreated     EventType = "ticket.created"
)

type Webhook struct {
    ID        string
    URL       string
    Events    []EventType
    Secret    string
    Enabled   bool
    CreatedAt time.Time
}

type Event struct {
    ID        string
    Type      EventType
    Timestamp time.Time
    Data      map[string]interface{}
}

type Delivery struct {
    ID             string
    WebhookID      string
    EventType      EventType
    ResponseStatus int
    Success        bool
    DurationMs     int64
}
```

**Service Functions:**
- `NewService() *Service`
- `(s *Service) RegisterWebhook(url, events, secret) *Webhook`
- `(s *Service) GetWebhook(id) (*Webhook, bool)`
- `(s *Service) ListWebhooks() []*Webhook`
- `(s *Service) DeleteWebhook(id) bool`
- `(s *Service) DisableWebhook(id) bool`
- `(s *Service) Emit(ctx, eventType, data)` - Send to all subscribers
- `(s *Service) GetDeliveries(webhookID, limit) []Delivery`

**Helper Functions:**
```go
// Emit common events
func (s *Service) EmitFindingCreated(ctx, findingID, policyID, severity, resource)
func (s *Service) EmitFindingResolved(ctx, findingID)
func (s *Service) EmitScanCompleted(ctx, scanned, violations, duration)
func (s *Service) EmitAttackPathFound(ctx, pathID, severity, steps)

// Signature verification (for incoming webhooks)
func VerifySignature(payload []byte, signature, secret string) bool
```

**Interface:**
```go
type EventEmitter interface {
    Emit(ctx context.Context, eventType EventType, data map[string]interface{})
}

// NoopEmitter for when webhooks disabled
type NoopEmitter struct{}
```

---

### `internal/ticketing`

**Purpose:** Integration with ticketing systems (Jira, Linear).

**Key Types:**
```go
type Ticket struct {
    ID          string
    ExternalID  string
    Provider    string
    Title       string
    Description string
    Status      string
    Priority    string
    Type        string  // finding, incident, task
    FindingIDs  []string
    Assignee    string
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

type TicketUpdate struct {
    Status   string
    Assignee string
    Priority string
}

type Comment struct {
    Body      string
    Author    string
    CreatedAt time.Time
}
```

**Provider Interface:**
```go
type Provider interface {
    Name() string
    CreateTicket(ctx, ticket) (*Ticket, error)
    GetTicket(ctx, id) (*Ticket, error)
    UpdateTicket(ctx, id, update) (*Ticket, error)
    ListTickets(ctx, filter) ([]*Ticket, error)
    AddComment(ctx, ticketID, comment) error
    Close(ctx, ticketID, resolution) error
}
```

**Service Functions:**
- `NewService() *Service`
- `(s *Service) RegisterProvider(provider)`
- `(s *Service) Primary() Provider` - Get primary ticketing provider
- `(s *Service) CreateTicket(ctx, ticket) (*Ticket, error)` - Create via primary

**Providers:**
```go
// Jira
func NewJiraProvider(cfg JiraConfig) *JiraProvider

// Linear
func NewLinearProvider(cfg LinearConfig) *LinearProvider
```

---

### `internal/attackpath`

**Purpose:** Attack path analysis and visualization.

**Key Types:**
```go
type Graph struct {
    nodes map[string]*Node
    edges map[string][]*Edge
    mu    sync.RWMutex
}

type Node struct {
    ID         string
    Type       string  // ec2_instance, iam_role, s3_bucket, etc.
    Name       string
    Properties map[string]interface{}
    RiskScore  int
}

type Edge struct {
    From       string
    To         string
    Type       string  // can_assume, has_access, network_path, etc.
    Properties map[string]interface{}
}

type Path struct {
    ID       string
    Nodes    []string
    Edges    []string
    Severity string
    RiskScore int
}
```

**Functions:**
- `NewGraph() *Graph`
- `(g *Graph) AddNode(node *Node)`
- `(g *Graph) AddEdge(edge *Edge)`
- `(g *Graph) GetNode(id) (*Node, bool)`
- `(g *Graph) GetNeighbors(nodeID) []*Node`
- `(g *Graph) GetAllNodes() []*Node`

**Path Finder:**
```go
type PathFinder struct {
    graph     *Graph
    maxDepth  int
    hvTargets []string
}

func NewPathFinder(graph *Graph, maxDepth int) *PathFinder
func (pf *PathFinder) SetHighValueTargets(targets []string)
func (pf *PathFinder) FindPaths(ctx context.Context) []*Path
```

---

### `internal/compliance`

**Purpose:** Compliance framework management and reporting.

**Key Types:**
```go
type Framework struct {
    ID          string
    Name        string
    Version     string
    Description string
    Controls    []Control
}

type Control struct {
    ID          string
    Title       string
    Description string
    PolicyIDs   []string  // Policies that map to this control
}

type ComplianceReport struct {
    FrameworkID   string
    FrameworkName string
    GeneratedAt   string
    Summary       ComplianceSummary
    Controls      []ControlStatus
}

type ComplianceSummary struct {
    TotalControls    int
    PassingControls  int
    FailingControls  int
    ComplianceScore  float64
}

type ControlStatus struct {
    ControlID string
    Status    string  // passing, failing
}
```

**Functions:**
- `GetFrameworks() []*Framework` - List all frameworks
- `GetFramework(id) *Framework` - Get specific framework

**Supported Frameworks:**
- SOC 2 Type II
- CIS AWS Foundations Benchmark
- CIS GCP Foundations Benchmark
- PCI DSS
- HIPAA
- NIST 800-53

---

### `internal/notifications`

**Purpose:** Alert notifications via Slack, PagerDuty.

**Key Types:**
```go
type Event struct {
    Type     string  // e.g., "finding.created", "scan.completed"
    Title    string
    Message  string
    Severity string
    Data     map[string]interface{}
}

type Notifier interface {
    Name() string
    Send(ctx context.Context, event Event) error
}

type Manager struct {
    notifiers []Notifier
}
```

**Functions:**
- `NewManager() *Manager`
- `(m *Manager) AddNotifier(n Notifier)`
- `(m *Manager) ListNotifiers() []string`
- `(m *Manager) Send(ctx, event) error` - Send to all notifiers

**Notifiers:**
```go
// Slack
type SlackNotifier struct { /* ... */ }
func NewSlackNotifier(cfg SlackConfig) *SlackNotifier

// PagerDuty
type PagerDutyNotifier struct { /* ... */ }
func NewPagerDutyNotifier(cfg PagerDutyConfig) *PagerDutyNotifier
```

---

### `internal/scheduler`

**Purpose:** Job scheduling for periodic tasks.

**Key Types:**
```go
type Scheduler struct {
    jobs   map[string]*Job
    logger *slog.Logger
    mu     sync.RWMutex
}

type Job struct {
    Name     string
    Interval time.Duration
    Fn       func(context.Context) error
    Enabled  bool
    Running  bool
    LastRun  time.Time
    NextRun  time.Time
}

type Status struct {
    Running    bool
    JobCount   int
    LastUpdate time.Time
}
```

**Functions:**
- `NewScheduler(logger) *Scheduler`
- `(s *Scheduler) AddJob(name, interval, fn)`
- `(s *Scheduler) Start(ctx)` - Start scheduler loop
- `(s *Scheduler) Stop()` - Stop scheduler
- `(s *Scheduler) RunNow(name) error` - Trigger job immediately
- `(s *Scheduler) EnableJob(name)`
- `(s *Scheduler) DisableJob(name)`
- `(s *Scheduler) ListJobs() []*Job`
- `(s *Scheduler) Status() *Status`

---

### `internal/cache`

**Purpose:** In-memory caching for policy evaluations.

**Key Types:**
```go
type PolicyCache struct {
    cache   map[string]*cacheEntry
    maxSize int
    ttl     time.Duration
    mu      sync.RWMutex
    stats   CacheStats
}

type CacheStats struct {
    Size   int
    Hits   int64
    Misses int64
}
```

**Functions:**
- `NewPolicyCache(maxSize int, ttl time.Duration) *PolicyCache`
- `(c *PolicyCache) Get(key string) (interface{}, bool)`
- `(c *PolicyCache) Set(key string, value interface{})`
- `(c *PolicyCache) Delete(key string)`
- `(c *PolicyCache) Clear()`
- `(c *PolicyCache) Stats() CacheStats`

---

### `internal/providers`

**Purpose:** Custom data providers for non-native sources.

**Provider Interface:**
```go
type Provider interface {
    Name() string
    Type() string  // security, identity, infrastructure
    Configure(ctx context.Context, config map[string]interface{}) error
    Schema() []Table
    Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error)
    Test(ctx context.Context) error
}

type Table struct {
    Name    string
    Columns []Column
}

type SyncOptions struct {
    FullSync    bool
    Incremental bool
    Tables      []string
}

type SyncResult struct {
    RowsSynced int64
    Duration   time.Duration
    Errors     []string
}
```

**Registry:**
```go
type Registry struct {
    providers map[string]Provider
    mu        sync.RWMutex
}

func NewRegistry() *Registry
func (r *Registry) Register(p Provider)
func (r *Registry) Get(name string) (Provider, bool)
func (r *Registry) List() []Provider
func (r *Registry) Configure(ctx, name, config) error
```

**Implementations:**
```go
// CrowdStrike Falcon
type CrowdStrikeProvider struct { /* ... */ }
func NewCrowdStrikeProvider() *CrowdStrikeProvider

// Okta
type OktaProvider struct { /* ... */ }
func NewOktaProvider() *OktaProvider
```

---

### `internal/metrics`

**Purpose:** Prometheus metrics exposition.

**Functions:**
- `Handler() http.Handler` - Prometheus metrics handler
- Automatic instrumentation via middleware

**Metrics:**
- `http_requests_total` - Total HTTP requests
- `http_request_duration_seconds` - Request latency histogram
- `findings_total` - Total findings by severity/status
- `scan_duration_seconds` - Scan execution time

---

## CLI Package

### `internal/cli`

**Commands:**
```bash
cerebro serve                        # Start API server
cerebro sync                         # Sync data via native scanners
cerebro policy list                  # List loaded policies
cerebro policy validate              # Validate policy files
cerebro policy test <id> <asset>     # Test policy against asset
cerebro query <sql>                  # Execute Snowflake query
cerebro bootstrap                    # Initialize database schema
```

**Implementation Files:**
- `root.go` - Root command and subcommand registration
- `serve.go` - API server command
- `sync.go` - Native sync command
- `policy.go` - Policy management commands
- `query.go` - Direct query command
- `bootstrap.go` - Database initialization

---

## API Package

### `internal/api`

**Server:**
```go
type Server struct {
    app    *app.App
    router *chi.Mux
}

func NewServer(application *app.App) *Server
func (s *Server) Run() error
func (s *Server) ServeHTTP(w, r)
```

**Middleware (`middleware.go`):**
- Request ID injection
- Real IP detection
- Structured logging
- Panic recovery
- Request timeout
- Compression
- Metrics collection

**Rate Limiting (`ratelimit.go`):**
```go
type RateLimitConfig struct {
    RequestsPerWindow int
    Window            time.Duration
    Enabled           bool
}

func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler
```

**Metrics (`metrics.go`):**
```go
func MetricsMiddleware(next http.Handler) http.Handler
```

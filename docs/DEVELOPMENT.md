# Cerebro Development Guide

## Prerequisites

- Go 1.23+
- Docker & Docker Compose (optional)
- Snowflake account (for full functionality)
- Make

## Getting Started

### Clone and Setup

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro

# Install dependencies
make setup
# Or: go mod download

# Copy environment template
cp .env.example .env
# Edit .env with your configuration
```

### Running Locally

```bash
# Development mode with hot reload (if using air)
make dev

# Or run directly
go run ./cmd/cerebro serve

# With specific port
API_PORT=9090 go run ./cmd/cerebro serve
```

### Running Tests

```bash
# All tests
make test

# With coverage
go test -v -cover ./...

# Specific package
go test -v ./internal/policy/...

# With race detection
go test -race ./...
```

### Building

```bash
# Build binary
make build
# Output: bin/cerebro

# Build Docker image
make docker-build

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o bin/cerebro-linux ./cmd/cerebro
GOOS=darwin GOARCH=arm64 go build -o bin/cerebro-darwin ./cmd/cerebro
```

---

## Project Structure

```
cerebro/
├── bin/                    # Build output
├── cmd/
│   └── cerebro/
│       └── main.go         # Application entrypoint
├── config/                 # Optional local configuration files
├── docs/                   # Documentation
├── internal/               # Private packages
│   ├── agents/             # AI agent system
│   │   ├── agent.go        # Agent types and registry
│   │   ├── tools.go        # Security tools for agents
│   │   └── providers/      # LLM provider implementations
│   ├── api/                # REST API
│   │   ├── server.go       # Server and routes
│   │   ├── middleware.go   # HTTP middleware
│   │   ├── ratelimit.go    # Rate limiting
│   │   └── metrics.go      # Prometheus metrics
│   ├── app/                # Application container
│   │   └── app.go          # DI and initialization
│   ├── attackpath/         # Attack path analysis
│   ├── cache/              # Policy cache
│   ├── cli/                # CLI commands
│   ├── compliance/         # Compliance frameworks
│   ├── config/             # Configuration loading
│   ├── findings/           # Findings storage
│   ├── identity/           # Access review system
│   ├── metrics/            # Prometheus metrics
│   ├── notifications/      # Alert notifications
│   ├── policy/             # Policy engine
│   ├── providers/          # Custom data providers
│   ├── scanner/            # Parallel scanner
│   ├── scheduler/          # Job scheduler
│   ├── snowflake/          # Database client
│   ├── ticketing/          # Jira/Linear integration
│   └── webhooks/           # Webhook system
├── policies/               # Security policies
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── kubernetes/
├── .env.example            # Environment template
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## Code Style

### Go Conventions

- Follow [Effective Go](https://golang.org/doc/effective_go)
- Use `gofmt` / `goimports` for formatting
- Run `golangci-lint` before committing

### Package Guidelines

1. **Keep packages focused** - Single responsibility
2. **Avoid circular imports** - Use interfaces
3. **Export minimally** - Only public API
4. **Document exported types** - GoDoc comments

### Error Handling

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to query snowflake: %w", err)
}

// Good: Use structured logging
logger.Error("query failed", "error", err, "table", tableName)

// Avoid: Ignoring errors
result, _ := doSomething()  // Bad
```

### Concurrency

```go
// Use sync.RWMutex for read-heavy data
type Store struct {
    data map[string]interface{}
    mu   sync.RWMutex
}

func (s *Store) Get(key string) (interface{}, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    v, ok := s.data[key]
    return v, ok
}

// Use channels for pipeline patterns
func process(ctx context.Context, input <-chan Item) <-chan Result {
    output := make(chan Result)
    go func() {
        defer close(output)
        for item := range input {
            select {
            case <-ctx.Done():
                return
            case output <- transform(item):
            }
        }
    }()
    return output
}
```

---

## Adding New Features

### Adding a New API Endpoint

1. **Add handler to `internal/api/server.go`:**

```go
func (s *Server) setupRoutes() {
    // ... existing routes ...
    
    r.Route("/api/v1/newfeature", func(r chi.Router) {
        r.Get("/", s.listNewFeature)
        r.Post("/", s.createNewFeature)
        r.Get("/{id}", s.getNewFeature)
    })
}

func (s *Server) listNewFeature(w http.ResponseWriter, r *http.Request) {
    // Implementation
    s.json(w, http.StatusOK, result)
}
```

2. **Add tests to `internal/api/server_test.go`**

### Adding a New Policy Condition

1. **Update `internal/policy/cedar.go`:**

```go
func evaluateCondition(condition string, asset map[string]interface{}) bool {
    // Add new condition syntax
    if strings.Contains(condition, " contains ") {
        parts := strings.SplitN(condition, " contains ", 2)
        field := strings.TrimSpace(parts[0])
        expected := strings.TrimSpace(parts[1])
        if val, ok := asset[field].([]interface{}); ok {
            for _, v := range val {
                if fmt.Sprintf("%v", v) == expected {
                    return true
                }
            }
        }
        return false
    }
    // ... existing conditions ...
}
```

2. **Add tests to `internal/policy/cedar_test.go`**

### Adding a New Notification Provider

1. **Create `internal/notifications/newprovider.go`:**

```go
package notifications

import (
    "context"
)

type NewProviderConfig struct {
    APIKey  string
    BaseURL string
}

type NewProviderNotifier struct {
    config NewProviderConfig
}

func NewNewProviderNotifier(cfg NewProviderConfig) *NewProviderNotifier {
    return &NewProviderNotifier{config: cfg}
}

func (n *NewProviderNotifier) Name() string {
    return "newprovider"
}

func (n *NewProviderNotifier) Send(ctx context.Context, event Event) error {
    // Implementation
    return nil
}
```

2. **Register in `internal/app/app.go`:**

```go
func (a *App) initNotifications() {
    // ... existing notifiers ...
    
    if a.Config.NewProviderAPIKey != "" {
        np := notifications.NewNewProviderNotifier(notifications.NewProviderConfig{
            APIKey: a.Config.NewProviderAPIKey,
        })
        a.Notifications.AddNotifier(np)
    }
}
```

### Adding a New LLM Provider

1. **Create `internal/agents/providers/newllm.go`:**

```go
package providers

import (
    "context"
    "github.com/writer/cerebro/internal/agents"
)

type NewLLMConfig struct {
    APIKey string
    Model  string
}

type NewLLMProvider struct {
    config NewLLMConfig
}

func NewNewLLMProvider(cfg NewLLMConfig) *NewLLMProvider {
    return &NewLLMProvider{config: cfg}
}

func (p *NewLLMProvider) Complete(ctx context.Context, messages []agents.Message, tools []agents.Tool) (*agents.Response, error) {
    // Implementation
    return &agents.Response{}, nil
}

func (p *NewLLMProvider) Stream(ctx context.Context, messages []agents.Message, tools []agents.Tool) (<-chan agents.StreamEvent, error) {
    // Implementation
    return nil, nil
}
```

### Adding a New Data Provider

1. **Create `internal/providers/newprovider.go`:**

```go
package providers

import (
    "context"
)

type NewDataProvider struct {
    config map[string]interface{}
}

func NewNewDataProvider() *NewDataProvider {
    return &NewDataProvider{}
}

func (p *NewDataProvider) Name() string {
    return "newprovider"
}

func (p *NewDataProvider) Type() string {
    return "security"
}

func (p *NewDataProvider) Configure(ctx context.Context, config map[string]interface{}) error {
    p.config = config
    return nil
}

func (p *NewDataProvider) Schema() []Table {
    return []Table{
        {Name: "newprovider_resources", Columns: []Column{...}},
    }
}

func (p *NewDataProvider) Sync(ctx context.Context, opts SyncOptions) (*SyncResult, error) {
    // Implementation
    return &SyncResult{}, nil
}

func (p *NewDataProvider) Test(ctx context.Context) error {
    // Implementation
    return nil
}
```

---

## Deep Research Agent (Code-to-Cloud)

The Deep Research Agent bridges the gap between Cloud Security Context and Source Code Analysis. To use this feature effectively in development, you need access to both:

1.  **Source Code**: Authenticated via `GITHUB_TOKEN` or local `gh` CLI.
2.  **Cloud Context**: Authenticated via AWS SSO.

### AWS SSO Setup

To enable the agent's cloud context capabilities in local development:

1.  **Configure AWS SSO Profile**:
    ```bash
    aws configure sso
    # Session name: writer
    # Start URL: https://d-9067fc8d21.awsapps.com/start/
    # Region: us-east-1
    # Registration scopes: sso:account:access
    # Profile name: cerebro-prod
    ```

2.  **Verify Access**:
    ```bash
    aws sso login --profile cerebro-prod
    aws sts get-caller-identity --profile cerebro-prod
    ```

3.  **Run Agent**:
    Ensure your local environment uses this profile when running the agent.
    ```bash
    export AWS_PROFILE=cerebro-prod
    make run
    ```

### GCP SSO Setup

To enable the agent's GCP cloud context capabilities:

1.  **Authenticate**:
    ```bash
    # Update gcloud CLI credentials
    gcloud auth login
    
    # Update Application Default Credentials (ADC) for libraries
    gcloud auth application-default login
    ```

2.  **Verify Access**:
    ```bash
    # Check active project
    gcloud config list project
    
    # Verify storage access (example)
    gcloud storage buckets list --limit=1
    ```

### Verification

Run the verification script to ensure Code, AWS, and GCP access are configured:

```bash
# Verify GitHub access
gh repo view writer/cerebro >/dev/null && echo "GitHub OK"

# Verify AWS access
aws sts get-caller-identity --profile cerebro-prod >/dev/null && echo "AWS OK"

# Verify GCP access (if using GCP features)
gcloud storage buckets list --limit=1 >/dev/null && echo "GCP OK"
```

---

## Testing

### Unit Tests

```go
// internal/policy/cedar_test.go
func TestEvaluateCondition(t *testing.T) {
    tests := []struct {
        name      string
        condition string
        asset     map[string]interface{}
        want      bool
    }{
        {
            name:      "equality match",
            condition: "status == active",
            asset:     map[string]interface{}{"status": "active"},
            want:      true,
        },
        {
            name:      "inequality violation",
            condition: "encryption != true",
            asset:     map[string]interface{}{"encryption": false},
            want:      true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := evaluateCondition(tt.condition, tt.asset)
            if got != tt.want {
                t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

```go
// internal/api/server_test.go
func TestHealthEndpoint(t *testing.T) {
    // Setup
    app := &app.App{
        Config: &app.Config{Port: 8080},
        Logger: slog.Default(),
        Policy: policy.NewEngine(),
        // ...
    }
    server := NewServer(app)

    // Test
    req := httptest.NewRequest("GET", "/health", nil)
    w := httptest.NewRecorder()
    server.ServeHTTP(w, req)

    // Assert
    if w.Code != http.StatusOK {
        t.Errorf("expected 200, got %d", w.Code)
    }
}
```

### Test Helpers

```go
// internal/testutil/helpers.go
package testutil

func NewTestApp(t *testing.T) *app.App {
    t.Helper()
    return &app.App{
        Config:   &app.Config{Port: 0},
        Logger:   slog.Default(),
        Policy:   policy.NewEngine(),
        Findings: findings.NewStore(),
        // ...
    }
}

func NewTestAsset(table string, data map[string]interface{}) map[string]interface{} {
    asset := map[string]interface{}{
        "_cq_table": table,
        "_cq_id":    uuid.New().String(),
    }
    for k, v := range data {
        asset[k] = v
    }
    return asset
}
```

---

## Debugging

### Logging

```go
// Enable debug logging
export LOG_LEVEL=debug

// Structured logging
logger.Debug("processing asset",
    "table", tableName,
    "id", assetID,
    "policies", len(policies),
)
```

### Profiling

```go
// Add pprof endpoints (for development only)
import _ "net/http/pprof"

// Access at:
// http://localhost:8080/debug/pprof/
// http://localhost:8080/debug/pprof/goroutine
// http://localhost:8080/debug/pprof/heap

// Generate CPU profile
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30
```

### Debugging Snowflake Queries

```go
// Log all queries
logger.Debug("executing query", "sql", query, "args", args)

// Test queries via CLI
go run ./cmd/cerebro query "SELECT * FROM aws_s3_buckets LIMIT 5"
```

---

## Makefile Targets

```makefile
# Development
make dev          # Run with hot reload
make run          # Run directly
make test         # Run all tests
make test-cover   # Run tests with coverage
make lint         # Run linters

# Building
make build        # Build binary
make docker-build # Build Docker image

# Utilities
make setup        # Install dependencies
make clean        # Clean build artifacts
make fmt          # Format code
make vet          # Run go vet

# Policy management
make policy-list     # List policies
make policy-validate # Validate policies
```

---

## CI/CD

### GitHub Actions Example

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      
      - name: Install dependencies
        run: go mod download
      
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: coverage.out

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: golangci/golangci-lint-action@v3
        with:
          version: latest

  build:
    runs-on: ubuntu-latest
    needs: [test, lint]
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      
      - name: Build
        run: make build
      
      - name: Build Docker image
        run: docker build -t cerebro:${{ github.sha }} .
```

---

## Common Issues

### Snowflake Connection Errors

**Error:** `failed to connect: authentication error`

**Solution:**
1. Verify connection string format
2. Check account name includes region (e.g., `myaccount.us-east-1`)
3. Ensure user has required grants

### Policy Not Loading

**Error:** `failed to load policies: parse error`

**Solution:**
1. Validate JSON syntax
2. Check required fields (`id`, `name`, `effect`, `conditions`, `severity`)
3. Ensure file extension is `.json`

### Rate Limiting Issues

**Error:** `429 Too Many Requests`

**Solution:**
1. Increase `RATE_LIMIT_REQUESTS`
2. Increase `RATE_LIMIT_WINDOW`
3. Implement client-side backoff

### AI Agent Not Responding

**Error:** `no LLM provider configured`

**Solution:**
1. Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
2. Verify API key is valid
3. Check API quota/limits

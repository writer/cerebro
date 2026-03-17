// Package app provides the main application container that wires together all
// Cerebro services and manages their lifecycle. This is the central dependency
// injection point for the application.
//
// The App struct holds references to all services organized into categories:
//
// Core Services:
//   - Snowflake: Data warehouse client for asset and findings storage
//   - Policy: Security policy engine for evaluating cloud resources
//   - Findings: Durable findings store with semantic and exact-ID deduplication
//   - Scanner: Asset scanner that applies policies to cloud resources
//   - Cache: Policy evaluation cache for performance
//
// Feature Services:
//   - Agents: AI-powered security investigation agents (Anthropic/OpenAI)
//   - Ticketing: Integration with Jira, Linear for finding tracking
//   - Identity: Stale access detection and identity analytics
//   - AttackPath: Attack path analysis and graph queries
//   - Providers: Custom data source integrations (CrowdStrike, Snyk, etc.)
//   - Notifications: Slack, PagerDuty, webhook notifications
//   - Scheduler: Periodic job scheduling for scans and syncs
//
// Security Services:
//   - RBAC: Role-based access control and multi-tenancy
//   - ThreatIntel: Threat intelligence feed management
//   - RuntimeDetect: Real-time threat detection engine
//   - RuntimeRespond: Automated response and containment
//   - Lineage: Deployment lineage tracking
//   - Remediation: Auto-remediation playbooks
//
// The New() function initializes all services based on environment configuration.
// Services gracefully handle missing configuration (e.g., no Snowflake connection).
//
//go:generate sh -c "cd ../.. && go run ./scripts/generate_config_docs/main.go"
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/apiauth"
	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/cache"
	"github.com/evalops/cerebro/internal/compliance"
	"github.com/evalops/cerebro/internal/dspm"
	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/executionstore"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graph/builders"
	"github.com/evalops/cerebro/internal/graphingest"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/identity"
	"github.com/evalops/cerebro/internal/lineage"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/providers"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/scanner"
	"github.com/evalops/cerebro/internal/scheduler"
	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/ticketing"
	"github.com/evalops/cerebro/internal/warehouse"
	"github.com/evalops/cerebro/internal/webhooks"
)

type retentionCleaner interface {
	CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	CleanupAgentData(ctx context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error)
	CleanupGraphData(ctx context.Context, olderThan time.Time) (pathsDeleted, edgesDeleted, nodesDeleted int64, err error)
	CleanupAccessReviewData(ctx context.Context, olderThan time.Time) (reviewsDeleted, itemsDeleted int64, err error)
}

// App is the main application container that holds references to all initialized
// services. Create a new App using the New() function which handles all service
// initialization and wiring based on environment configuration.
//
// Use the Close() method to gracefully shutdown all services when the application
// is terminating.
type App struct {
	Config *Config
	Logger *slog.Logger

	// Core services
	Snowflake      *snowflake.Client
	Warehouse      warehouse.DataWarehouse
	Policy         *policy.Engine
	Findings       findings.FindingStore
	Scanner        *scanner.Scanner
	DSPM           *dspm.Scanner
	Cache          *cache.PolicyCache
	ExecutionStore executionstore.Store
	GraphSnapshots *graph.GraphPersistenceStore

	// Feature services
	Agents         *agents.AgentRegistry
	Ticketing      *ticketing.Service
	Identity       *identity.Service
	AttackPath     *attackpath.Graph
	Providers      *providers.Registry
	Webhooks       *webhooks.Service
	TapConsumer    *events.Consumer
	AlertRouter    *events.AlertRouter
	TapEventMapper *graphingest.Mapper
	RemoteTools    *agents.RemoteToolProvider
	ToolPublisher  *agents.ToolPublisher
	Notifications  *notifications.Manager
	Scheduler      *scheduler.Scheduler

	// Repositories (for Snowflake persistence)
	FindingsRepo        *snowflake.FindingRepository
	TicketsRepo         *snowflake.TicketRepository
	AuditRepo           *snowflake.AuditRepository
	PolicyHistoryRepo   *snowflake.PolicyHistoryRepository
	RiskEngineStateRepo *snowflake.RiskEngineStateRepository
	RetentionRepo       retentionCleaner

	// Snowflake-backed stores (when available)
	SnowflakeFindings *findings.SnowflakeStore

	// Incremental scanning
	ScanWatermarks *scanner.WatermarkStore

	// New services
	RBAC                *auth.RBAC
	ThreatIntel         *threatintel.ThreatIntelService
	Compliance          *compliance.ComplianceReport
	Health              *health.Registry
	Lineage             *lineage.LineageMapper
	Remediation         *remediation.Engine
	RemediationExecutor *remediation.Executor
	RuntimeDetect       *runtime.DetectionEngine
	RuntimeIngest       runtime.IngestStore
	RuntimeRespond      *runtime.ResponseEngine

	// Security Graph
	SecurityGraph                 *graph.Graph
	SecurityGraphBuilder          *builders.Builder
	Propagation                   *graph.PropagationEngine
	graphReady                    chan struct{} // closed when initial graph build completes
	graphCtx                      context.Context
	graphCancel                   context.CancelFunc
	graphUpdateMu                 sync.Mutex
	graphBuildMu                  sync.RWMutex
	graphBuildState               GraphBuildState
	graphBuildLastAt              time.Time
	graphBuildErr                 string
	graphConsistencyMu            sync.Mutex
	graphConsistencyLast          time.Time
	graphConsistencyRun           bool
	graphConsistencyCancel        context.CancelFunc
	graphConsistencyWG            sync.WaitGroup
	eventCorrelationRefreshQueue  *eventCorrelationRefreshQueue
	eventCorrelationRefreshCancel context.CancelFunc
	eventCorrelationRefreshWG     sync.WaitGroup
	threatIntelSyncCancel         context.CancelFunc
	threatIntelSyncWG             sync.WaitGroup
	traceShutdown                 func(context.Context) error
	secretsReloadCancel           context.CancelFunc
	secretsReloadWG               sync.WaitGroup
	tapMapperOnce                 sync.Once
	tapMapperErr                  error
	tapResolveGraphMu             sync.RWMutex
	tapResolveGraph               *graph.Graph
	securityGraphInitMu           sync.RWMutex
	reloadMu                      sync.Mutex
	apiKeys                       atomic.Value // map[string]string
	apiCredentials                atomic.Value // map[string]apiauth.Credential
	apiCredentialStore            *apiauth.ManagedCredentialStore
	secretsLoader                 secretsLoader

	// Cached table list from Snowflake (shared by graph builder + policy coverage)
	AvailableTables []string
}

// New creates and wires up the entire application using environment-backed config.
func New(ctx context.Context) (*App, error) {
	return NewWithOptions(ctx)
}

// NewWithConfig creates and wires up the entire application from an explicit config.
// This enables deterministic integration tests and gradual container decomposition
// without relying on process-wide environment mutation.
func NewWithConfig(ctx context.Context, cfg *Config) (*App, error) {
	return NewWithOptions(ctx, WithConfig(cfg))
}

// NewWithOptions creates and wires up the entire application from constructor options.
// This allows incremental decomposition of app construction while preserving the
// existing New/NewWithConfig behavior.
func NewWithOptions(ctx context.Context, opts ...Option) (*App, error) {
	options := applyOptions(opts)

	cfg := options.config
	if cfg == nil {
		cfg = LoadConfig()
	}
	cfg.RefreshProviderAwareConfig()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	managedCredentialStore := apiauth.NewManagedCredentialStore(cfg.APICredentialStateFile)
	if err := managedCredentialStore.Load(); err != nil {
		return nil, fmt.Errorf("load managed api credential state: %w", err)
	}
	if cfg.APIAuthEnabled && len(cfg.APIKeys) == 0 && len(managedCredentialStore.List()) == 0 {
		return nil, fmt.Errorf("api auth enabled but no API_KEYS configured")
	}

	logger := options.logger
	if logger == nil {
		logger = newDefaultAppLogger(cfg.LogLevel)
	}
	logUnboundedRetentionWarnings(logger, cfg)

	app := &App{
		Config: cfg,
		Logger: logger,
	}
	app.secretsLoader = options.secretsLoader
	app.apiCredentialStore = managedCredentialStore
	if len(cfg.APICredentials) > 0 || len(cfg.APIKeys) == 0 {
		app.setAPICredentials(cfg.APICredentials)
	} else {
		app.setAPIKeys(cfg.APIKeys)
	}

	initCtx := ctx
	if initCtx == nil {
		initCtx = context.Background()
	}
	if cfg.InitTimeout > 0 {
		var cancel context.CancelFunc
		initCtx, cancel = context.WithTimeout(initCtx, cfg.InitTimeout)
		defer cancel()
	}

	if err := app.initialize(initCtx); err != nil {
		if app.graphCancel != nil {
			app.graphCancel()
		}
		app.stopThreatIntelSync()
		if errors.Is(err, context.DeadlineExceeded) || initCtx.Err() == context.DeadlineExceeded {
			logger.Error("application initialization timed out", "timeout", cfg.InitTimeout, "error", err)
		}
		return nil, err
	}

	logger.Info("application initialized",
		"snowflake", app.Snowflake != nil,
		"policies", len(app.Policy.ListPolicies()),
	)
	app.startSecretsReloader(ctx)

	return app, nil
}

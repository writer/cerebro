package apptest

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/cache"
	"github.com/evalops/cerebro/internal/executionstore"
	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/graph"
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
	"github.com/evalops/cerebro/internal/threatintel"
	"github.com/evalops/cerebro/internal/ticketing"
	"github.com/evalops/cerebro/internal/warehouse"
	"github.com/evalops/cerebro/internal/webhooks"
)

// NewConfig returns a deterministic test config with isolated temp-backed paths.
func NewConfig(t *testing.T) *app.Config {
	t.Helper()

	stateDir := t.TempDir()
	graphSnapshotPath := strings.TrimSpace(os.Getenv("GRAPH_SNAPSHOT_PATH"))
	if graphSnapshotPath == "" {
		graphSnapshotPath = filepath.Join(stateDir, "graph-snapshots")
		t.Setenv("GRAPH_SNAPSHOT_PATH", graphSnapshotPath)
	}

	return &app.Config{
		LogLevel:                   "error",
		Port:                       0,
		ExecutionStoreFile:         filepath.Join(stateDir, "executions.db"),
		PlatformReportRunStateFile: filepath.Join(stateDir, "state.json"),
		PlatformReportSnapshotPath: filepath.Join(stateDir, "snapshots"),
		GraphSnapshotPath:          graphSnapshotPath,
		WorkloadScanStateFile:      filepath.Join(stateDir, "workload-scan.db"),
		WorkloadScanMountBasePath:  filepath.Join(stateDir, "workload-scan", "mounts"),
	}
}

// NewApp creates a minimal in-memory App suitable for cross-package tests.
func NewApp(t *testing.T) *app.App {
	t.Helper()
	return NewAppWithWarehouse(t, nil)
}

// NewAppWithWarehouse creates a minimal test app with an explicit warehouse dependency.
func NewAppWithWarehouse(t *testing.T, store warehouse.DataWarehouse) *app.App {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg := NewConfig(t)
	pe := policy.NewEngine()
	fs := findings.NewStore()
	sc := scanner.NewScanner(pe, scanner.ScanConfig{Workers: 2}, logger)
	executionStore, err := executionstore.NewSQLiteStore(cfg.ExecutionStoreFile)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	application := &app.App{
		Config:         cfg,
		Logger:         logger,
		Warehouse:      store,
		Policy:         pe,
		Findings:       fs,
		Scanner:        sc,
		Cache:          cache.NewPolicyCache(1000, 5*time.Minute),
		ExecutionStore: executionStore,
		Agents:         agents.NewAgentRegistry(),
		RBAC:           auth.NewRBAC(),
		Webhooks:       webhooks.NewServiceForTesting(),
		Notifications:  notifications.NewManager(),
		Scheduler:      scheduler.NewScheduler(logger),
		Ticketing:      ticketing.NewService(),
		AttackPath:     attackpath.NewGraph(),
		Providers:      providers.NewRegistry(),
		Health:         health.NewRegistry(),
		Lineage:        lineage.NewLineageMapper(),
		Remediation:    remediation.NewEngine(logger),
		RuntimeDetect:  runtime.NewDetectionEngine(),
		RuntimeRespond: runtime.NewResponseEngine(),
		SecurityGraph:  graph.New(),
		ScanWatermarks: scanner.NewWatermarkStore(nil),
		ThreatIntel:    threatintel.NewThreatIntelService(),
	}
	application.Identity = identity.NewService(
		identity.WithExecutionStore(executionStore),
		identity.WithGraphResolver(func() *graph.Graph { return application.SecurityGraph }),
	)
	t.Cleanup(func() { _ = application.Close() })
	return application
}

package apptest

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/attackpath"
	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/cache"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/identity"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/threatintel"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
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
		RuntimeIngest: func() runtime.IngestStore {
			ingestStore, err := runtime.NewSQLiteIngestStoreWithExecutionStore(executionStore)
			if err != nil {
				t.Fatalf("NewSQLiteIngestStoreWithExecutionStore: %v", err)
			}
			return ingestStore
		}(),
		RuntimeRespond: runtime.NewResponseEngine(),
		SecurityGraph:  graph.New(),
		ScanWatermarks: scanner.NewWatermarkStore(nil),
		ThreatIntel:    threatintel.NewThreatIntelService(),
	}
	application.Identity = identity.NewService(
		identity.WithExecutionStore(executionStore),
		identity.WithGraphResolver(func(context.Context) *graph.Graph { return application.SecurityGraph }),
	)
	t.Cleanup(func() { _ = application.Close() })
	return application
}

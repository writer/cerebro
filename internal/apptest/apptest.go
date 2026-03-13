package apptest

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/agents"
	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/attackpath"
	"github.com/evalops/cerebro/internal/auth"
	"github.com/evalops/cerebro/internal/cache"
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

	reportStateDir := t.TempDir()
	if os.Getenv("GRAPH_SNAPSHOT_PATH") == "" {
		t.Setenv("GRAPH_SNAPSHOT_PATH", filepath.Join(reportStateDir, "graph-snapshots"))
	}

	return &app.Config{
		LogLevel:                   "error",
		Port:                       0,
		ExecutionStoreFile:         filepath.Join(reportStateDir, "executions.db"),
		PlatformReportRunStateFile: filepath.Join(reportStateDir, "state.json"),
		PlatformReportSnapshotPath: filepath.Join(reportStateDir, "snapshots"),
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

	return &app.App{
		Config:         cfg,
		Logger:         logger,
		Warehouse:      store,
		Policy:         pe,
		Findings:       fs,
		Scanner:        sc,
		Cache:          cache.NewPolicyCache(1000, 5*time.Minute),
		Agents:         agents.NewAgentRegistry(),
		RBAC:           auth.NewRBAC(),
		Webhooks:       webhooks.NewServiceForTesting(),
		Notifications:  notifications.NewManager(),
		Scheduler:      scheduler.NewScheduler(logger),
		Ticketing:      ticketing.NewService(),
		Identity:       identity.NewService(),
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
}

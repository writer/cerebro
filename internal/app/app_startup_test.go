package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunInitStep_RecoversPanic(t *testing.T) {
	err := runInitStep("panic-step", func() {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected panic to be converted into an error")
	}
	if !strings.Contains(err.Error(), "panic-step init panic") {
		t.Fatalf("expected panic-step context, got: %v", err)
	}
}

func TestRunInitErrorStep_RecoversPanic(t *testing.T) {
	err := runInitErrorStep("panic-step", func() error {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected panic to be converted into an error")
	}
	if !strings.Contains(err.Error(), "panic-step init panic") {
		t.Fatalf("expected panic-step context, got: %v", err)
	}
}

func TestRunInitErrorStep_ReturnsError(t *testing.T) {
	want := errors.New("init failed")
	err := runInitErrorStep("error-step", func() error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("expected wrapped error %v, got %v", want, err)
	}
}

func TestNew_MissingSnowflakeConfigStartsWithSQLiteWarehouse(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("API_AUTH_ENABLED", "false")
	t.Setenv("API_KEYS", "")
	t.Setenv("WAREHOUSE_BACKEND", "sqlite")
	t.Setenv("WAREHOUSE_SQLITE_PATH", filepath.Join(tempDir, "warehouse.db"))
	t.Setenv("EXECUTION_STORE_FILE", filepath.Join(tempDir, "executions.db"))
	t.Setenv("GRAPH_SNAPSHOT_PATH", filepath.Join(tempDir, "graph-snapshots"))
	t.Setenv("PLATFORM_REPORT_RUN_STATE_FILE", filepath.Join(tempDir, "report-runs.json"))
	t.Setenv("PLATFORM_REPORT_SNAPSHOT_PATH", filepath.Join(tempDir, "report-snapshots"))
	t.Setenv("CEREBRO_DB_PATH", filepath.Join(tempDir, "findings.db"))

	app, err := New(context.Background())
	if err != nil {
		t.Fatalf("expected startup without snowflake to succeed with sqlite warehouse, got: %v", err)
	}
	t.Cleanup(func() {
		_ = app.Close()
	})

	if app.Snowflake != nil {
		t.Fatal("expected snowflake client to be nil when required snowflake auth env vars are unset")
	}
	if app.Warehouse == nil {
		t.Fatal("expected local sqlite warehouse to be initialized when snowflake auth is unset")
	}
	if app.Findings == nil || app.Scanner == nil || app.Policy == nil {
		t.Fatal("expected core services to still initialize with sqlite warehouse")
	}
	if !app.WaitForGraph(context.Background()) {
		t.Fatal("expected graph readiness to become true when sqlite warehouse is configured")
	}
}

func TestInitRBAC_InvalidStateFileFallsBackToInMemory(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "rbac-state.json")
	if err := os.WriteFile(statePath, []byte("invalid-json"), 0o600); err != nil {
		t.Fatalf("write invalid RBAC state: %v", err)
	}

	a := &App{
		Config: &Config{
			RBACStateFile: statePath,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	a.initRBAC()
	if a.RBAC == nil {
		t.Fatal("expected RBAC to fall back to in-memory defaults when state file is invalid")
	}
	if len(a.RBAC.ListRoles()) == 0 {
		t.Fatal("expected fallback RBAC instance to include default roles")
	}
}

func TestWaitForGraph_ContextCanceled(t *testing.T) {
	a := &App{graphReady: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	if a.WaitForGraph(ctx) {
		t.Fatal("expected WaitForGraph to return false on context cancellation")
	}
}

func TestClose_CancelsGraphBuilderBeforeWaiting(t *testing.T) {
	graphReady := make(chan struct{})
	cancelCalled := make(chan struct{})

	a := &App{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		graphCancel: func() {
			close(cancelCalled)
			close(graphReady)
		},
		graphReady: graphReady,
	}

	if err := a.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	select {
	case <-cancelCalled:
	default:
		t.Fatal("expected graph cancel to be called before close returned")
	}
}

func TestClose_LogsWarningWhenGraphShutdownTimesOut(t *testing.T) {
	oldTimeout := appShutdownTimeout
	appShutdownTimeout = 20 * time.Millisecond
	t.Cleanup(func() {
		appShutdownTimeout = oldTimeout
	})

	var logs bytes.Buffer
	a := &App{
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})),
		graphCancel: func() {
			// Intentionally leave graphReady open to force timeout path.
		},
		graphReady: make(chan struct{}),
	}

	start := time.Now()
	if err := a.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close() took too long waiting on graph shutdown: %s", elapsed)
	}

	if !strings.Contains(logs.String(), "timed out waiting for security graph shutdown") {
		t.Fatalf("expected graph shutdown timeout warning, got logs: %s", logs.String())
	}
}

func TestStopThreatIntelSyncWaitsForBackgroundWorker(t *testing.T) {
	stopped := make(chan struct{})
	application := &App{}
	application.threatIntelSyncCancel = func() {
		close(stopped)
	}
	application.threatIntelSyncWG.Add(1)
	go func() {
		defer application.threatIntelSyncWG.Done()
		<-stopped
	}()

	application.stopThreatIntelSync()
}

func TestInitCache_EntriesDoNotExpireImmediately(t *testing.T) {
	a := &App{}
	a.initCache()
	if a.Cache == nil {
		t.Fatal("expected cache to be initialized")
	}

	a.Cache.SetEvaluation("policy-1", "asset-1", "hit")
	time.Sleep(2 * time.Millisecond)
	if _, ok := a.Cache.GetEvaluation("policy-1", "asset-1"); !ok {
		t.Fatal("expected cache entry to survive immediate follow-up lookup")
	}
}

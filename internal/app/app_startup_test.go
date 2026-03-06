package app

import (
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

func TestNew_MissingSnowflakeConfigStartsDegraded(t *testing.T) {
	t.Setenv("SNOWFLAKE_PRIVATE_KEY", "")
	t.Setenv("SNOWFLAKE_ACCOUNT", "")
	t.Setenv("SNOWFLAKE_USER", "")
	t.Setenv("API_AUTH_ENABLED", "false")
	t.Setenv("API_KEYS", "")

	app, err := New(context.Background())
	if err != nil {
		t.Fatalf("expected startup without snowflake to succeed in degraded mode, got: %v", err)
	}
	t.Cleanup(func() {
		_ = app.Close()
	})

	if app.Snowflake != nil {
		t.Fatal("expected snowflake client to be nil when required snowflake auth env vars are unset")
	}
	if app.Findings == nil || app.Scanner == nil || app.Policy == nil {
		t.Fatal("expected core services to still initialize in degraded mode")
	}
	if app.WaitForGraph(context.Background()) {
		t.Fatal("expected graph readiness to be false when snowflake is not configured")
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

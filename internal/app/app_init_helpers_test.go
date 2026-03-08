package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/evalops/cerebro/internal/policy"
)

func TestRunInitStep_Success(t *testing.T) {
	called := false
	err := runInitStep("cache", func() {
		called = true
	})
	if err != nil {
		t.Fatalf("runInitStep returned error: %v", err)
	}
	if !called {
		t.Fatal("expected init function to run")
	}
}

func TestInitPhase1_ExplicitMappingsModeReturnsError(t *testing.T) {
	t.Setenv("CEREBRO_POLICY_EXPLICIT_MAPPINGS_ONLY", "true")

	a := &App{
		Config: &Config{
			PoliciesPath: filepath.Join(t.TempDir(), "missing-policies"),
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := a.initPhase1(context.Background()); err == nil {
		t.Fatal("expected explicit-mappings-only mode to fail when policy loading fails")
	}
}

func TestInitPhase3_InitializesScannerAndDSPM(t *testing.T) {
	a := &App{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Policy: policy.NewEngine(),
	}

	a.initPhase3()

	if a.Scanner == nil {
		t.Fatal("expected scanner to be initialized")
	}
	if a.DSPM == nil {
		t.Fatal("expected DSPM scanner to be initialized")
	}
}

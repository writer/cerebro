package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/apiauth"
)

func TestNewWithOptions_UsesProvidedLogger(t *testing.T) {
	cfg := LoadConfig()
	cfg.APIAuthEnabled = false

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := NewWithOptions(context.Background(), WithConfig(cfg), WithLogger(logger))
	if err != nil {
		t.Fatalf("NewWithOptions() failed: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })

	if app.Logger != logger {
		t.Fatal("expected NewWithOptions to use provided logger")
	}
}

func TestNewWithOptions_APIAuthEnabledWithoutKeys(t *testing.T) {
	cfg := LoadConfig()
	cfg.APIAuthEnabled = true
	cfg.APIKeys = map[string]string{}
	cfg.APICredentials = map[string]apiauth.Credential{}

	_, err := NewWithOptions(context.Background(), WithConfig(cfg))
	if err == nil {
		t.Fatal("expected error when API auth is enabled with no API keys")
	}
	if !strings.Contains(err.Error(), "api auth enabled but no API_KEYS configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

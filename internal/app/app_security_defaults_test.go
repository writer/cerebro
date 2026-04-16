package app

import (
	"strings"
	"testing"
)

func TestLoadConfigDefaultsEnableAPISecurityControls(t *testing.T) {
	cfg := LoadConfig()
	if !cfg.APIAuthEnabled {
		t.Fatal("expected API auth to default to enabled")
	}
	if !cfg.RateLimitEnabled {
		t.Fatal("expected rate limiting to default to enabled")
	}
	if cfg.DevMode {
		t.Fatal("expected dev mode to default to disabled")
	}
}

func TestLoadConfigDevModeDisablesAPISecurityControls(t *testing.T) {
	t.Setenv("CEREBRO_DEV_MODE", "true")

	cfg := LoadConfig()
	if !cfg.DevMode {
		t.Fatal("expected dev mode to be enabled")
	}
	if cfg.APIAuthEnabled {
		t.Fatal("expected dev mode to disable API auth")
	}
	if cfg.RateLimitEnabled {
		t.Fatal("expected dev mode to disable rate limiting")
	}
}

func TestValidateDevModeRequiresDebugOrAck(t *testing.T) {
	cfg := LoadConfig()
	cfg.DevMode = true
	cfg.APIAuthEnabled = false
	cfg.RateLimitEnabled = false
	cfg.LogLevel = "info"
	cfg.DevModeAck = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error when dev mode is enabled without debug logging or ack")
	}
	if !strings.Contains(err.Error(), "CEREBRO_DEV_MODE requires LOG_LEVEL=debug or CEREBRO_DEV_MODE_ACK=1") {
		t.Fatalf("unexpected validation error: %v", err)
	}

	cfg.LogLevel = "debug"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected debug logging to satisfy dev mode validation, got %v", err)
	}

	cfg.LogLevel = "info"
	cfg.DevModeAck = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected explicit ack to satisfy dev mode validation, got %v", err)
	}
}

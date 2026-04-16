package app

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLoadConfigValidateRejectsInsecureTLSWithoutOverride(t *testing.T) {
	t.Setenv("NATS_JETSTREAM_ENABLED", "true")
	t.Setenv("NATS_JETSTREAM_TLS_ENABLED", "true")
	t.Setenv("NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("CEREBRO_ALLOW_INSECURE_TLS", "false")

	cfg := LoadConfig()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected config validation error")
	}
	if !strings.Contains(err.Error(), "NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY requires CEREBRO_ALLOW_INSECURE_TLS=true") {
		t.Fatalf("expected insecure TLS validation failure, got %v", err)
	}
}

func TestLoadConfigValidateAllowsInsecureTLSWithOverride(t *testing.T) {
	t.Setenv("NATS_JETSTREAM_ENABLED", "true")
	t.Setenv("NATS_JETSTREAM_TLS_ENABLED", "true")
	t.Setenv("NATS_JETSTREAM_TLS_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("CEREBRO_ALLOW_INSECURE_TLS", "true")

	cfg := LoadConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected insecure TLS override to validate, got %v", err)
	}
}

func TestLogInsecureTLSWarnings(t *testing.T) {
	t.Setenv("CEREBRO_ALLOW_INSECURE_TLS", "true")

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	logInsecureTLSWarnings(logger, &Config{
		NATSJetStreamTLSEnabled:  true,
		NATSJetStreamTLSInsecure: true,
	})

	output := logs.String()
	if !strings.Contains(output, "insecure TLS verification bypass enabled for NATS clients") {
		t.Fatalf("expected insecure TLS warning, got %q", output)
	}
}

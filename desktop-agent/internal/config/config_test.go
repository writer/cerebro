package config

import (
	"flag"
	"os"
	"testing"
	"time"
)

// resetFlags creates a fresh FlagSet for each invocation of Load during tests.
func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func TestLoadDefaults(t *testing.T) {
	resetFlags()
	os.Args = []string{"desktop-agent"}

	// ensure environment does not interfere with defaults
	t.Setenv("CEREBRO_API_BASE_URL", "")
	t.Setenv("CEREBRO_AGENT_MAX_PROCESSES", "")
	t.Setenv("CEREBRO_COLLECTION_INTERVAL", "")
	t.Setenv("CEREBRO_AGENT_ONCE", "")

	cfg := Load()

	if cfg.APIBaseURL != "http://localhost:8000/api/v1" {
		t.Fatalf("expected default API base URL, got %q", cfg.APIBaseURL)
	}
	if cfg.Interval != 5*time.Minute {
		t.Fatalf("expected default interval 5m, got %s", cfg.Interval)
	}
	if cfg.Once {
		t.Fatalf("expected Once=false by default")
	}
	if cfg.MaxProcesses != 40 {
		t.Fatalf("expected default MaxProcesses=40, got %d", cfg.MaxProcesses)
	}
	if cfg.Tags["agent"] != "desktop-go" {
		t.Fatalf("expected default agent tag 'desktop-go', got %q", cfg.Tags["agent"])
	}
}

func TestLoadEnvironmentAndFlagOverrides(t *testing.T) {
	resetFlags()
	os.Args = []string{
		"desktop-agent",
		"--interval=30s",
		"--max-processes=5",
		"--once",
		"--api=https://api.example.com",
		"--token=secret",
	}

	t.Setenv("CEREBRO_AGENT_SITE", "hq")
	t.Setenv("CEREBRO_EVENT_FLUSH_INTERVAL", "10s")
	t.Setenv("CEREBRO_EVENT_BATCH_SIZE", "10")

	cfg := Load()

	if cfg.APIBaseURL != "https://api.example.com" {
		t.Fatalf("expected flag to override API base URL, got %q", cfg.APIBaseURL)
	}
	if cfg.APIToken != "secret" {
		t.Fatalf("expected token from flag, got %q", cfg.APIToken)
	}
	if cfg.Interval != 30*time.Second {
		t.Fatalf("expected interval 30s, got %s", cfg.Interval)
	}
	if !cfg.Once {
		t.Fatalf("expected Once=true from flag")
	}
	if cfg.MaxProcesses != 5 {
		t.Fatalf("expected MaxProcesses=5, got %d", cfg.MaxProcesses)
	}
	if cfg.Site != "hq" {
		t.Fatalf("expected site from env, got %q", cfg.Site)
	}
	if cfg.EventFlushInterval != 10*time.Second {
		t.Fatalf("expected event flush interval 10s, got %s", cfg.EventFlushInterval)
	}
	if cfg.EventBatchSize != 10 {
		t.Fatalf("expected event batch size 10, got %d", cfg.EventBatchSize)
	}
}

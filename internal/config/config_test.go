package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 10*time.Second)
	}
	if cfg.AppendLog.Driver != "" {
		t.Fatalf("AppendLog.Driver = %q, want empty", cfg.AppendLog.Driver)
	}
	if cfg.StateStore.Driver != "" {
		t.Fatalf("StateStore.Driver = %q, want empty", cfg.StateStore.Driver)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("CEREBRO_HTTP_ADDR", "127.0.0.1:9000")
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "cerebro.events")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9000" {
		t.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, "127.0.0.1:9000")
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 3*time.Second)
	}
	if cfg.AppendLog.Driver != AppendLogDriverJetStream {
		t.Fatalf("AppendLog.Driver = %q, want %q", cfg.AppendLog.Driver, AppendLogDriverJetStream)
	}
	if cfg.AppendLog.JetStreamSubjectPrefix != "cerebro.events" {
		t.Fatalf("JetStreamSubjectPrefix = %q, want %q", cfg.AppendLog.JetStreamSubjectPrefix, "cerebro.events")
	}
	if cfg.StateStore.Driver != StateStoreDriverPostgres {
		t.Fatalf("StateStore.Driver = %q, want %q", cfg.StateStore.Driver, StateStoreDriverPostgres)
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("CEREBRO_SHUTDOWN_TIMEOUT", "not-a-duration")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadInfersDriversFromURLs(t *testing.T) {
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "")
	t.Setenv("CEREBRO_JETSTREAM_URL", "nats://127.0.0.1:4222")
	t.Setenv("CEREBRO_JETSTREAM_SUBJECT_PREFIX", "")
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", "")
	t.Setenv("CEREBRO_POSTGRES_DSN", "postgres://127.0.0.1:5432/cerebro?sslmode=disable")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AppendLog.Driver != AppendLogDriverJetStream {
		t.Fatalf("AppendLog.Driver = %q, want %q", cfg.AppendLog.Driver, AppendLogDriverJetStream)
	}
	if cfg.AppendLog.JetStreamSubjectPrefix != "events" {
		t.Fatalf("JetStreamSubjectPrefix = %q, want %q", cfg.AppendLog.JetStreamSubjectPrefix, "events")
	}
	if cfg.StateStore.Driver != StateStoreDriverPostgres {
		t.Fatalf("StateStore.Driver = %q, want %q", cfg.StateStore.Driver, StateStoreDriverPostgres)
	}
}

func TestLoadRejectsUnknownAppendLogDriver(t *testing.T) {
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", "unknown")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingJetStreamURL(t *testing.T) {
	t.Setenv("CEREBRO_APPEND_LOG_DRIVER", AppendLogDriverJetStream)
	t.Setenv("CEREBRO_JETSTREAM_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoadRejectsMissingPostgresDSN(t *testing.T) {
	t.Setenv("CEREBRO_STATE_STORE_DRIVER", StateStoreDriverPostgres)
	t.Setenv("CEREBRO_POSTGRES_DSN", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

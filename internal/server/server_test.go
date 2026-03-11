package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig(8080)

	if cfg.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.ReadTimeout != 15*time.Second {
		t.Errorf("expected ReadTimeout 15s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 60*time.Second {
		t.Errorf("expected WriteTimeout 60s, got %v", cfg.WriteTimeout)
	}
	if cfg.IdleTimeout != 120*time.Second {
		t.Errorf("expected IdleTimeout 120s, got %v", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("expected ShutdownTimeout 30s, got %v", cfg.ShutdownTimeout)
	}
}

func TestNew(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := DefaultConfig(9090)

	srv := New(handler, cfg, logger)

	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.httpServer == nil {
		t.Fatal("expected non-nil http server")
	}
	if srv.httpServer.Addr != ":9090" {
		t.Errorf("expected addr :9090, got %s", srv.httpServer.Addr)
	}
	if srv.httpServer.ReadTimeout != cfg.ReadTimeout {
		t.Errorf("expected ReadTimeout %v, got %v", cfg.ReadTimeout, srv.httpServer.ReadTimeout)
	}
}

func TestServer_Shutdown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{
		Port:            0,
		ShutdownTimeout: 1 * time.Second,
	}

	srv := New(handler, cfg, logger)

	// Shutdown on a server that hasn't started should work
	err := srv.Shutdown()
	if err != nil {
		t.Errorf("unexpected shutdown error: %v", err)
	}
}

func TestServer_Handler(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatalf("write response: %v", err)
		}
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !called {
		t.Error("expected handler to be called")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("expected body 'ok', got %s", string(body))
	}
}

func TestRunWithCleanup_CallsCleanups(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{
		Port:            0,
		ShutdownTimeout: 100 * time.Millisecond,
	}

	cleanup1Called := false
	cleanup2Called := false

	cleanup1 := func() error {
		cleanup1Called = true
		return nil
	}
	cleanup2 := func() error {
		cleanup2Called = true
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := RunWithCleanup(ctx, handler, cfg, logger, cleanup1, cleanup2); err != nil {
		t.Fatalf("RunWithCleanup returned error: %v", err)
	}

	if !cleanup1Called {
		t.Error("expected cleanup1 to be called")
	}
	if !cleanup2Called {
		t.Error("expected cleanup2 to be called")
	}
}

func TestConfig_ZeroValues(t *testing.T) {
	cfg := Config{}

	if cfg.Port != 0 {
		t.Errorf("expected zero port, got %d", cfg.Port)
	}
	if cfg.ReadTimeout != 0 {
		t.Errorf("expected zero ReadTimeout, got %v", cfg.ReadTimeout)
	}
}

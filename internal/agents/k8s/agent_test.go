package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewAgentDefaults(t *testing.T) {
	agent := NewAgent(AgentConfig{})
	if agent.config.CollectInterval != 10*time.Second {
		t.Fatalf("expected default collect interval 10s, got %v", agent.config.CollectInterval)
	}
	if agent.config.BatchSize != 100 {
		t.Fatalf("expected default batch size 100, got %d", agent.config.BatchSize)
	}
}

func TestBytesReaderRead(t *testing.T) {
	reader := &bytesReader{data: []byte("abc")}
	buf := make([]byte, 2)

	count, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:count]) != "ab" {
		t.Fatalf("expected \"ab\", got %q", string(buf[:count]))
	}

	count, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:count]) != "c" {
		t.Fatalf("expected \"c\", got %q", string(buf[:count]))
	}

	_, err = reader.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestDaemonSetManifest(t *testing.T) {
	manifest := DaemonSetManifest("default", "https://cerebro.local", "token")
	checks := []string{
		"namespace: default",
		"value: \"https://cerebro.local\"",
		"token: \"token\"",
	}

	for _, check := range checks {
		if !strings.Contains(manifest, check) {
			t.Fatalf("expected manifest to contain %q", check)
		}
	}
}

func TestSendBatchWithContextPostsTelemetry(t *testing.T) {
	var (
		gotAuthHeader string
		gotPayload    map[string]any
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		gotAuthHeader = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/telemetry/ingest" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	agent := NewAgent(AgentConfig{
		NodeName:    "node-a",
		ClusterName: "cluster-a",
		CerebroURL:  server.URL,
		APIToken:    "secret-token",
	})

	err := agent.sendBatchWithContext(context.Background(), []Event{{
		ID:        "evt-1",
		Type:      "process.exec",
		Timestamp: time.Date(2026, 3, 23, 20, 0, 0, 0, time.UTC),
		NodeName:  "node-a",
	}})
	if err != nil {
		t.Fatalf("sendBatchWithContext() error = %v", err)
	}
	if gotAuthHeader != "Bearer secret-token" {
		t.Fatalf("authorization = %q, want %q", gotAuthHeader, "Bearer secret-token")
	}
	if gotPayload["node"] != "node-a" {
		t.Fatalf("payload node = %#v, want %#v", gotPayload["node"], "node-a")
	}
	if gotPayload["cluster"] != "cluster-a" {
		t.Fatalf("payload cluster = %#v, want %#v", gotPayload["cluster"], "cluster-a")
	}
	events, ok := gotPayload["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("payload events = %#v, want single event", gotPayload["events"])
	}
}

func TestSendBatchWithContextServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer server.Close()

	agent := NewAgent(AgentConfig{
		CerebroURL: server.URL,
	})
	err := agent.sendBatchWithContext(context.Background(), []Event{{ID: "evt-1"}})
	if err == nil {
		t.Fatal("sendBatchWithContext() error = nil, want server error")
		return
	}
	if !strings.Contains(err.Error(), "server returned 502") {
		t.Fatalf("sendBatchWithContext() error = %v, want status message", err)
	}
}

func TestBatchSenderFlushesPendingEventsOnStop(t *testing.T) {
	received := make(chan []any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		events, _ := payload["events"].([]any)
		received <- events
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	agent := NewAgent(AgentConfig{
		NodeName:        "node-a",
		ClusterName:     "cluster-a",
		CerebroURL:      server.URL,
		CollectInterval: time.Hour,
		BatchSize:       10,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	agent.telemetry <- Event{ID: "evt-stop"}
	deadline := time.Now().Add(time.Second)
	for len(agent.telemetry) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	agent.Stop()

	select {
	case events := <-received:
		if len(events) != 1 {
			t.Fatalf("received %d events, want 1", len(events))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for flushed batch")
	}
}

func TestRegisterCollectorAndStopStopsCollectors(t *testing.T) {
	agent := NewAgent(AgentConfig{})
	collector := &fakeCollector{
		name: "fake",
		start: func(ctx context.Context, _ chan<- Event) error {
			<-ctx.Done()
			return nil
		},
	}
	agent.RegisterCollector(collector)
	if len(agent.collectors) != 1 {
		t.Fatalf("collectors = %d, want 1", len(agent.collectors))
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := agent.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	cancel()
	agent.Stop()

	if !collector.stopCalled {
		t.Fatal("expected collector Stop() to be called")
	}
}

type fakeCollector struct {
	name       string
	start      func(context.Context, chan<- Event) error
	stopCalled bool
	mu         sync.Mutex
}

func (c *fakeCollector) Name() string { return c.name }

func (c *fakeCollector) Start(ctx context.Context, events chan<- Event) error {
	if c.start == nil {
		return nil
	}
	return c.start(ctx, events)
}

func (c *fakeCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopCalled = true
	return nil
}

package archetype

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceReadEmitsScanAndVulnerabilityEvents(t *testing.T) {
	var sawAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer token" {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/api/v1/scans":
			writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed", "completed_at": "2026-06-17T12:05:00Z"}})
		case "/api/v1/repositories":
			writeJSON(t, w, []map[string]any{{"id": 7, "owner": "WriterInternal", "name": "Archetype"}})
		case "/api/v1/scans/1/vulnerabilities":
			body, err := os.ReadFile("testdata/sample_vulnerability.json")
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[" + string(body) + "]"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{
		"__cerebro_runtime_tenant_id": "writer",
		"base_url":                    server.URL,
		"token":                       "token",
	}), nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if !sawAuth {
		t.Fatal("server did not receive bearer token")
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	if pull.Events[0].GetKind() != "archetype.scan" || pull.Events[1].GetKind() != "archetype.vulnerability" {
		t.Fatalf("event kinds = %q, %q", pull.Events[0].GetKind(), pull.Events[1].GetKind())
	}
	if got := pull.Events[1].GetAttributes()["repo"]; got != "Archetype" {
		t.Fatalf("vulnerability repo attr = %q, want Archetype", got)
	}
	if got := pull.Checkpoint.GetCursorOpaque(); got != "1" {
		t.Fatalf("checkpoint cursor = %q, want 1", got)
	}
}

func TestSourceReadHonorsCheckpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		writeJSON(t, w, []map[string]any{{"id": 1, "repository_id": 7, "status": "completed"}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	pull, err := source.ReadWithCheckpoint(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
	}), nil, &cerebrov1.SourceCheckpoint{CursorOpaque: "1"})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
}

func TestSourceCheckRejectsBadFamily(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  "https://archetype.example.com",
		"family":    "repository",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want error")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
)

func TestCreateGRCVendorSupportsTenantOnlyAndWorkspaceScopes(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		body          map[string]any
		wantWorkspace string
	}{
		{
			name:  "tenant only",
			query: "tenant_id=writer",
			body: map[string]any{
				"tenant_id":  "writer",
				"name":       "Acme Vendor",
				"owner":      "security",
				"risk_level": "medium",
			},
		},
		{
			name:  "tenant and workspace",
			query: "tenant_id=writer&workspace_id=workspace-a",
			body: map[string]any{
				"tenant_id":    "writer",
				"workspace_id": "workspace-a",
				"name":         "Workspace Vendor",
				"source_id":    "okta",
				"provider":     "Okta",
				"runtime_id":   "okta-runtime",
			},
			wantWorkspace: "workspace-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appendLog := &recordingAppendLog{}
			graph := &stubGraphStore{}
			app := New(config.Config{}, Dependencies{AppendLog: appendLog, GraphStore: graph}, nil)
			server := httptest.NewServer(app.Handler())
			defer server.Close()

			payload, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			response, err := server.Client().Post(server.URL+"/grc/vendors?"+tt.query, "application/json", bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("POST /grc/vendors error: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("POST /grc/vendors status = %d, want %d; body = %s", response.StatusCode, http.StatusCreated, body)
			}

			var result struct {
				Vendor      grcvendor.Vendor `json:"vendor"`
				GeneratedAt string           `json:"generated_at"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if result.Vendor.Name != tt.body["name"] || result.GeneratedAt == "" {
				t.Fatalf("response = %#v, want created vendor", result)
			}
			if len(appendLog.events) != 1 {
				t.Fatalf("append log events = %d, want 1", len(appendLog.events))
			}
			event := appendLog.events[0]
			if event.GetTenantId() != "writer" || event.GetSourceId() != "grc" || event.GetKind() != "grc.vendor" || event.GetSchemaRef() != "grc/vendor/v1" {
				t.Fatalf("event identity = tenant %q source %q kind %q schema %q", event.GetTenantId(), event.GetSourceId(), event.GetKind(), event.GetSchemaRef())
			}
			if got := event.GetAttributes()[ports.EventAttributeApplicationWorkspaceID]; got != tt.wantWorkspace {
				t.Fatalf("event workspace = %q, want %q", got, tt.wantWorkspace)
			}
			if len(graph.entities) == 0 {
				t.Fatal("projected vendor entity missing")
			}
		})
	}
}

func TestCreateGRCVendorRejectsMalformedAndOversizedFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: `{"name":"Acme Vendor","unknown":"value"}`},
		{name: "oversized name", body: `{"name":"` + strings.Repeat("x", 1025) + `"}`},
		{name: "oversized attribute key", body: `{"name":"Acme Vendor","attributes":{"` + strings.Repeat("k", 129) + `":"value"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := New(config.Config{}, Dependencies{AppendLog: &recordingAppendLog{}, GraphStore: &stubGraphStore{}}, nil)
			server := httptest.NewServer(app.Handler())
			defer server.Close()

			response, err := server.Client().Post(server.URL+"/grc/vendors?tenant_id=writer", "application/json", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("POST /grc/vendors error: %v", err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("POST /grc/vendors status = %d, want %d", response.StatusCode, http.StatusBadRequest)
			}
		})
	}
}

func TestCreateGRCVendorRejectsBodyWorkspaceWithoutResolvedScope(t *testing.T) {
	appendLog := &recordingAppendLog{}
	graph := &stubGraphStore{}
	app := New(config.Config{}, Dependencies{AppendLog: appendLog, GraphStore: graph}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/grc/vendors?tenant_id=writer", "application/json", bytes.NewBufferString(`{"tenant_id":"writer","workspace_id":"workspace-a","name":"Acme Vendor"}`))
	if err != nil {
		t.Fatalf("POST /grc/vendors error: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /grc/vendors status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	if len(appendLog.events) != 0 {
		t.Fatalf("append log events = %d, want 0", len(appendLog.events))
	}
}

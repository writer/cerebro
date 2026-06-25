package langchain

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "langchain" {
		t.Fatalf("Spec().Id = %q, want langchain", got)
	}
}

func TestReadWorkspaceMemberUsesLangSmithHeadersAndScopeAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/v1/workspaces/current/members" {
			t.Fatalf("request path = %q, want /api/v1/workspaces/current/members", got)
		}
		if got := r.Header.Get("X-API-Key"); got != "fixture-key" {
			t.Fatalf("X-API-Key = %q, want fixture-key", got)
		}
		if got := r.Header.Get("X-Organization-Id"); got != "org_123" {
			t.Fatalf("X-Organization-Id = %q, want org_123", got)
		}
		if got := r.Header.Get("X-Tenant-Id"); got != "workspace_123" {
			t.Fatalf("X-Tenant-Id = %q, want workspace_123", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":         "user_123",
			"email":      "ada@example.com",
			"full_name":  "Ada Lovelace",
			"role_name":  "Admin",
			"created_at": "2026-06-24T12:00:00Z",
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":         "fixture-key",
		"base_url":        server.URL,
		"family":          "workspace_member",
		"organization_id": "org_123",
		"tenant_id":       "writer",
		"workspace_id":    "workspace_123",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langchain.workspace_member" {
		t.Fatalf("Kind = %q, want langchain.workspace_member", event.Kind)
	}
	for key, want := range map[string]string{
		"email":           "ada@example.com",
		"organization_id": "org_123",
		"role":            "Admin",
		"user_id":         "user_123",
		"workspace_id":    "workspace_123",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadWorkspaceInjectsOrganizationScopeAttribute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/v1/workspaces" {
			t.Fatalf("request path = %q, want /api/v1/workspaces", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":           "workspace_123",
			"display_name": "Production Workspace",
			"created_at":   "2026-06-24T12:00:00Z",
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":         "fixture-key",
		"base_url":        server.URL,
		"family":          "workspace",
		"organization_id": "org_123",
		"tenant_id":       "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langchain.workspace" {
		t.Fatalf("Kind = %q, want langchain.workspace", event.Kind)
	}
	if got := event.Attributes["organization_id"]; got != "org_123" {
		t.Fatalf("organization_id = %q, want org_123", got)
	}
}

func TestReadAPIKeyEmitsStaticCredentialType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/v1/orgs/current/service-keys" {
			t.Fatalf("request path = %q, want /api/v1/orgs/current/service-keys", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":         "key_123",
			"name":       "production service key",
			"created_at": "2026-06-24T12:00:00Z",
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":         "fixture-key",
		"base_url":        server.URL,
		"family":          "api_key",
		"organization_id": "org_123",
		"tenant_id":       "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langchain.api_key" {
		t.Fatalf("Kind = %q, want langchain.api_key", event.Kind)
	}
	if got := event.Attributes["credential_type"]; got != "langchain_service_key" {
		t.Fatalf("credential_type = %q, want langchain_service_key", got)
	}
}

func TestReadRunMapsUsageAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/v1/runs" {
			t.Fatalf("request path = %q, want /api/v1/runs", got)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"id":         "run_123",
			"name":       "answer-question",
			"run_type":   "llm",
			"session_id": "project_123",
			"usage_metadata": map[string]any{
				"input_tokens":  "12",
				"output_tokens": "34",
				"total_tokens":  "46",
			},
			"start_time": "2026-06-24T12:00:00Z",
		}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":      "fixture-key",
		"base_url":     server.URL,
		"family":       "run",
		"tenant_id":    "writer",
		"workspace_id": "workspace_123",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	event := pull.Events[0]
	if event.Kind != "langchain.run" {
		t.Fatalf("Kind = %q, want langchain.run", event.Kind)
	}
	for key, want := range map[string]string{
		"input_tokens":  "12",
		"output_tokens": "34",
		"project_id":    "project_123",
		"run_id":        "run_123",
		"total_tokens":  "46",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "openai" {
		t.Fatalf("Spec().Id = %q, want openai", got)
	}
}

func TestReadAuditLogMapsQueryAndUnixTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organization/audit_logs" {
			t.Fatalf("request path = %q, want /organization/audit_logs", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer admin-key" {
			t.Fatalf("Authorization = %q, want Bearer admin-key", got)
		}
		if got := r.URL.Query().Get("effective_at[gte]"); got != "1711471533" {
			t.Fatalf("effective_at[gte] = %q, want 1711471533", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":           "audit-1",
				"type":         "project.created",
				"effective_at": 1711471533,
				"actor": map[string]any{
					"type": "user",
					"user": map[string]any{
						"id":    "user-1",
						"email": "alice@example.com",
					},
				},
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":          "admin-key",
		"base_url":         server.URL,
		"effective_at_gte": "1711471533",
		"family":           "audit_log",
		"per_page":         "2",
		"tenant_id":        "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "openai.audit_log" {
		t.Fatalf("Kind = %q, want openai.audit_log", event.Kind)
	}
	if got := event.Attributes["event_type"]; got != "project.created" {
		t.Fatalf("event_type = %q, want project.created", got)
	}
	if got := event.Attributes["actor_email"]; got != "alice@example.com" {
		t.Fatalf("actor_email = %q, want alice@example.com", got)
	}
	want := time.Unix(1711471533, 0).UTC()
	if got := event.OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestReadProjectRateLimitUsesProjectPathParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organization/projects/proj_123/rate_limits" {
			t.Fatalf("request path = %q, want /organization/projects/proj_123/rate_limits", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":                        "rl_1",
				"model":                     "gpt-5",
				"max_requests_per_1_minute": 600,
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":    "admin-key",
		"base_url":   server.URL,
		"family":     "project_rate_limit",
		"per_page":   "2",
		"project_id": "proj_123",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "openai.project_rate_limit" {
		t.Fatalf("Kind = %q, want openai.project_rate_limit", event.Kind)
	}
	if got := event.Attributes["project_id"]; got != "proj_123" {
		t.Fatalf("project_id = %q, want proj_123", got)
	}
	if got := event.Attributes["model"]; got != "gpt-5" {
		t.Fatalf("model = %q, want gpt-5", got)
	}
	if got := event.Attributes["max_requests_per_1_minute"]; got != "600" {
		t.Fatalf("max_requests_per_1_minute = %q, want 600", got)
	}
}

func TestReadProjectHostedToolPermissionDoesNotSendPageSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organization/projects/proj_123/hosted_tool_permissions" {
			t.Fatalf("request path = %q, want /organization/projects/proj_123/hosted_tool_permissions", got)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no page-size params", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code_interpreter": map[string]any{"enabled": true},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":    "admin-key",
		"base_url":   server.URL,
		"family":     "project_hosted_tool_permission",
		"project_id": "proj_123",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["project_id"]; got != "proj_123" {
		t.Fatalf("project_id = %q, want proj_123", got)
	}
	if got := event.Attributes["code_interpreter_enabled"]; got != "true" {
		t.Fatalf("code_interpreter_enabled = %q, want true", got)
	}
}

func TestReadProjectRoleUsesProjectRootPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/projects/proj_123/roles" {
			t.Fatalf("request path = %q, want /projects/proj_123/roles", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":            "role_123",
				"name":          "Project Key Manager",
				"permissions":   []string{"api.organization.projects.api_keys.read"},
				"resource_type": "api.project",
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":    "admin-key",
		"base_url":   server.URL,
		"family":     "project_role",
		"per_page":   "2",
		"project_id": "proj_123",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "openai.project_role" {
		t.Fatalf("Kind = %q, want openai.project_role", event.Kind)
	}
	if got := event.Attributes["project_id"]; got != "proj_123" {
		t.Fatalf("project_id = %q, want proj_123", got)
	}
	if got := event.Attributes["resource_type"]; got != "api.project" {
		t.Fatalf("resource_type = %q, want api.project", got)
	}
}

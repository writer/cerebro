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
		if got := r.URL.Query().Get("resource_ids"); got != "proj_123" {
			t.Fatalf("resource_ids = %q, want proj_123", got)
		}
		if got := r.URL.Query().Get("tenant_only"); got != "true" {
			t.Fatalf("tenant_only = %q, want true", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":           "audit-1",
				"type":         "project.archived",
				"effective_at": 1711471533,
				"actor": map[string]any{
					"type": "user",
					"user": map[string]any{
						"id":    "user-1",
						"email": "alice@example.com",
					},
				},
				"project.archived": map[string]any{"id": "proj_123"},
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
		"resource_ids":     "proj_123",
		"tenant_id":        "writer",
		"tenant_only":      "true",
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
	if got := event.Attributes["event_type"]; got != "project.archived" {
		t.Fatalf("event_type = %q, want project.archived", got)
	}
	if got := event.Attributes["actor_email"]; got != "alice@example.com" {
		t.Fatalf("actor_email = %q, want alice@example.com", got)
	}
	if got := event.Attributes["project_id"]; got != "proj_123" {
		t.Fatalf("project_id = %q, want proj_123", got)
	}
	want := time.Unix(1711471533, 0).UTC()
	if got := event.OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestReadAuditLogMapsNestedActorAndTargetDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":           "audit-2",
				"type":         "api_key.updated",
				"effective_at": 1711471544,
				"actor": map[string]any{
					"type": "api_key",
					"api_key": map[string]any{
						"id":   "key_actor",
						"type": "service_account",
						"service_account": map[string]any{
							"id": "sa_123",
						},
					},
				},
				"api_key.updated": map[string]any{
					"id": "key_target",
					"changes_requested": map[string]any{
						"scopes": []string{"api.model.request"},
					},
				},
			}, {
				"id":           "audit-3",
				"type":         "role.assignment.created",
				"effective_at": 1711471555,
				"actor": map[string]any{
					"type": "session",
					"session": map[string]any{
						"user": map[string]any{
							"id":    "user-admin",
							"email": "admin@example.com",
						},
						"ip_address": "203.0.113.10",
					},
				},
				"role.assignment.created": map[string]any{
					"id":             "assign_123",
					"principal_id":   "group_123",
					"principal_type": "group",
					"resource_id":    "proj_456",
					"resource_type":  "project",
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
		"api_key":   "admin-key",
		"base_url":  server.URL,
		"family":    "audit_log",
		"tenant_id": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(pull.Events))
	}
	keyEvent := pull.Events[0]
	if got := keyEvent.Attributes["actor_api_key_id"]; got != "key_actor" {
		t.Fatalf("actor_api_key_id = %q, want key_actor", got)
	}
	if got := keyEvent.Attributes["actor_service_account_id"]; got != "sa_123" {
		t.Fatalf("actor_service_account_id = %q, want sa_123", got)
	}
	if got := keyEvent.Attributes["api_key_id"]; got != "key_target" {
		t.Fatalf("api_key_id = %q, want key_target", got)
	}
	roleEvent := pull.Events[1]
	if got := roleEvent.Attributes["actor_user_id"]; got != "user-admin" {
		t.Fatalf("actor_user_id = %q, want user-admin", got)
	}
	if got := roleEvent.Attributes["actor_ip_address"]; got != "203.0.113.10" {
		t.Fatalf("actor_ip_address = %q, want 203.0.113.10", got)
	}
	if got := roleEvent.Attributes["principal_type"]; got != "group" {
		t.Fatalf("principal_type = %q, want group", got)
	}
	if got := roleEvent.Attributes["resource_id"]; got != "proj_456" {
		t.Fatalf("resource_id = %q, want proj_456", got)
	}
}

func TestReadInviteMapsAcceptanceAndProjectMembershipDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organization/invites" {
			t.Fatalf("request path = %q, want /organization/invites", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":          "invite_123",
				"email":       "new-admin@example.com",
				"role":        "owner",
				"status":      "pending",
				"created_at":  1711471533,
				"accepted_at": 1711471633,
				"expires_at":  1712076333,
				"projects": []map[string]any{{
					"id":   "proj_123",
					"role": "owner",
				}},
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
		"api_key":   "admin-key",
		"base_url":  server.URL,
		"family":    "invite",
		"tenant_id": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "openai.invite" {
		t.Fatalf("Kind = %q, want openai.invite", event.Kind)
	}
	if got := event.Attributes["accepted_at"]; got != "1711471633" {
		t.Fatalf("accepted_at = %q, want 1711471633", got)
	}
	if got := event.Attributes["projects"]; got == "" {
		t.Fatalf("projects attribute empty, want serialized project membership details")
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

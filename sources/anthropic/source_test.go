package anthropic

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
	if got := source.Spec().GetId(); got != "anthropic" {
		t.Fatalf("Spec().Id = %q, want anthropic", got)
	}
}

func TestReadWorkspaceMemberUsesAdminAPIKeyHeadersAndCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organizations/workspaces/wrkspc_123/members" {
			t.Fatalf("request path = %q, want /organizations/workspaces/wrkspc_123/members", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		if got := r.Header.Get("x-api-key"); got != "admin-key" {
			t.Fatalf("x-api-key = %q, want admin-key", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("after_id") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":             "user_1",
					"email":          "alice@example.com",
					"workspace_role": "workspace_developer",
				}},
				"has_more": true,
				"last_id":  "user_1",
			})
		case "user_1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":             "user_2",
					"email":          "bob@example.com",
					"workspace_role": "workspace_admin",
				}},
				"has_more": false,
				"last_id":  "user_2",
			})
		default:
			t.Fatalf("after_id = %q, want empty or user_1", r.URL.Query().Get("after_id"))
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"api_key":      "admin-key",
		"base_url":     server.URL,
		"family":       "workspace_member",
		"per_page":     "2",
		"tenant_id":    "writer",
		"workspace_id": "wrkspc_123",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "user_1" {
		t.Fatalf("first NextCursor = %q, want user_1", first.NextCursor.GetOpaque())
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	event := first.Events[0]
	if event.Kind != "anthropic.workspace_member" {
		t.Fatalf("Kind = %q, want anthropic.workspace_member", event.Kind)
	}
	if got := event.Attributes["workspace_id"]; got != "wrkspc_123" {
		t.Fatalf("workspace_id = %q, want wrkspc_123", got)
	}
	if got := event.Attributes["workspace_role"]; got != "workspace_developer" {
		t.Fatalf("workspace_role = %q, want workspace_developer", got)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
}

func TestReadServiceAccountCanUseBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/organizations/service_accounts" {
			t.Fatalf("request path = %q, want /organizations/service_accounts", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer oauth-token" {
			t.Fatalf("Authorization = %q, want Bearer oauth-token", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Fatalf("x-api-key = %q, want empty", got)
		}
		if got := r.Header.Get("anthropic-version"); got != "2023-06-01" {
			t.Fatalf("anthropic-version = %q, want 2023-06-01", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":          "svac_1",
				"name":        "CI",
				"description": "Automation",
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
		"auth_model": "bearer_token",
		"base_url":   server.URL,
		"family":     "service_account",
		"tenant_id":  "writer",
		"token":      "oauth-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "anthropic.service_account" {
		t.Fatalf("Kind = %q, want anthropic.service_account", event.Kind)
	}
	if got := event.Attributes["service_account_id"]; got != "svac_1" {
		t.Fatalf("service_account_id = %q, want svac_1", got)
	}
}

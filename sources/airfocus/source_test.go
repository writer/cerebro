package airfocus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(airfocusTestHandler(t, map[string]airfocusTestResponse{
		"/api/team/users": {
			method: http.MethodGet,
			body:   []map[string]any{{"id": "user-1", "fullName": "Grace Hopper", "email": "grace@example.test", "role": "admin", "createdAt": "2026-06-01T00:00:00Z", "updatedAt": "2026-06-02T00:00:00Z"}},
		},
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "per_page": "100"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "airfocus.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["user_id"]; got != "user-1" {
		t.Fatalf("user_id = %q, want user-1", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadProviderVerifiedFamilyPaths(t *testing.T) {
	tests := []struct {
		family   string
		method   string
		path     string
		response any
		wantKind string
	}{
		{
			family:   familyWorkspaces,
			method:   http.MethodPost,
			path:     "/api/workspaces/search",
			wantKind: "airfocus.workspaces",
			response: map[string]any{"items": []map[string]any{{"id": "workspace-1", "name": "Roadmap", "alias": "roadmap", "createdAt": "2026-06-01T00:00:00Z", "updatedAt": "2026-06-02T00:00:00Z"}}, "totalItems": 1},
		},
		{
			family:   familyWorkspaceGroups,
			method:   http.MethodPost,
			path:     "/api/workspaces/groups/search",
			wantKind: "airfocus.workspace_groups",
			response: map[string]any{"items": []map[string]any{{"id": "group-1", "name": "Product", "createdAt": "2026-06-01T00:00:00Z", "updatedAt": "2026-06-02T00:00:00Z"}}, "totalItems": 1},
		},
		{
			family:   familyLinkTypes,
			method:   http.MethodPost,
			path:     "/api/link-types/search",
			wantKind: "airfocus.link_types",
			response: map[string]any{"items": []map[string]any{{"id": "link-type-1", "name": "blocks", "inwardName": "is blocked by", "outwardName": "blocks", "createdAt": "2026-06-01T00:00:00Z", "updatedAt": "2026-06-02T00:00:00Z"}}, "totalItems": 1},
		},
		{
			family:   familyAPIKeys,
			method:   http.MethodGet,
			path:     "/api/profile/api-keys",
			wantKind: "airfocus.api_keys",
			response: []map[string]any{{"id": "api-key-1", "userId": "user-1", "name": "integration token", "scopes": []string{"workspace"}, "createdAt": "2026-06-01T00:00:00Z", "lastUsedAt": "2026-06-02T00:00:00Z"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(airfocusTestHandler(t, map[string]airfocusTestResponse{tt.path: {method: tt.method, body: tt.response}}))
			defer server.Close()

			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token", "per_page": "100"}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got, tt.wantKind)
			}
			if got := pull.Events[0].Attributes["resource_urn"]; strings.TrimSpace(got) == "" {
				t.Fatalf("resource_urn is empty: %#v", pull.Events[0].Attributes)
			}
		})
	}
}

type airfocusTestResponse struct {
	method string
	body   any
}

func airfocusTestHandler(t *testing.T, responses map[string]airfocusTestResponse) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path == "/api/team" {
			if r.Method != http.MethodGet {
				t.Fatalf("health method = %q, want GET", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "team-1", "name": "Example"})
			return
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Method != response.method {
			t.Fatalf("method for %s = %q, want %q", r.URL.Path, r.Method, response.method)
		}
		if response.method == http.MethodPost {
			if got := r.URL.Query().Get("limit"); got != "100" {
				t.Fatalf("limit query = %q, want 100", got)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response.body); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}
}

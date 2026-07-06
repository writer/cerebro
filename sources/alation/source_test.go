package alation

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
	server := httptest.NewServer(alationTestHandler(t, map[string]alationTestResponse{
		"/integration/v2/user/": {
			method: http.MethodGet,
			body: []map[string]any{{
				"id":           101,
				"display_name": "Ada Lovelace",
				"email":        "ada@example.test",
				"last_login":   "2026-06-02 00:00:00",
				"ts_created":   "2026-06-01 00:00:00",
			}},
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
	if event.Kind != "alation.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["user_id"]; got != "101" {
		t.Fatalf("user_id = %q, want 101", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadProviderVerifiedFamilyPaths(t *testing.T) {
	tests := []struct {
		family   string
		path     string
		response any
		wantKind string
	}{
		{
			family:   familyGroups,
			path:     "/integration/v1/group/",
			wantKind: "alation.groups",
			response: []map[string]any{{"id": 201, "display_name": "Data Stewards", "email": "stewards@example.test", "ts_created": "2026-06-01 00:00:00"}},
		},
		{
			family:   familyDataSources,
			path:     "/integration/v1/datasource/",
			wantKind: "alation.data_sources",
			response: []map[string]any{{"id": 301, "title": "Warehouse", "dbtype": "snowflake", "description": "Production warehouse", "is_virtual": false, "url": "/data/301/"}},
		},
		{
			family:   familyPolicies,
			path:     "/integration/v1/business_policies/",
			wantKind: "alation.policies",
			response: []map[string]any{{"id": 401, "title": "Retention Policy", "description": "Approved retention policy", "deleted": false, "ts_created": "2026-06-01 00:00:00"}},
		},
		{
			family:   familyTerms,
			path:     "/integration/v2/term/",
			wantKind: "alation.terms",
			response: []map[string]any{{"id": 501, "title": "Customer", "description": "Business glossary term", "glossary_id": 1, "ts_created": "2026-06-01 00:00:00"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(alationTestHandler(t, map[string]alationTestResponse{tt.path: {method: http.MethodGet, body: tt.response}}))
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
			if got := pull.Events[0].Attributes["resource_urn"]; strings.TrimSpace(got) == "" && tt.family != familyGroups {
				t.Fatalf("resource_urn is empty: %#v", pull.Events[0].Attributes)
			}
		})
	}
}

func TestReadSkipPaginationAdvancesByPageSize(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	var skips []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("TOKEN") != "test-token" {
			t.Fatalf("TOKEN = %q, want test-token", r.Header.Get("TOKEN"))
		}
		if r.URL.Path != "/integration/v2/user/" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		skips = append(skips, r.URL.Query().Get("skip"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("skip") {
		case "0":
			items := make([]map[string]any, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, map[string]any{"id": 1000 + i, "display_name": "Ada Lovelace", "email": "ada@example.test"})
			}
			_ = json.NewEncoder(w).Encode(items)
		case "100":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 102, "display_name": "Grace Hopper", "email": "grace@example.test"}})
		default:
			t.Fatalf("skip = %q, want 0 or 100", r.URL.Query().Get("skip"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyUsers, "token": "test-token", "per_page": "100"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := sourcecdk.CursorToken(pull.NextCursor); got == "" {
		t.Fatalf("first next cursor is empty")
	}
	if _, err := source.Read(context.Background(), cfg, pull.NextCursor); err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if got, want := strings.Join(skips, ","), "0,100"; got != want {
		t.Fatalf("skip sequence = %s, want %s", got, want)
	}
}

type alationTestResponse struct {
	method string
	body   any
}

func alationTestHandler(t *testing.T, responses map[string]alationTestResponse) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("TOKEN") != "test-token" {
			t.Fatalf("TOKEN = %q, want test-token", r.Header.Get("TOKEN"))
		}
		if r.URL.Path == "/integration/v2/user/" && r.URL.Query().Get("limit") == "1" {
			if r.Method != http.MethodGet {
				t.Fatalf("health method = %q, want GET", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 101, "display_name": "Ada Lovelace", "email": "ada@example.test"}})
			return
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Method != response.method {
			t.Fatalf("method for %s = %q, want %q", r.URL.Path, r.Method, response.method)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit query = %q, want 100", got)
		}
		if got := r.URL.Query().Get("skip"); got != "0" {
			t.Fatalf("skip query = %q, want 0", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response.body)
	}
}

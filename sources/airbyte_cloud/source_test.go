package airbyte_cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/health" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/organizations" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"organizationId": "org-1", "organizationName": "Example Org", "email": "admin@example.com"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
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
	if event.Kind != "airbyte_cloud.organizations" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadsDocumentedAirbyteFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	seen := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		seen = append(seen, r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/users":
			if got := r.URL.Query().Get("organizationId"); got != "org-1" {
				t.Fatalf("organizationId query = %q, want org-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "user-1", "name": "Airbyte User", "email": "user@example.com"}}})
		case "/organizations":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"organizationId": "org-1", "organizationName": "Example Org", "email": "admin@example.com"}}})
		case "/sources":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"sourceId": "source-1", "name": "Postgres", "sourceType": "postgres", "workspaceId": "workspace-1", "definitionId": "definition-1"}}})
		case "/permissions":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"permissionId": "permission-1", "permissionType": "workspace_admin", "userId": "user-1", "scope": "workspace", "scopeId": "workspace-1"}}})
		case "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"connectionId": "connection-1", "name": "Warehouse sync", "sourceId": "source-1", "destinationId": "destination-1", "workspaceId": "workspace-1", "status": "active", "dataResidency": "auto", "createdAt": 1758053604}}})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	for _, family := range []string{familyUsers, familyOrganizations, familySources, familyPermissions, familyConnections} {
		pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
			"tenant_id":       "tenant",
			"base_url":        server.URL,
			"family":          family,
			"token":           "test-token",
			"organization_id": "org-1",
		}), nil)
		if err != nil {
			t.Fatalf("Read(%s) error = %v", family, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%s) events = %d, want 1", family, len(pull.Events))
		}
		wantKind := "airbyte_cloud." + family
		if pull.Events[0].Kind != wantKind {
			t.Fatalf("Read(%s) kind = %q, want %q", family, pull.Events[0].Kind, wantKind)
		}
	}
	for _, want := range []string{"/users?organizationId=org-1", "/organizations", "/sources?limit=100&offset=0", "/permissions", "/connections?limit=100&offset=0"} {
		if !slices.Contains(seen, want) {
			t.Fatalf("requests = %v, missing %s", seen, want)
		}
	}
}

func TestSourceAdvancesOffsetPaginationByPageSize(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	offsets := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offsets = append(offsets, r.URL.Query().Get("offset"))
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("offset") {
		case "0":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"sourceId": "source-1", "name": "One", "sourceType": "postgres", "workspaceId": "workspace-1"}, {"sourceId": "source-2", "name": "Two", "sourceType": "mysql", "workspaceId": "workspace-1"}}})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"sourceId": "source-3", "name": "Three", "sourceType": "stripe", "workspaceId": "workspace-1"}}})
		default:
			t.Fatalf("unexpected offset = %q", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familySources, "token": "test-token", "per_page": "2"})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := first.NextCursor.GetOpaque(); got != "2" {
		t.Fatalf("first cursor = %q, want 2", got)
	}
	second, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: first.NextCursor.GetOpaque()})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor.GetOpaque() != "" {
		t.Fatalf("second cursor = %q, want empty", second.NextCursor.GetOpaque())
	}
	if got := strings.Join(offsets, ","); got != "0,2" {
		t.Fatalf("offsets = %q, want 0,2", got)
	}
}

package asana

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/users/me" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("workspace"); got != "workspace-1" {
			t.Fatalf("workspace query = %q, want workspace-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{{
				"gid":           "1200123456789012",
				"resource_type": "user",
				"name":          "Alice Example",
				"display_name":  "Display Fallback",
				"email":         "alice@example.test",
				"created_at":    "2026-06-01T00:00:00Z",
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "workspace_gid": "workspace-1"}
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
	if event.Kind != "asana.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["workspace_gid"]; got != "workspace-1" {
		t.Fatalf("workspace_gid = %q, want workspace-1", got)
	}
	if got := event.Attributes["display_name"]; got != "Alice Example" {
		t.Fatalf("display_name = %q, want Asana name", got)
	}
}

func TestRuntimeUsesAsanaAPIPathsAndOffsetPagination(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/users":
			if got := r.URL.Query().Get("workspace"); got != "workspace-1" {
				t.Fatalf("users workspace = %q, want workspace-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]string{{"gid": "user-1", "name": "User One", "email": "user@example.test"}},
				"next_page": map[string]string{
					"offset": "cursor-2",
				},
			})
		case "/projects":
			if got := r.URL.Query().Get("workspace"); got != "workspace-1" {
				t.Fatalf("projects workspace = %q, want workspace-1", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"gid": "project-1", "name": "Security Evidence"}}})
		case "/workspaces/workspace-1/audit_log_events":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
				"gid":        "audit-1",
				"event_type": "project.created",
				"actor":      map[string]string{"gid": "user-1", "email": "user@example.test", "name": "User One"},
				"resource":   map[string]string{"gid": "project-1", "resource_type": "project", "name": "Security Evidence"},
			}}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	baseCfg := map[string]string{
		"base_url":      server.URL,
		"tenant_id":     "tenant",
		"token":         "test-token",
		"workspace_gid": "workspace-1",
	}
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: familyUsers, kind: "asana.users"},
		{family: familyProjects, kind: "asana.projects"},
		{family: familyAuditEvents, kind: "asana.audit_events"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			cfgValues := map[string]string{}
			for key, value := range baseCfg {
				cfgValues[key] = value
			}
			cfgValues["family"] = tt.family
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if tt.family == familyUsers && (pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "cursor-2") {
				t.Fatalf("users NextCursor = %#v, want cursor-2", pull.NextCursor)
			}
		})
	}
	if got := strings.Join(requests, "\n"); !strings.Contains(got, "/users?") || !strings.Contains(got, "/projects?") || !strings.Contains(got, "/workspaces/workspace-1/audit_log_events?") {
		t.Fatalf("requests = %s, want Asana collection paths", got)
	}
}

func TestProjectsUseModifiedAtForOccurredAt(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/projects" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("workspace"); got != "workspace-1" {
			t.Fatalf("workspace query = %q, want workspace-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"gid":           "project-1",
				"resource_type": "project",
				"name":          "Security Evidence",
				"created_at":    "2026-06-01T00:00:00Z",
				"modified_at":   "2026-06-03T00:00:00Z",
			}},
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        familyProjects,
		"token":         "test-token",
		"workspace_gid": "workspace-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["observed_at"]; got != "2026-06-03T00:00:00Z" {
		t.Fatalf("observed_at = %q, want modified_at", got)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:runtime_projects:project-1" {
		t.Fatalf("resource_urn = %q, want synthesized project URN", got)
	}
	want := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	if got := event.OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestAuditEventDoesNotFabricateAffectedResourceURN(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/workspaces/workspace-1/audit_log_events" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":          "audit-1",
				"event_type":  "project.created",
				"actor":       map[string]any{"id": "legacy-user-1", "gid": "user-1", "email": "user@example.test", "name": "User One"},
				"resource":    map[string]any{"id": "legacy-project-1", "gid": "project-1", "resource_type": "project", "name": "Security Evidence"},
				"target_name": "Target Fallback",
			}, {
				"id":         "audit-2",
				"event_type": "project.deleted",
				"actor":      map[string]any{"gid": "user-2", "email": "user2@example.test", "name": "User Two"},
				"target":     map[string]any{"gid": "target-project-2", "id": "legacy-target-project-2", "name": "Fallback Project"},
			}},
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "tenant",
		"base_url":      server.URL,
		"family":        familyAuditEvents,
		"token":         "test-token",
		"workspace_gid": "workspace-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for key, want := range map[string]string{
		"actor_id":      "user-1",
		"resource_id":   "project-1",
		"resource_name": "Security Evidence",
		"resource_type": "project",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("%s = %q, want %q; attrs=%#v", key, got, want, attrs)
		}
	}
	if got := attrs["resource_urn"]; got != "" {
		t.Fatalf("resource_urn = %q, want empty unless provider sends resource_urn", got)
	}
	fallbackAttrs := pull.Events[1].Attributes
	if got := fallbackAttrs["resource_id"]; got != "target-project-2" {
		t.Fatalf("target fallback resource_id = %q, want target gid; attrs=%#v", got, fallbackAttrs)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyUsers, familyProjects, familyAuditEvents} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyUsers, kind: "asana.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:user-1"},
		{family: familyProjects, kind: "asana.projects", wantResourceURN: "urn:cerebro:tenant:runtime_projects:project-1"},
		{family: familyAuditEvents, kind: "asana.audit_events"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}

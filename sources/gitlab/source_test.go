package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
		if r.URL.RequestURI() == "/api/v4/user" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/v4/projects" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("page"); got == "" {
			t.Fatalf("page query is empty")
		}
		if got := r.URL.Query().Get("per_page"); got == "" {
			t.Fatalf("per_page query is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 101, "name": "cerebro", "path_with_namespace": "writer/cerebro", "web_url": "https://gitlab.example.test/writer/cerebro", "last_activity_at": "2026-06-01T00:00:00Z"}})
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
	if event.Kind != "gitlab.repositories" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:runtime_repositories:101" {
		t.Fatalf("resource_urn = %q", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestNewFixtureReplaysGitLabFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyRepositories, familyUsers, familyAuditEvents} {
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
		{family: familyRepositories, kind: "gitlab.repositories", wantResourceURN: "urn:cerebro:tenant:runtime_repositories:101"},
		{family: familyUsers, kind: "gitlab.users", wantResourceURN: "urn:cerebro:tenant:runtime_users:7"},
		{family: familyAuditEvents, kind: "gitlab.audit_events", wantResourceURN: "urn:cerebro:tenant:runtime_repositories:101"},
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

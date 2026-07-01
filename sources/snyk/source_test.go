package snyk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != sourceID {
		t.Fatalf("Spec().Id = %q, want %q", got, sourceID)
	}
}

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/orgs" {
			t.Fatalf("path = %q, want /orgs", r.URL.Path)
		}
		if got := r.URL.Query().Get("version"); got != defaultAPIVersion {
			t.Fatalf("version = %q, want %q", got, defaultAPIVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id": "org-1",
			"attributes": map[string]string{
				"name":       "Security",
				"slug":       "security",
				"created_at": "2026-06-01T00:00:00Z",
				"updated_at": "2026-06-02T00:00:00Z",
			},
		}}})
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
	if event.Kind != "snyk.orgs" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["org_id"]; got != "org-1" {
		t.Fatalf("org_id = %q, want org-1", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestRuntimeUsesSnykRESTPathsAndVersionedPagination(t *testing.T) {
	for _, tt := range []struct {
		family    string
		kind      string
		path      string
		record    map[string]any
		wantAttrs map[string]string
		wantQuery map[string]string
	}{
		{
			family: familyOrgs,
			kind:   "snyk.orgs",
			path:   "/orgs",
			record: map[string]any{"id": "org-1", "attributes": map[string]any{"name": "Security", "slug": "security"}},
			wantAttrs: map[string]string{
				"org_id": "org-1",
				"name":   "Security",
			},
		},
		{
			family: familyGroups,
			kind:   "snyk.groups",
			path:   "/groups",
			record: map[string]any{"id": "group-1", "attributes": map[string]any{"name": "Engineering", "slug": "engineering"}},
			wantAttrs: map[string]string{
				"group_id": "group-1",
				"name":     "Engineering",
			},
		},
		{
			family: familyProjects,
			kind:   "snyk.projects",
			path:   "/orgs/org-1/projects",
			record: map[string]any{"id": "project-1", "attributes": map[string]any{"name": "Checkout API", "origin": "github", "type": "maven"}, "relationships": map[string]any{"target": map[string]any{"data": map[string]string{"id": "target-1"}}}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"project_id":    "project-1",
				"name":          "Checkout API",
				"target_id":     "target-1",
				"resource_type": "snyk_project",
			},
		},
		{
			family: familyTargets,
			kind:   "snyk.targets",
			path:   "/orgs/org-1/targets",
			record: map[string]any{"id": "target-1", "attributes": map[string]any{"display_name": "writer/cerebro", "source_type": "github", "url": "https://github.com/writer/cerebro", "is_private": true}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"target_id":     "target-1",
				"display_name":  "writer/cerebro",
				"is_private":    "true",
				"resource_type": "snyk_target",
			},
		},
		{
			family: familyAssets,
			kind:   "snyk.assets",
			path:   "/orgs/org-1/inventory/assets",
			record: map[string]any{"id": "asset-1", "attributes": map[string]any{"name": "writer/cerebro", "type": "repository", "updated_at": "2026-06-01T00:00:00Z"}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"asset_id":      "asset-1",
				"resource_id":   "asset-1",
				"resource_name": "writer/cerebro",
				"resource_type": "repository",
			},
		},
		{
			family: familyFindings,
			kind:   "snyk.findings",
			path:   "/orgs/org-1/issues",
			record: map[string]any{"id": "issue-1", "attributes": map[string]any{"title": "Critical package issue", "status": "open", "effective_severity_level": "critical", "type": "package_vulnerability"}, "relationships": map[string]any{"scan_item": map[string]any{"data": map[string]string{"id": "project-1", "type": "project"}}}},
			wantAttrs: map[string]string{
				"org_id":     "org-1",
				"finding_id": "issue-1",
				"severity":   "critical",
				"status":     "open",
				"issue_type": "package_vulnerability",
			},
		},
		{
			family: familyVulnerabilities,
			kind:   "snyk.vulnerabilities",
			path:   "/orgs/org-1/issues",
			record: map[string]any{"id": "vuln-1", "attributes": map[string]any{"title": "CVE-2026-0001", "status": "open", "effective_severity_level": "high", "type": "package_vulnerability"}},
			wantAttrs: map[string]string{
				"org_id":     "org-1",
				"finding_id": "vuln-1",
				"severity":   "high",
				"status":     "open",
				"issue_type": "package_vulnerability",
			},
			wantQuery: map[string]string{"type": "package_vulnerability"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Token test-token" {
					t.Fatalf("Authorization = %q, want Token test-token", got)
				}
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("path = %q, want %s", got, tt.path)
				}
				if got := r.Method; got != http.MethodGet {
					t.Fatalf("method = %q, want GET", got)
				}
				assertSnykQuery(t, r.URL.Query(), defaultAPIVersion, "100", tt.wantQuery)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{tt.record}})
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{
				"base_url":  server.URL,
				"family":    tt.family,
				"org_id":    "org-1",
				"tenant_id": "tenant",
				"token":     "test-token",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, want := range tt.wantAttrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
			for key, want := range map[string]string{
				"family":          tt.family,
				"provider":        sourceID,
				"source_provider": sourceID,
			} {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestRuntimeExtractsSnykRelativeNextLinkCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Query())
		if got := r.URL.EscapedPath(); got != "/orgs/org-1/inventory/assets" {
			t.Fatalf("path = %q, want /orgs/org-1/inventory/assets", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("starting_after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "asset-1", "attributes": map[string]string{"name": "Repo One", "type": "repository"}}},
				"links": map[string]string{
					"next": "/orgs/org-1/inventory/assets?version=2026-03-25&limit=100&starting_after=cursor-2",
				},
			})
		case "cursor-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "asset-2", "attributes": map[string]string{"name": "Repo Two", "type": "repository"}}},
			})
		default:
			t.Fatalf("starting_after = %q, want empty or cursor-2", r.URL.Query().Get("starting_after"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAssets,
		"org_id":    "org-1",
		"tenant_id": "tenant",
		"token":     "test-token",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("first NextCursor = %q, want cursor-2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "cursor-2"})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].Get("starting_after") != "cursor-2" {
		t.Fatalf("requests = %#v, want second request with starting_after=cursor-2", requests)
	}
}

func TestNewFixtureReplaysSnykFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyOrgs,
		familyGroups,
		familyProjects,
		familyTargets,
		familyAssets,
		familyFindings,
		familyVulnerabilities,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"org_id":    "org-1",
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func assertSnykQuery(t *testing.T, query url.Values, wantVersion string, wantLimit string, want map[string]string) {
	t.Helper()
	if got := query.Get("version"); got != wantVersion {
		t.Fatalf("version = %q, want %q", got, wantVersion)
	}
	if got := query.Get("limit"); got != wantLimit {
		t.Fatalf("limit = %q, want %q", got, wantLimit)
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
}

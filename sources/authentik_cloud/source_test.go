package authentik_cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

func TestCatalogDeclaresVerifiedAuthentikProviderAPI(t *testing.T) {
	payload, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog struct {
		RuntimeFamilies []string `yaml:"runtime_families"`
		ProviderAPI     struct {
			Status        string   `yaml:"status"`
			Basis         string   `yaml:"basis"`
			Transport     string   `yaml:"transport"`
			Auth          string   `yaml:"auth"`
			AuthMechanics string   `yaml:"auth_mechanics"`
			BaseURL       string   `yaml:"base_url"`
			SpecURL       string   `yaml:"spec_url"`
			SpecKind      string   `yaml:"spec_kind"`
			References    []string `yaml:"references"`
			AuthEvidence  []string `yaml:"auth_evidence"`
			ScopeEvidence []string `yaml:"scope_evidence"`
			Families      []struct {
				ID        string `yaml:"id"`
				Method    string `yaml:"method"`
				Path      string `yaml:"path"`
				Operation string `yaml:"operation"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	assertStringSet(t, catalog.RuntimeFamilies, []string{
		familyApplications,
		familyAuditEvents,
		familyGroups,
		familyRoles,
		familyUsers,
	})
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Basis != "declared" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "bearer_token" {
		t.Fatalf("provider_api = %#v, want verified declared REST bearer-token API", catalog.ProviderAPI)
	}
	if catalog.ProviderAPI.AuthMechanics != "authorization_bearer_api_token_or_oauth_access_token" || catalog.ProviderAPI.BaseURL != "${config.base_url}/api/v3" {
		t.Fatalf("provider_api auth/base = %#v", catalog.ProviderAPI)
	}
	if catalog.ProviderAPI.SpecURL != "https://raw.githubusercontent.com/goauthentik/authentik/main/schema.yml" || catalog.ProviderAPI.SpecKind != "openapi" {
		t.Fatalf("provider_api spec = %q/%q, want provider OpenAPI schema", catalog.ProviderAPI.SpecURL, catalog.ProviderAPI.SpecKind)
	}
	for _, ref := range []string{
		"https://api.goauthentik.io/",
		"https://api.goauthentik.io/authentication/",
		"https://api.goauthentik.io/reference/core-users-list/",
		"https://api.goauthentik.io/reference/core-groups-list/",
		"https://api.goauthentik.io/reference/rbac-roles-list/",
		"https://api.goauthentik.io/reference/core-applications-list/",
		"https://api.goauthentik.io/reference/events-events-list/",
		"https://raw.githubusercontent.com/goauthentik/authentik/main/schema.yml",
	} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	if len(catalog.ProviderAPI.AuthEvidence) == 0 || len(catalog.ProviderAPI.ScopeEvidence) == 0 {
		t.Fatalf("provider evidence incomplete: auth=%v scopes=%v", catalog.ProviderAPI.AuthEvidence, catalog.ProviderAPI.ScopeEvidence)
	}
	wantPaths := map[string]string{
		familyApplications: "/core/applications/",
		familyAuditEvents:  "/events/events/",
		familyGroups:       "/core/groups/",
		familyRoles:        "/rbac/roles/",
		familyUsers:        "/core/users/",
	}
	gotPaths := map[string]string{}
	for _, family := range catalog.ProviderAPI.Families {
		if family.Method != http.MethodGet {
			t.Fatalf("provider family %s method = %q, want GET", family.ID, family.Method)
		}
		if strings.TrimSpace(family.Operation) == "" {
			t.Fatalf("provider family %s operation is empty", family.ID)
		}
		gotPaths[family.ID] = family.Path
	}
	for family, want := range wantPaths {
		if got := gotPaths[family]; got != want {
			t.Fatalf("provider path for %s = %q, want %q", family, got, want)
		}
	}
}

func TestSourceCheckAndReadUsesAuthentikAPI(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []*http.Request{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v3/core/users/me/" {
			_ = json.NewEncoder(w).Encode(map[string]any{"pk": 1, "username": "admin"})
			return
		}
		if r.URL.Path != "/api/v3/core/users/" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("page"); got != "1" {
			t.Fatalf("page = %q, want 1", got)
		}
		if got := r.URL.Query().Get("page_size"); got != "1" && got != "2" {
			t.Fatalf("page_size = %q, want check page size 1 or read page size 2", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pagination": map[string]any{"next": nil, "previous": nil, "count": 1, "current": 1, "total_pages": 1},
			"results": []map[string]any{{
				"pk":           7,
				"uuid":         "9320bd09-5b73-48e1-a909-fd1e55bd31c0",
				"uid":          "authentik-user-1",
				"username":     "alice",
				"name":         "Alice Example",
				"email":        "alice@example.test",
				"is_active":    true,
				"date_joined":  "2026-06-01T00:00:00Z",
				"last_updated": "2026-06-02T00:00:00Z",
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "per_page": "2"}
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
	if event.Kind != "authentik_cloud.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	for key, want := range map[string]string{
		"user_id":      "7",
		"login":        "alice",
		"display_name": "Alice Example",
		"email":        "alice@example.test",
		"status":       "true",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want health, check, and read", len(requests))
	}
}

func TestReadAuthentikRuntimeFamiliesUseDocumentedPaths(t *testing.T) {
	wantPaths := map[string]string{
		familyApplications: "/api/v3/core/applications/",
		familyAuditEvents:  "/api/v3/events/events/",
		familyGroups:       "/api/v3/core/groups/",
		familyRoles:        "/api/v3/rbac/roles/",
		familyUsers:        "/api/v3/core/users/",
	}
	for family, wantPath := range wantPaths {
		t.Run(family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
				}
				if r.URL.Path != wantPath {
					t.Fatalf("path = %q, want %q", r.URL.Path, wantPath)
				}
				if got := r.URL.Query().Get("page"); got != "1" {
					t.Fatalf("page = %q, want 1", got)
				}
				if got := r.URL.Query().Get("page_size"); got != "1" {
					t.Fatalf("page_size = %q, want 1", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"pagination": map[string]any{"next": nil, "previous": nil, "count": 0, "current": 1, "total_pages": 1},
					"results":    []map[string]any{},
				})
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"family":    family,
				"token":     "test-token",
				"per_page":  "1",
			})
			if _, err := source.Read(context.Background(), cfg, nil); err != nil {
				t.Fatalf("Read() error = %v", err)
			}
		})
	}
}

func TestNewFixtureLoadsProviderPayloadContracts(t *testing.T) {
	fixture, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, family := range []string{familyApplications, familyAuditEvents, familyGroups, familyRoles, familyUsers} {
		cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": family})
		pull, err := fixture.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("fixture Read(%s) error = %v", family, err)
		}
		if len(pull.Events) == 0 {
			t.Fatalf("fixture Read(%s) returned no events", family)
		}
	}
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("set length = %d, want %d: got %v want %v", len(got), len(want), got, want)
	}
	seen := map[string]bool{}
	for _, value := range got {
		seen[value] = true
	}
	for _, value := range want {
		if !seen[value] {
			t.Fatalf("set = %v, missing %s", got, value)
		}
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

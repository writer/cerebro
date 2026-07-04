package bitwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

func TestCatalogDeclaresVerifiedBitwardenProviderAPI(t *testing.T) {
	raw, err := os.ReadFile("catalog.yaml")
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
			Families      []struct {
				ID        string `yaml:"id"`
				Method    string `yaml:"method"`
				Path      string `yaml:"path"`
				Operation string `yaml:"operation"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(raw, &catalog); err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Basis != "declared" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "bearer_token" {
		t.Fatalf("provider_api = %#v, want verified declared REST bearer-token API", catalog.ProviderAPI)
	}
	if catalog.ProviderAPI.AuthMechanics != "oauth2_client_credentials_access_token_scope_api_organization" || catalog.ProviderAPI.BaseURL != "${config.base_url}/public" {
		t.Fatalf("provider_api auth/base = %#v", catalog.ProviderAPI)
	}
	if catalog.ProviderAPI.SpecURL != "https://bitwarden.com/help/api/" || catalog.ProviderAPI.SpecKind != "openapi_embedded_html" {
		t.Fatalf("provider_api spec = %q/%q, want embedded OpenAPI page", catalog.ProviderAPI.SpecURL, catalog.ProviderAPI.SpecKind)
	}
	for _, ref := range []string{"https://bitwarden.com/help/public-api/", "https://bitwarden.com/help/api/"} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	gotFamilies := make([]string, 0, len(catalog.ProviderAPI.Families))
	for _, family := range catalog.ProviderAPI.Families {
		gotFamilies = append(gotFamilies, family.ID)
		if family.Method != "GET" || strings.TrimSpace(family.Path) == "" || strings.TrimSpace(family.Operation) == "" {
			t.Fatalf("provider family mapping = %#v, want documented GET path and operation", family)
		}
	}
	assertStringSet(t, gotFamilies, catalog.RuntimeFamilies)
}

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
		if r.URL.RequestURI() == "/public/organization/subscription" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/public/members" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("continuationToken"); got != "" {
			t.Fatalf("continuationToken = %q, want empty first page", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []map[string]any{{"object": "member", "id": "member-1", "userId": "user-1", "name": "Member One", "email": "member@example.test", "status": 2, "type": 1, "twoFactorEnabled": true}}, "continuationToken": "next-page"})
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
	if event.Kind != "bitwarden.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["email"] != "member@example.test" || event.Attributes["user_id"] != "member-1" {
		t.Fatalf("attributes = %#v, want member email and user id", event.Attributes)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("strings = %v, want %v", got, want)
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

package akeyless

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	fixtureBaseURL = "https://akeyless.example.test"
	fixtureToken   = "test-token"
)

func newFixtureConfig(family string, extra map[string]string) map[string]string {
	cfg := map[string]string{
		"tenant_id": "tenant",
		"base_url":  fixtureBaseURL,
		"family":    family,
		"api_token": fixtureToken,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != sourceID {
		t.Fatalf("Spec().Id = %q, want %s", source.Spec().Id, sourceID)
	}
	if source.Spec().Name != "Akeyless" {
		t.Fatalf("Spec().Name = %q, want Akeyless", source.Spec().Name)
	}
}

func TestRuntimeConfigUsesDefaultBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg, err := source.runtimeConfig(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"family":    familyItems,
		"api_token": fixtureToken,
	}))
	if err != nil {
		t.Fatalf("runtimeConfig() error = %v", err)
	}
	if got := sourcecdk.ConfigValue(cfg, "base_url"); got != defaultBaseURLTemplate {
		t.Fatalf("base_url = %q, want %q", got, defaultBaseURLTemplate)
	}
}

func TestParseSettingsRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyItems,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestParseSettingsRejectsUnknownFamily(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(newFixtureConfig("unknown", nil)))
	if err == nil {
		t.Fatal("Check(unknown) error = nil, want non-nil")
	}
}

func TestDiscoverReturnsURNsForEachFamily(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		kind    string
		payload map[string]any
	}{
		{family: familyItems, path: "/list-items", kind: "akeyless.items", payload: map[string]any{"items": []map[string]any{{"item_id": "item-1", "item_name": "DB Password", "item_type": "STATIC_SECRET", "item_state": "Enabled", "modification_date": "2026-06-01T00:00:00Z"}}}},
		{family: familyAuthMethods, path: "/list-auth-methods", kind: "akeyless.auth_methods", payload: map[string]any{"auth_methods": []map[string]any{{"auth_method_id": 7, "auth_method_name": "SAML Auth", "auth_method_access_id": "auth-1", "auth_method_type": "saml"}}}},
		{family: familyRoles, path: "/list-roles", kind: "akeyless.roles", payload: map[string]any{"roles": []map[string]any{{"role_id": 9, "role_name": "Admin Role", "comment": "Full access"}}}},
		{family: familyAnalytics, path: "/get-analytics-data", kind: "akeyless.analytics", payload: map[string]any{"date_updated": 1783296000, "usage_reports": map[string]any{"secrets": map[string]any{"total_secrets": 42, "total_clients": 7}}}},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertAkeylessRequest(t, r, tt.path)
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
					http.Error(w, "unexpected path", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.payload)
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(newFixtureConfig(tt.family, map[string]string{"base_url": server.URL}))
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tt.family, err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", tt.family, len(urns))
			}
		})
	}
}

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAkeylessRequest(t, r, "/list-items")
		if r.URL.Path != "/list-items" {
			t.Errorf("path = %q", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"item_id": "record-1", "item_name": "Record One", "item_type": "STATIC_SECRET", "item_state": "Enabled", "modification_date": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "api_token": "test-token"}
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
	if event.Kind != "akeyless.items" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadAllFamilies(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		kind    string
		payload map[string]any
		attrs   map[string]string
	}{
		{
			family:  familyItems,
			path:    "/list-items",
			kind:    "akeyless.items",
			payload: map[string]any{"items": []map[string]any{{"item_id": "item-1", "item_name": "DB Password", "item_state": "Enabled", "item_type": "STATIC_SECRET", "modification_date": "2026-06-01T00:00:00Z"}}},
			attrs:   map[string]string{"secret_id": "item-1", "secret_name": "DB Password", "secret_status": "Enabled", "secret_type": "STATIC_SECRET", "resource_id": "item-1", "resource_name": "DB Password", "source_system": "akeyless", "record_class": "secret"},
		},
		{
			family:  familyAuthMethods,
			path:    "/list-auth-methods",
			kind:    "akeyless.auth_methods",
			payload: map[string]any{"auth_methods": []map[string]any{{"auth_method_id": 7, "auth_method_name": "SAML Auth", "auth_method_access_id": "auth-1", "auth_method_type": "saml"}}},
			attrs:   map[string]string{"resource_id": "7", "resource_name": "SAML Auth", "resource_type": "saml", "source_system": "akeyless", "record_class": "asset"},
		},
		{
			family:  familyRoles,
			path:    "/list-roles",
			kind:    "akeyless.roles",
			payload: map[string]any{"roles": []map[string]any{{"role_id": 9, "role_name": "Admin Role", "comment": "Full access"}}},
			attrs:   map[string]string{"group_id": "9", "group_name": "Admin Role", "description": "Full access", "resource_id": "9", "resource_name": "Admin Role", "source_system": "akeyless", "record_class": "identity_group"},
		},
		{
			family:  familyAnalytics,
			path:    "/get-analytics-data",
			kind:    "akeyless.analytics",
			payload: map[string]any{"date_updated": 1783296000, "usage_reports": map[string]any{"secrets": map[string]any{"total_secrets": 42, "total_clients": 7}}},
			attrs:   map[string]string{"resource_id": "1783296000", "resource_type": "akeyless_analytics", "source_system": "akeyless", "record_class": "analytics_report"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertAkeylessRequest(t, r, tt.path)
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
					http.Error(w, "unexpected path", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.payload)
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(newFixtureConfig(tt.family, map[string]string{"base_url": server.URL}))
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check(%s) error = %v", tt.family, err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty")
			}
			for key, want := range tt.attrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %q = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, baseURL := range []string{
		"http://akeyless.example.test",
		"https://localhost.",
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://169.254.169.254",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  baseURL,
				"family":    familyItems,
				"api_token": fixtureToken,
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestItemSecretAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
			"item_id":           "item-42",
			"item_name":         "prod/db-password",
			"item_state":        "Enabled",
			"item_type":         "STATIC_SECRET",
			"auto_rotate":       "true",
			"creation_date":     "2026-01-01T00:00:00Z",
			"modification_date": "2026-06-01T00:00:00Z",
		}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(newFixtureConfig(familyItems, map[string]string{"base_url": server.URL}))
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	for key, want := range map[string]string{
		"secret_id":               "item-42",
		"secret_name":             "prod/db-password",
		"secret_status":           "Enabled",
		"secret_type":             "STATIC_SECRET",
		"secret_rotation_enabled": "true",
		"resource_id":             "item-42",
		"resource_name":           "prod/db-password",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func assertAkeylessRequest(t *testing.T, r *http.Request, path string) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("method = %q, want POST", r.Method)
	}
	if r.URL.Path != path {
		return
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty because Akeyless token is sent in JSON body", got)
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if got := body["token"]; got != fixtureToken {
		t.Fatalf("body token = %v, want %q", got, fixtureToken)
	}
}

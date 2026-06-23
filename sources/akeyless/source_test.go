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

func TestParseSettingsRequiresBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"family":    familyItems,
		"api_token": fixtureToken,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil")
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
		{family: familyItems, path: "/v2/items", kind: "akeyless.items", payload: map[string]any{"data": []map[string]any{{"id": "item-1", "name": "DB Password", "secret_id": "item-1", "secret_name": "DB Password", "secret_status": "active", "updated_at": "2026-06-01T00:00:00Z"}}}},
		{family: familyAuthMethods, path: "/v2/auth-methods", kind: "akeyless.auth_methods", payload: map[string]any{"data": []map[string]any{{"id": "auth-1", "name": "SAML Auth", "resource_id": "auth-1", "resource_type": "auth_method", "resource_urn": "urn:akeyless:auth:auth-1"}}}},
		{family: familyRoles, path: "/v2/roles", kind: "akeyless.roles", payload: map[string]any{"data": []map[string]any{{"id": "role-1", "name": "Admin Role", "group_id": "role-1", "group_name": "Admin Role"}}}},
		{family: familyAuditEvents, path: "/v2/audit", kind: "akeyless.audit_events", payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "login", "actor_id": "user-1", "actor_email": "admin@example.com"}}}},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RequestURI() == defaultHealthPath {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
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
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == defaultHealthPath {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v2/items" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
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
			path:    "/v2/items",
			kind:    "akeyless.items",
			payload: map[string]any{"data": []map[string]any{{"id": "item-1", "name": "DB Password", "secret_id": "item-1", "secret_name": "DB Password", "secret_status": "active", "secret_type": "static", "updated_at": "2026-06-01T00:00:00Z"}}},
			attrs:   map[string]string{"secret_id": "item-1", "secret_name": "DB Password", "secret_status": "active", "secret_type": "static", "resource_id": "item-1", "resource_name": "DB Password", "source_system": "akeyless", "record_class": "secret"},
		},
		{
			family:  familyAuthMethods,
			path:    "/v2/auth-methods",
			kind:    "akeyless.auth_methods",
			payload: map[string]any{"data": []map[string]any{{"id": "auth-1", "name": "SAML Auth", "resource_id": "auth-1", "resource_type": "auth_method", "resource_urn": "urn:akeyless:auth:auth-1"}}},
			attrs:   map[string]string{"resource_id": "auth-1", "resource_name": "SAML Auth", "resource_type": "auth_method", "resource_urn": "urn:akeyless:auth:auth-1", "source_system": "akeyless", "record_class": "asset"},
		},
		{
			family:  familyRoles,
			path:    "/v2/roles",
			kind:    "akeyless.roles",
			payload: map[string]any{"data": []map[string]any{{"id": "role-1", "name": "Admin Role", "group_id": "role-1", "group_name": "Admin Role", "group_email": "admin@example.com", "description": "Full access", "domain": "example.com"}}},
			attrs:   map[string]string{"group_id": "role-1", "group_name": "Admin Role", "group_email": "admin@example.com", "description": "Full access", "domain": "example.com", "resource_id": "role-1", "resource_name": "Admin Role", "source_system": "akeyless", "record_class": "identity_group"},
		},
		{
			family:  familyAuditEvents,
			path:    "/v2/audit",
			kind:    "akeyless.audit_events",
			payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "secret.read", "actor_id": "user-1", "actor_email": "admin@example.com", "actor_name": "Admin", "resource_id": "secret-1", "resource_name": "API Key", "resource_type": "secret"}}},
			attrs:   map[string]string{"event_type": "secret.read", "actor_id": "user-1", "actor_email": "admin@example.com", "actor_name": "Admin", "resource_id": "secret-1", "resource_name": "API Key", "resource_type": "secret", "source_system": "akeyless", "record_class": "audit_event"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RequestURI() == defaultHealthPath {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
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
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id":                      "item-42",
			"name":                    "prod/db-password",
			"secret_id":               "item-42",
			"secret_name":             "prod/db-password",
			"secret_status":           "active",
			"secret_type":             "static",
			"secret_rotation_enabled": "true",
			"created_at":              "2026-01-01T00:00:00Z",
			"updated_at":              "2026-06-01T00:00:00Z",
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
		"secret_status":           "active",
		"secret_type":             "static",
		"secret_rotation_enabled": "true",
		"resource_id":             "item-42",
		"resource_name":           "prod/db-password",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

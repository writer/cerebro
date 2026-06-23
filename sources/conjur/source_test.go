package conjur

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
	fixtureBaseURL = "https://conjur.example.test"
	fixtureToken   = "test-token"
)

func newFixtureConfig(family string, extra map[string]string) map[string]string {
	cfg := map[string]string{
		"tenant_id": "tenant",
		"base_url":  fixtureBaseURL,
		"family":    family,
		"token":     fixtureToken,
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
	if source.Spec().Name != "CyberArk Conjur" {
		t.Fatalf("Spec().Name = %q, want CyberArk Conjur", source.Spec().Name)
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
		"family":    familyResource,
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

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/resources" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
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
	if event.Kind != "conjur.resource" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestDiscoverReturnsURNsForEachFamily(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		extra   map[string]string
		payload map[string]any
	}{
		{family: familyResource, path: "/resources", payload: map[string]any{"items": []map[string]any{{"id": "res-1", "annotations": "web-secret", "resource_id": "res-1", "resource_type": "resource", "resource_urn": "urn:conjur:resource:res-1"}}}},
		{family: familyAuthenticator, path: "/authenticators", payload: map[string]any{"configured": []map[string]any{{"id": "authn-ldap", "name": "LDAP Auth"}}}},
		{family: familyResource2, path: "/resources/myaccount", extra: map[string]string{"account": "myaccount"}, payload: map[string]any{"items": []map[string]any{{"id": "res-2", "annotations": "scoped-secret"}}}},
		{family: familyResource3, path: "/resources/myaccount/variable", extra: map[string]string{"account": "myaccount", "kind": "variable"}, payload: map[string]any{"items": []map[string]any{{"id": "res-3", "annotations": "env-var"}}}},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == defaultHealthPath && r.URL.Path != tt.path {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "health-ok"}})
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.payload)
			}))
			defer server.Close()
			extra := map[string]string{"base_url": server.URL}
			for k, v := range tt.extra {
				extra[k] = v
			}
			cfg := sourcecdk.NewConfig(newFixtureConfig(tt.family, extra))
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

func TestReadAllFamilies(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		kind    string
		extra   map[string]string
		payload map[string]any
		attrs   map[string]string
	}{
		{
			family:  familyResource,
			path:    "/resources",
			kind:    "conjur.resource",
			payload: map[string]any{"items": []map[string]any{{"id": "res-1", "annotations": "web-secret", "resource_urn": "urn:conjur:resource:res-1"}}},
			attrs:   map[string]string{"resource_id": "res-1", "resource_name": "web-secret", "id": "res-1", "name": "web-secret", "source_system": "conjur", "record_class": "asset"},
		},
		{
			family:  familyAuthenticator,
			path:    "/authenticators",
			kind:    "conjur.authenticator",
			payload: map[string]any{"configured": []map[string]any{{"id": "authn-ldap", "resource_urn": "urn:conjur:authenticator:authn-ldap"}}},
			attrs:   map[string]string{"resource_id": "authn-ldap", "resource_name": "authn-ldap", "source_system": "conjur", "record_class": "asset"},
		},
		{
			family:  familyResource2,
			path:    "/resources/myaccount",
			kind:    "conjur.resource_2",
			extra:   map[string]string{"account": "myaccount"},
			payload: map[string]any{"items": []map[string]any{{"id": "res-2a", "annotations": "scoped-secret", "resource_urn": "urn:conjur:resource_2:res-2a"}}},
			attrs:   map[string]string{"resource_id": "res-2a", "resource_name": "scoped-secret", "source_system": "conjur", "record_class": "asset", "schema": "resource_2"},
		},
		{
			family:  familyResource3,
			path:    "/resources/myaccount/variable",
			kind:    "conjur.resource_3",
			extra:   map[string]string{"account": "myaccount", "kind": "variable"},
			payload: map[string]any{"items": []map[string]any{{"id": "res-3a", "annotations": "env-var", "resource_urn": "urn:conjur:resource_3:res-3a"}}},
			attrs:   map[string]string{"resource_id": "res-3a", "resource_name": "env-var", "source_system": "conjur", "record_class": "asset", "schema": "resource_3"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == defaultHealthPath && r.URL.Path != tt.path {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "health-ok"}})
					return
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.payload)
			}))
			defer server.Close()
			extra := map[string]string{"base_url": server.URL}
			for k, v := range tt.extra {
				extra[k] = v
			}
			cfg := sourcecdk.NewConfig(newFixtureConfig(tt.family, extra))
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
		"https://localhost.",
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://169.254.169.254",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  baseURL,
				"family":    familyResource,
				"token":     fixtureToken,
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestResourceAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
			"id":           "myorg:variable:db/password",
			"annotations":  "db-password",
			"resource_urn": "urn:conjur:resource:myorg:variable:db/password",
			"updated_at":   "2026-06-01T00:00:00Z",
		}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(newFixtureConfig(familyResource, map[string]string{"base_url": server.URL}))
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	for key, want := range map[string]string{
		"resource_id":   "myorg:variable:db/password",
		"resource_name": "db-password",
		"resource_urn":  "urn:conjur:resource:myorg:variable:db/password",
		"id":            "myorg:variable:db/password",
		"name":          "db-password",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

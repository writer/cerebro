package doppler

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
	fixtureBaseURL = "https://doppler.example.test"
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
	if source.Spec().Name != "Doppler" {
		t.Fatalf("Spec().Name = %q, want Doppler", source.Spec().Name)
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
		"family":    familySecrets,
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
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		if r.URL.RequestURI() == defaultHealthPath {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v3/workplace/secrets" {
			t.Errorf("path = %q", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
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
	if event.Kind != "doppler.secrets" {
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
		payload map[string]any
	}{
		{family: familySecrets, path: "/v3/workplace/secrets", payload: map[string]any{"data": []map[string]any{{"id": "secret-1", "name": "DB_PASSWORD", "secret_id": "secret-1"}}}},
		{family: familyProjects, path: "/v3/workplace/projects", payload: map[string]any{"data": []map[string]any{{"id": "proj-1", "name": "Backend API"}}}},
		{family: familyAuditEvents, path: "/v3/workplace/logs", payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "secret.read", "actor_id": "user-1"}}}},
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

func TestReadAllFamilies(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		kind    string
		payload map[string]any
		attrs   map[string]string
	}{
		{
			family:  familySecrets,
			path:    "/v3/workplace/secrets",
			kind:    "doppler.secrets",
			payload: map[string]any{"data": []map[string]any{{"id": "secret-1", "name": "DB_PASSWORD", "secret_id": "secret-1", "secret_name": "DB_PASSWORD", "secret_status": "active", "secret_type": "env_var", "updated_at": "2026-06-01T00:00:00Z"}}},
			attrs:   map[string]string{"secret_id": "secret-1", "secret_name": "DB_PASSWORD", "secret_status": "active", "secret_type": "env_var", "resource_id": "secret-1", "resource_name": "DB_PASSWORD", "source_system": "doppler", "record_class": "secret"},
		},
		{
			family:  familyProjects,
			path:    "/v3/workplace/projects",
			kind:    "doppler.projects",
			payload: map[string]any{"data": []map[string]any{{"id": "proj-1", "name": "Backend API", "resource_id": "proj-1", "resource_type": "project", "resource_urn": "urn:doppler:project:proj-1"}}},
			attrs:   map[string]string{"resource_id": "proj-1", "resource_name": "Backend API", "resource_type": "project", "resource_urn": "urn:doppler:project:proj-1", "source_system": "doppler", "record_class": "asset"},
		},
		{
			family:  familyAuditEvents,
			path:    "/v3/workplace/logs",
			kind:    "doppler.audit_events",
			payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "secret.read", "actor_id": "user-1", "actor_email": "admin@example.com", "actor_name": "Admin", "resource_id": "secret-1", "resource_name": "DB_PASSWORD", "resource_type": "secret"}}},
			attrs:   map[string]string{"event_type": "secret.read", "actor_id": "user-1", "actor_email": "admin@example.com", "actor_name": "Admin", "resource_id": "secret-1", "resource_name": "DB_PASSWORD", "resource_type": "secret", "source_system": "doppler", "record_class": "audit_event"},
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
		"http://doppler.example.test",
		"https://localhost.",
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://169.254.169.254",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  baseURL,
				"family":    familySecrets,
				"token":     fixtureToken,
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestSecretEmitsProjectJoinAttribute(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "secret-1", "name": "DB Password", "secret_id": "secret-1", "project": map[string]string{"id": "proj-1"}}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familySecrets, "token": "test-token"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["project_id"]; got != "proj-1" {
		t.Fatalf("project_id = %q, want proj-1 (attrs=%#v)", got, pull.Events[0].Attributes)
	}
}

func TestSecretAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id":                      "secret-42",
			"name":                    "STRIPE_KEY",
			"secret_id":               "secret-42",
			"secret_name":             "STRIPE_KEY",
			"secret_status":           "active",
			"secret_type":             "api_key",
			"secret_rotation_enabled": "false",
			"created_at":              "2026-01-01T00:00:00Z",
			"updated_at":              "2026-06-01T00:00:00Z",
		}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(newFixtureConfig(familySecrets, map[string]string{"base_url": server.URL}))
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	for key, want := range map[string]string{
		"secret_id":               "secret-42",
		"secret_name":             "STRIPE_KEY",
		"secret_status":           "active",
		"secret_type":             "api_key",
		"secret_rotation_enabled": "false",
		"resource_id":             "secret-42",
		"resource_name":           "STRIPE_KEY",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

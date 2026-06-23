package hashicorp_vault

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
	fixtureBaseURL = "https://vault.example.test"
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
	if source.Spec().Name != "HashiCorp Vault" {
		t.Fatalf("Spec().Name = %q, want HashiCorp Vault", source.Spec().Name)
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
		"family":    familyUsers,
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
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == defaultHealthPath {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v1/users" {
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
	if event.Kind != "hashicorp_vault.users" {
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
		{family: familyUsers, path: "/v1/users", payload: map[string]any{"data": []map[string]any{{"id": "user-1", "email": "alice@example.com", "display_name": "Alice", "status": "active"}}}},
		{family: familySecrets, path: "/v1/secrets", payload: map[string]any{"data": []map[string]any{{"id": "secret-1", "name": "API Key", "secret_id": "secret-1"}}}},
		{family: familyAuditEvents, path: "/v1/audit/events", payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "secret.read", "actor_id": "user-1"}}}},
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

func TestReadAllFamilies(t *testing.T) {
	for _, tt := range []struct {
		family  string
		path    string
		kind    string
		payload map[string]any
		attrs   map[string]string
	}{
		{
			family:  familyUsers,
			path:    "/v1/users",
			kind:    "hashicorp_vault.users",
			payload: map[string]any{"data": []map[string]any{{"id": "user-1", "email": "alice@example.com", "display_name": "Alice", "status": "active", "login": "alice", "department": "Engineering", "job_title": "SRE"}}},
			attrs:   map[string]string{"user_id": "user-1", "email": "alice@example.com", "display_name": "Alice", "status": "active", "login": "alice", "department": "Engineering", "job_title": "SRE", "resource_id": "user-1", "resource_name": "Alice", "source_system": "hashicorp_vault", "record_class": "identity_user"},
		},
		{
			family:  familySecrets,
			path:    "/v1/secrets",
			kind:    "hashicorp_vault.secrets",
			payload: map[string]any{"data": []map[string]any{{"id": "secret-1", "name": "API Key", "secret_id": "secret-1", "secret_name": "API Key", "secret_status": "active", "secret_type": "kv", "owner_id": "user-1", "updated_at": "2026-06-01T00:00:00Z"}}},
			attrs:   map[string]string{"secret_id": "secret-1", "secret_name": "API Key", "secret_status": "active", "secret_type": "kv", "owner_user_id": "user-1", "resource_id": "secret-1", "resource_name": "API Key", "source_system": "hashicorp_vault", "record_class": "secret"},
		},
		{
			family:  familyAuditEvents,
			path:    "/v1/audit/events",
			kind:    "hashicorp_vault.audit_events",
			payload: map[string]any{"data": []map[string]any{{"id": "evt-1", "event_type": "secret.read", "actor_id": "user-1", "actor_email": "alice@example.com", "actor_name": "Alice", "resource_id": "secret-1", "resource_name": "API Key", "resource_type": "secret"}}},
			attrs:   map[string]string{"event_type": "secret.read", "actor_id": "user-1", "actor_email": "alice@example.com", "actor_name": "Alice", "resource_id": "secret-1", "resource_name": "API Key", "resource_type": "secret", "source_system": "hashicorp_vault", "record_class": "audit_event"},
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
		"https://localhost.",
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://169.254.169.254",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  baseURL,
				"family":    familyUsers,
				"token":     fixtureToken,
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestSecretEmitsOwnerJoinAttribute(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "secret-1", "name": "API Key", "secret_id": "secret-1", "owner_id": "user-1"}}})
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
	if got := pull.Events[0].Attributes["owner_user_id"]; got != "user-1" {
		t.Fatalf("owner_user_id = %q, want user-1 (attrs=%#v)", got, pull.Events[0].Attributes)
	}
}

func TestUserAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id":           "user-42",
			"email":        "sre@example.com",
			"display_name": "SRE Team Lead",
			"login":        "sre-lead",
			"status":       "active",
			"department":   "Platform",
			"job_title":    "Team Lead",
			"domain":       "example.com",
		}}})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(newFixtureConfig(familyUsers, map[string]string{"base_url": server.URL}))
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	for key, want := range map[string]string{
		"user_id":       "user-42",
		"email":         "sre@example.com",
		"display_name":  "SRE Team Lead",
		"login":         "sre-lead",
		"status":        "active",
		"department":    "Platform",
		"job_title":     "Team Lead",
		"domain":        "example.com",
		"resource_id":   "user-42",
		"resource_name": "SRE Team Lead",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
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
			"id":                      "secret-99",
			"name":                    "db-root-password",
			"secret_id":               "secret-99",
			"secret_name":             "db-root-password",
			"secret_status":           "active",
			"secret_type":             "kv_v2",
			"secret_rotation_enabled": "true",
			"owner_id":                "user-42",
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
		"secret_id":               "secret-99",
		"secret_name":             "db-root-password",
		"secret_status":           "active",
		"secret_type":             "kv_v2",
		"secret_rotation_enabled": "true",
		"owner_user_id":           "user-42",
		"resource_id":             "secret-99",
		"resource_name":           "db-root-password",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

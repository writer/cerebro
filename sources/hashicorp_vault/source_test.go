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
	server := httptest.NewServer(vaultFamilyHandler(t, "/v1/identity/entity/id", true, vaultEntitiesPayload()))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": fixtureToken})
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
		family    string
		path      string
		wantList  bool
		payload   map[string]any
		wantURNID string
	}{
		{family: familyUsers, path: "/v1/identity/entity/id", wantList: true, payload: vaultEntitiesPayload(), wantURNID: "user-1"},
		{family: familySecrets, path: "/v1/sys/mounts", payload: vaultMountsPayload(), wantURNID: "secret/"},
		{family: familyAuditEvents, path: "/v1/sys/audit", payload: vaultAuditDevicesPayload(), wantURNID: "file/"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(vaultFamilyHandler(t, tt.path, tt.wantList, tt.payload))
			defer server.Close()
			cfg := sourcecdk.NewConfig(newFixtureConfig(tt.family, map[string]string{"base_url": server.URL}))
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tt.family, err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", tt.family, len(urns))
			}
			if !strings.Contains(urns[0].String(), tt.wantURNID) {
				t.Fatalf("Discover(%s) URN = %q, want id %q", tt.family, urns[0].String(), tt.wantURNID)
			}
		})
	}
}

func TestReadAllFamilies(t *testing.T) {
	for _, tt := range []struct {
		family   string
		path     string
		wantList bool
		kind     string
		payload  map[string]any
		attrs    map[string]string
	}{
		{
			family:   familyUsers,
			path:     "/v1/identity/entity/id",
			wantList: true,
			kind:     "hashicorp_vault.users",
			payload:  vaultEntitiesPayload(),
			attrs: map[string]string{
				"user_id":         "user-1",
				"email":           "alice@example.com",
				"display_name":    "Alice",
				"status":          "active",
				"login":           "alice",
				"resource_id":     "user-1",
				"resource_name":   "Alice",
				"resource_type":   "vault_identity_entity",
				"source_event_id": "user-1",
				"source_system":   "hashicorp_vault",
				"record_class":    "identity_user",
			},
		},
		{
			family:  familySecrets,
			path:    "/v1/sys/mounts",
			kind:    "hashicorp_vault.secrets",
			payload: vaultMountsPayload(),
			attrs: map[string]string{
				"secret_id":       "secret/",
				"secret_name":     "secret/",
				"secret_status":   "enabled",
				"secret_type":     "kv",
				"resource_id":     "secret/",
				"resource_name":   "secret/",
				"resource_type":   "vault_secret_engine",
				"source_event_id": "secret/",
				"source_system":   "hashicorp_vault",
				"record_class":    "secret",
				"vault_id":        "kv_123",
			},
		},
		{
			family:  familyAuditEvents,
			path:    "/v1/sys/audit",
			kind:    "hashicorp_vault.audit_events",
			payload: vaultAuditDevicesPayload(),
			attrs: map[string]string{
				"event_type":      "vault.audit_device.enabled",
				"actor_id":        "vault",
				"resource_id":     "file/",
				"resource_name":   "file/",
				"resource_type":   "vault_audit_device",
				"source_event_id": "file/",
				"source_system":   "hashicorp_vault",
				"record_class":    "audit_event",
			},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(vaultFamilyHandler(t, tt.path, tt.wantList, tt.payload))
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
		"http://vault.example.test",
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

func TestSecretEngineEmitsVaultJoinAttribute(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(vaultFamilyHandler(t, "/v1/sys/mounts", false, vaultMountsPayload()))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familySecrets, "token": fixtureToken})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["vault_id"]; got != "kv_123" {
		t.Fatalf("vault_id = %q, want kv_123 (attrs=%#v)", got, pull.Events[0].Attributes)
	}
}

func TestUserAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(vaultFamilyHandler(t, "/v1/identity/entity/id", true, vaultEntitiesPayload()))
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
		"user_id":       "user-1",
		"email":         "alice@example.com",
		"display_name":  "Alice",
		"login":         "alice",
		"status":        "active",
		"resource_id":   "user-1",
		"resource_name": "Alice",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func TestSecretEngineAttributeMapping(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(vaultFamilyHandler(t, "/v1/sys/mounts", false, vaultMountsPayload()))
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
		"secret_id":     "secret/",
		"secret_name":   "secret/",
		"secret_status": "enabled",
		"secret_type":   "kv",
		"resource_id":   "secret/",
		"resource_name": "secret/",
		"vault_id":      "kv_123",
	} {
		if got := pull.Events[0].Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func vaultFamilyHandler(t *testing.T, wantPath string, wantList bool, payload map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != fixtureToken {
			t.Errorf("X-Vault-Token = %q", got)
			http.Error(w, "unexpected token", http.StatusUnauthorized)
			return
		}
		if r.URL.RequestURI() == defaultHealthPath {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if wantList && r.URL.Query().Get("list") != "true" {
			t.Errorf("list query = %q, want true", r.URL.RawQuery)
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func vaultEntitiesPayload() map[string]any {
	return map[string]any{
		"data": map[string]any{
			"key_info": map[string]any{
				"user-1": map[string]any{
					"name":                "Alice",
					"creation_time":       "2026-01-01T00:00:00Z",
					"last_update_time":    "2026-06-01T00:00:00Z",
					"disabled":            false,
					"aliases":             []map[string]string{{"name": "alice", "mount_type": "oidc"}},
					"metadata":            map[string]string{"email": "alice@example.com", "login": "alice", "status": "active"},
					"direct_group_ids":    []string{"group-1"},
					"inherited_group_ids": []string{"group-2"},
				},
			},
			"keys": []string{"user-1"},
		},
	}
}

func vaultMountsPayload() map[string]any {
	return map[string]any{
		"data": map[string]any{
			"secret/": map[string]any{
				"accessor":    "kv_123",
				"type":        "kv",
				"description": "application secrets",
				"options":     map[string]string{"version": "2"},
				"config":      map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 0},
			},
		},
	}
}

func vaultAuditDevicesPayload() map[string]any {
	return map[string]any{
		"data": map[string]any{
			"file/": map[string]any{
				"type":        "file",
				"description": "file audit log",
				"options":     map[string]string{"file_path": "/var/log/vault_audit.log"},
			},
		},
	}
}

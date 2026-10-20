package identitysso

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

const bootstrapDoc = `{
  "tenantId": "default",
  "connection": {
    "id": "okta",
    "name": "Okta",
    "protocol": "oidc",
    "domains": ["example.com"],
    "oidc": {"issuer": "https://example.okta.com/oauth2/default", "clientId": "client-1", "clientSecretRef": "env:CEREBRO_SSO_OKTA_CLIENT_SECRET", "scopes": ["openid", "email", "groups"], "groupsClaim": "groups"},
    "roleMappings": [],
    "defaultRoles": ["cerebro.admin"],
    "jitProvisioning": true
  },
  "policy": {"enforced": true, "sessionMaxLifetimeMinutes": 480}
}`

func mustBootstrap(t *testing.T, raw string) *sso.Bootstrap {
	t.Helper()
	bootstrap, err := sso.ParseBootstrap([]byte(raw))
	if err != nil {
		t.Fatalf("ParseBootstrap: %v", err)
	}
	return bootstrap
}

func newBootstrapHarness(t *testing.T, bootstrap *sso.Bootstrap) *harness {
	t.Helper()
	h := &harness{t: t, store: newFakeStore(), now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	handler := Handler{
		store:   h.store,
		resolve: func(_ context.Context, requested string) (string, error) { return requested, nil },
		actor:   func(context.Context) string { return "admin@example.com" },
		now:     func() time.Time { return h.now },
	}.WithBootstrap(bootstrap)
	h.mux = newTestMux(handler)
	return h
}

func TestSeedBootstrapCreatesActiveConnectionAndPolicy(t *testing.T) {
	bootstrap := mustBootstrap(t, bootstrapDoc)
	store := newFakeStore()
	first := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if err := sso.SeedBootstrap(context.Background(), store, bootstrap, first); err != nil {
		t.Fatalf("SeedBootstrap: %v", err)
	}
	conn, err := store.GetSSOConnection(context.Background(), "default", "okta")
	if err != nil {
		t.Fatalf("GetSSOConnection: %v", err)
	}
	if conn.Status != sso.StatusActive || conn.UpdatedBy != sso.BootstrapActor || !conn.CreatedAt.Equal(first) {
		t.Fatalf("seeded connection = %+v", conn)
	}
	if conn.OIDC == nil || conn.OIDC.ClientSecretRef != "env:CEREBRO_SSO_OKTA_CLIENT_SECRET" {
		t.Fatalf("seeded oidc = %+v", conn.OIDC)
	}
	policy, err := store.GetSSOPolicy(context.Background(), "default")
	if err != nil {
		t.Fatalf("GetSSOPolicy: %v", err)
	}
	if !policy.Enforced || policy.SessionMaxLifetimeMinutes != 480 {
		t.Fatalf("seeded policy = %+v", policy)
	}
}

func TestSeedBootstrapOverwritesConfigButKeepsCreatedAt(t *testing.T) {
	store := newFakeStore()
	first := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if err := sso.SeedBootstrap(context.Background(), store, mustBootstrap(t, bootstrapDoc), first); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	stale, _ := store.GetSSOConnection(context.Background(), "default", "okta")
	stale.Status = sso.StatusDisabled
	stale.Domains = []string{"stale.example.com"}
	if err := store.PutSSOConnection(context.Background(), stale, sso.MaxConnections); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	updated := strings.Replace(bootstrapDoc, `"name": "Okta"`, `"name": "Okta SSO"`, 1)
	second := first.Add(time.Hour)
	if err := sso.SeedBootstrap(context.Background(), store, mustBootstrap(t, updated), second); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	conn, _ := store.GetSSOConnection(context.Background(), "default", "okta")
	if conn.Name != "Okta SSO" || conn.Status != sso.StatusActive || conn.Domains[0] != "example.com" {
		t.Fatalf("reseeded connection = %+v", conn)
	}
	if !conn.CreatedAt.Equal(first) {
		t.Fatalf("createdAt = %s, want %s", conn.CreatedAt, first)
	}
	if err := sso.SeedBootstrap(context.Background(), store, mustBootstrap(t, updated), second.Add(time.Hour)); err != nil {
		t.Fatalf("idempotent seed: %v", err)
	}
}

func TestSeedBootstrapFailsOnDomainConflict(t *testing.T) {
	h := newHarness(t)
	h.activeConnection("Other", "example.com")
	err := sso.SeedBootstrap(context.Background(), h.store, mustBootstrap(t, bootstrapDoc), h.now)
	if err == nil || !errors.Is(err, ports.ErrSSODomainConflict) {
		t.Fatalf("SeedBootstrap error = %v, want domain conflict", err)
	}
}

func TestSeedBootstrapRequiresStore(t *testing.T) {
	if err := sso.SeedBootstrap(context.Background(), nil, mustBootstrap(t, bootstrapDoc), time.Now()); err == nil {
		t.Fatal("SeedBootstrap without a store succeeded")
	}
}

func TestSeedConfiguredBootstrap(t *testing.T) {
	bootstrap := mustBootstrap(t, bootstrapDoc)
	if err := sso.SeedConfiguredBootstrap(context.Background(), struct{}{}, nil); err != nil {
		t.Fatalf("unset bootstrap: %v", err)
	}
	if err := sso.SeedConfiguredBootstrap(context.Background(), struct{}{}, bootstrap); err == nil {
		t.Fatal("seeded into a store without identity SSO support")
	}
	var typedNil *fakeStore
	if err := sso.SeedConfiguredBootstrap(context.Background(), typedNil, bootstrap); err == nil {
		t.Fatal("seeded into a typed-nil store")
	}
	//nolint:staticcheck // A nil context is the misuse being tested.
	if err := sso.SeedConfiguredBootstrap(nil, newFakeStore(), bootstrap); err == nil {
		t.Fatal("seeded without a context")
	}
	store := newFakeStore()
	if err := sso.SeedConfiguredBootstrap(context.Background(), store, bootstrap); err != nil {
		t.Fatalf("SeedConfiguredBootstrap: %v", err)
	}
	if _, err := store.GetSSOConnection(context.Background(), "default", "okta"); err != nil {
		t.Fatalf("connection not seeded: %v", err)
	}
}

func TestBootstrapManagedConnectionIsReadOnly(t *testing.T) {
	bootstrap := mustBootstrap(t, bootstrapDoc)
	h := newBootstrapHarness(t, bootstrap)
	if err := sso.SeedBootstrap(context.Background(), h.store, bootstrap, h.now); err != nil {
		t.Fatalf("SeedBootstrap: %v", err)
	}

	got := h.expect(h.do(http.MethodGet, "/platform/identity/sso/connections/okta", nil), http.StatusOK)
	if managed, _ := got.body["managed"].(bool); !managed {
		t.Fatalf("managed = %v, want true; body = %s", got.body["managed"], got.raw)
	}
	list := h.expect(h.do(http.MethodGet, "/platform/identity/sso/connections", nil), http.StatusOK)
	connections, _ := list.body["connections"].([]any)
	if len(connections) != 1 || connections[0].(map[string]any)["managed"] != true {
		t.Fatalf("list = %s", list.raw)
	}

	body := oidcConnection("Okta", "example.com")
	body["status"] = "disabled"
	h.expectError(h.do(http.MethodPut, "/platform/identity/sso/connections/okta", body), http.StatusConflict, "bootstrap_managed")
	h.expectError(h.do(http.MethodDelete, "/platform/identity/sso/connections/okta", nil), http.StatusConflict, "bootstrap_managed")
	h.expectError(
		h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": false, "sessionMaxLifetimeMinutes": 480, "sessionIdleTimeoutMinutes": 60}),
		http.StatusConflict,
		"bootstrap_managed",
	)
	h.expect(
		h.do(http.MethodPut, "/platform/identity/sso/policy", map[string]any{"enforced": true, "sessionMaxLifetimeMinutes": 600, "sessionIdleTimeoutMinutes": 60}),
		http.StatusOK,
	)

	other := h.expect(h.do(http.MethodPost, "/platform/identity/sso/connections", oidcConnection("Other", "other.example.com")), http.StatusCreated)
	if managed, _ := other.body["managed"].(bool); managed {
		t.Fatalf("unmanaged connection reported managed: %s", other.raw)
	}
	h.expect(h.do(http.MethodDelete, "/platform/identity/sso/connections/"+other.body["id"].(string), nil), http.StatusNoContent)
}

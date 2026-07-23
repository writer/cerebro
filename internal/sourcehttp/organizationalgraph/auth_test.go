package organizationalgraph

import (
	"net/http"
	"testing"
)

const testSharedSecret = "test-organizational-graph-secret-32-bytes"

func TestTenantAuthenticatorBindsTokenToTenant(t *testing.T) {
	auth, err := newTenantAuthenticator(testSharedSecret)
	if err != nil {
		t.Fatalf("newTenantAuthenticator() error = %v", err)
	}
	requestA, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	requestB, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if err := auth.authorize(requestA, "tenant-a"); err != nil {
		t.Fatalf("authorize(tenant-a) error = %v", err)
	}
	if err := auth.authorize(requestB, "tenant-b"); err != nil {
		t.Fatalf("authorize(tenant-b) error = %v", err)
	}
	if requestA.Header.Get("Authorization") == requestB.Header.Get("Authorization") {
		t.Fatal("tenant-bound authorization tokens are equal")
	}
	if got := requestA.Header.Get(tenantAuthHeader); got != "tenant-a" {
		t.Fatalf("%s = %q, want tenant-a", tenantAuthHeader, got)
	}
	const expected = "Bearer 34b1625abbaa7a28cbca5f0a4803c1ba5360a998e5cc2f5b28d37bd32ba131d6"
	if got := requestA.Header.Get("Authorization"); got != expected {
		t.Fatalf("Authorization = %q, want shared Go/Rust test vector", got)
	}
}

func TestTenantAuthenticatorRejectsShortSecret(t *testing.T) {
	if _, err := newTenantAuthenticator("too-short"); err == nil {
		t.Fatal("newTenantAuthenticator(short secret) error = nil")
	}
}

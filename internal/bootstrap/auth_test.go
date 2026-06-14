package bootstrap

import (
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestTenantAllowedFailsClosedForUnscopedPrincipal(t *testing.T) {
	principal := authPrincipal{AuthMode: "api_key"}
	if tenantAllowed(config.AuthConfig{}, principal, "writer") {
		t.Fatal("tenantAllowed() = true for unscoped principal and non-empty tenant, want false")
	}
}

func TestTenantAllowedUsesExplicitGlobalAllowlistForUnscopedPrincipal(t *testing.T) {
	principal := authPrincipal{AuthMode: "api_key"}
	cfg := config.AuthConfig{AllowedTenants: []string{"writer"}}
	if !tenantAllowed(cfg, principal, "writer") {
		t.Fatal("tenantAllowed() = false for globally allowed tenant, want true")
	}
	if tenantAllowed(cfg, principal, "security") {
		t.Fatal("tenantAllowed() = true for tenant outside global allowlist, want false")
	}
}

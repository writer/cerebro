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

func TestAccessAuditCredentialTier(t *testing.T) {
	for _, tt := range []struct {
		name      string
		principal authPrincipal
		want      string
	}{
		{name: "admin api key", principal: authPrincipal{AuthMode: "api_key"}, want: "admin"},
		{name: "scoped token", principal: authPrincipal{AuthMode: "api_key", Scopes: []string{scopeCosmoSecurityRead}}, want: "scoped"},
		{name: "device", principal: authPrincipal{AuthMode: "device_jwt", Scopes: []string{scopeCosmoSecurityRead}}, want: "device"},
		{name: "anonymous", principal: authPrincipal{}, want: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := accessAuditCredentialTier(tt.principal); got != tt.want {
				t.Fatalf("accessAuditCredentialTier() = %q, want %q", got, tt.want)
			}
		})
	}
}

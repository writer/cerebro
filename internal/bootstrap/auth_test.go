package bootstrap

import (
	"testing"
	"time"

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
		{name: "rbac role", principal: authPrincipal{AuthMode: "api_credential", Roles: []string{roleCerebroViewer}}, want: "rbac"},
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

func TestCapabilityTokenCanAuthorizeWithRoleOnlyGrant(t *testing.T) {
	cfg := config.AuthConfig{
		CapabilityTokenSecrets:  []string{"capability-secret"},
		CapabilityTokenAudience: "cerebro-api",
	}
	token, err := issueCapabilityToken(cfg, capabilityClaims{
		Audience: cfg.CapabilityTokenAudience,
		Subject:  "service:viewer",
		TenantID: "writer",
		Roles:    []string{roleCerebroViewer},
		Groups:   []string{"security"},
	}, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("issueCapabilityToken: %v", err)
	}
	principal, ok := authenticateCapabilityToken(cfg, token, time.Now())
	if !ok {
		t.Fatal("authenticateCapabilityToken() rejected role-only token")
	}
	if got := expandedPrincipalScopes(principal); len(got) != 2 || got[0] != scopeCosmoSecurityRead || got[1] != scopeUserPreferencesWrite {
		t.Fatalf("expanded scopes = %#v, want [%s %s]", got, scopeCosmoSecurityRead, scopeUserPreferencesWrite)
	}
	if err := authorizePrincipalHTTPPolicy(principal, httpRoutePolicyFor("GET", "/sources")); err != nil {
		t.Fatalf("role-only capability token rejected for read route: %v", err)
	}
}

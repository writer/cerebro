package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestEvidenceMaximumSensitivityUsesPrincipalScopes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		scopes []string
		want   string
	}{
		{name: "missing principal", want: ports.EvidenceSensitivityPublic},
		{name: "unscoped administrator", scopes: []string{}, want: ports.EvidenceSensitivityRestricted},
		{name: "security reader", scopes: []string{scopeCosmoSecurityRead}, want: ports.EvidenceSensitivityInternal},
		{name: "GRC writer", scopes: []string{scopeCosmoSecurityRead, scopeGRCInventoryWrite}, want: ports.EvidenceSensitivityRestricted},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.scopes != nil {
				ctx = context.WithValue(ctx, authContextKey{}, authContext{principal: authPrincipal{Scopes: test.scopes}})
			}
			if got := evidenceMaximumSensitivity(ctx); got != test.want {
				t.Fatalf("evidenceMaximumSensitivity() = %q, want %q", got, test.want)
			}
		})
	}
}

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

func TestApplicationWorkspaceAuthorizationIsTenantQualifiedAndBackwardCompatible(t *testing.T) {
	legacy := authPrincipal{TenantID: "tenant-a"}
	if !applicationWorkspaceAllowed(legacy, "tenant-a", "workspace-any") {
		t.Fatal("principal with omitted application workspace grants lost legacy access")
	}

	restricted := authPrincipal{
		AllowedTenants: []string{"tenant-a", "tenant-b"},
		ApplicationWorkspaceGrants: []config.ApplicationWorkspaceGrant{
			{TenantID: "tenant-a", ApplicationWorkspaceIDs: []string{"workspace-shared"}},
			{TenantID: "tenant-b", ApplicationWorkspaceIDs: []string{"workspace-b"}},
		},
	}
	if !applicationWorkspaceAllowed(restricted, "tenant-a", "workspace-shared") {
		t.Fatal("tenant-a workspace grant was rejected")
	}
	if applicationWorkspaceAllowed(restricted, "tenant-b", "workspace-shared") {
		t.Fatal("workspace authority crossed tenants")
	}
	if applicationWorkspaceAllowed(restricted, "tenant-a", "workspace-other") {
		t.Fatal("ungranted application workspace was authorized")
	}
}

func TestCapabilityTokenPreservesApplicationWorkspaceGrants(t *testing.T) {
	cfg := config.AuthConfig{
		CapabilityTokenSecrets:  []string{"capability-secret"},
		CapabilityTokenAudience: "cerebro-api",
	}
	token, err := issueCapabilityToken(cfg, capabilityClaims{
		Audience: cfg.CapabilityTokenAudience,
		Subject:  "service:workspace-reader",
		TenantID: "tenant-a",
		Scopes:   []string{scopeCosmoSecurityRead},
		ApplicationWorkspaceGrants: []config.ApplicationWorkspaceGrant{
			{TenantID: "tenant-a", ApplicationWorkspaceIDs: []string{"workspace-b", "workspace-a", "workspace-a"}},
		},
	}, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("issueCapabilityToken() error = %v", err)
	}
	principal, ok := authenticateCapabilityToken(cfg, token, time.Now())
	if !ok {
		t.Fatal("authenticateCapabilityToken() rejected application workspace grant")
	}
	grants := principal.ApplicationWorkspaceGrants
	if len(grants) != 1 || grants[0].TenantID != "tenant-a" || len(grants[0].ApplicationWorkspaceIDs) != 2 || grants[0].ApplicationWorkspaceIDs[0] != "workspace-a" || grants[0].ApplicationWorkspaceIDs[1] != "workspace-b" {
		t.Fatalf("application workspace grants = %#v, want normalized tenant-a grant", grants)
	}
}

func TestCapabilityTokenRejectsApplicationWorkspaceGrantOutsideTenantAuthority(t *testing.T) {
	cfg := config.AuthConfig{
		CapabilityTokenSecrets:  []string{"capability-secret"},
		CapabilityTokenAudience: "cerebro-api",
	}
	_, err := issueCapabilityToken(cfg, capabilityClaims{
		Audience: cfg.CapabilityTokenAudience,
		Subject:  "service:workspace-reader",
		TenantID: "tenant-a",
		Scopes:   []string{scopeCosmoSecurityRead},
		ApplicationWorkspaceGrants: []config.ApplicationWorkspaceGrant{
			{TenantID: "tenant-b", ApplicationWorkspaceIDs: []string{"workspace-b"}},
		},
	}, time.Minute, time.Now())
	if err == nil {
		t.Fatal("issueCapabilityToken() error = nil, want cross-tenant workspace grant rejection")
	}
}

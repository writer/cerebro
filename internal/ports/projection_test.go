package ports

import (
	"errors"
	"strings"
	"testing"
)

func requireProjectedTenantScopeError(t *testing.T, err error, field, urn string) {
	t.Helper()
	if !errors.Is(err, ErrProjectedTenantScope) {
		t.Fatalf("error = %v, want %v", err, ErrProjectedTenantScope)
	}
	var scopeErr *ProjectedTenantScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("error = %T, want *ProjectedTenantScopeError", err)
	}
	if scopeErr.Field != field || scopeErr.URN != urn || scopeErr.URNTenantID != "victim" || scopeErr.ProjectionTenantID != "writer" {
		t.Fatalf("scope error = %#v", scopeErr)
	}
}

func TestValidateProjectedTenantScopesRejectsCrossTenantCerebroURNs(t *testing.T) {
	err := ValidateProjectedTenantScopes(
		[]*ProjectedEntity{
			{URN: "urn:cerebro:writer:asset:ok", TenantID: "writer"},
			{URN: "arn:aws:s3:::shared-bucket", TenantID: "writer"},
			{URN: "urn:cerebro:victim:asset:stolen", TenantID: "writer"},
		},
		nil,
	)
	if err == nil {
		t.Fatal("ValidateProjectedTenantScopes() error = nil, want cross-tenant Cerebro URN error")
	}
	requireProjectedTenantScopeError(t, err, "projected entity urn", "urn:cerebro:victim:asset:stolen")
}

func TestValidateProjectedTenantScopesAllowsSameTenantAndExternalURNs(t *testing.T) {
	err := ValidateProjectedTenantScopes(
		[]*ProjectedEntity{
			{URN: "urn:cerebro:writer:asset:ok", TenantID: "writer"},
			{URN: "arn:aws:s3:::shared-bucket", TenantID: "writer"},
		},
		[]*ProjectedLink{
			{
				TenantID: "writer",
				FromURN:  "urn:cerebro:writer:asset:ok",
				ToURN:    "https://example.test/resource",
			},
		},
	)
	if err != nil {
		t.Fatalf("ValidateProjectedTenantScopes() error = %v", err)
	}
}

func TestValidateProjectedTenantScopesRejectsCrossTenantLinkEndpoint(t *testing.T) {
	err := ValidateProjectedTenantScopes(nil, []*ProjectedLink{
		{
			TenantID: "writer",
			FromURN:  "urn:cerebro:writer:asset:ok",
			ToURN:    "urn:cerebro:victim:asset:target",
		},
	})
	if err == nil {
		t.Fatal("ValidateProjectedTenantScopes() error = nil, want cross-tenant link endpoint error")
	}
	requireProjectedTenantScopeError(t, err, "projected link to urn", "urn:cerebro:victim:asset:target")
}

func TestValidateApplicationWorkspaceScopeIsTenantQualifiedAndBounded(t *testing.T) {
	if got, err := ValidateApplicationWorkspaceScope("tenant-a", " workspace-a "); err != nil || got != "workspace-a" {
		t.Fatalf("ValidateApplicationWorkspaceScope() = %q, %v", got, err)
	}
	for _, test := range []struct {
		tenantID    string
		workspaceID string
	}{
		{workspaceID: "workspace-a"},
		{tenantID: "tenant-a", workspaceID: "*"},
		{tenantID: "tenant-a", workspaceID: "workspace-a,workspace-b"},
		{tenantID: "tenant-a", workspaceID: "workspace\nother"},
	} {
		if _, err := ValidateApplicationWorkspaceScope(test.tenantID, test.workspaceID); err == nil {
			t.Fatalf("ValidateApplicationWorkspaceScope(%q, %q) error = nil", test.tenantID, test.workspaceID)
		}
	}
	if got, err := ValidateApplicationWorkspaceScope("", ""); err != nil || got != "" {
		t.Fatalf("blank tenant-wide legacy scope = %q, %v", got, err)
	}
	if got, err := ValidateApplicationWorkspaceScope("tenant-a", strings.Repeat("w", 128)); err != nil || len(got) != 128 {
		t.Fatalf("128-byte workspace scope = %q, %v", got, err)
	}
	if _, err := ValidateApplicationWorkspaceScope("tenant-a", strings.Repeat("w", 129)); err == nil {
		t.Fatal("129-byte workspace scope error = nil")
	}
}

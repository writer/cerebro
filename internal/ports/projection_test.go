package ports

import (
	"errors"
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

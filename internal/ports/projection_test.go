package ports

import (
	"strings"
	"testing"
)

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
	if got := err.Error(); !strings.Contains(got, "urn:cerebro:victim:asset:stolen") || !strings.Contains(got, "not projection tenant") {
		t.Fatalf("ValidateProjectedTenantScopes() error = %q", got)
	}
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
	if got := err.Error(); !strings.Contains(got, "projected link to urn") || !strings.Contains(got, "not projection tenant") {
		t.Fatalf("ValidateProjectedTenantScopes() error = %q", got)
	}
}

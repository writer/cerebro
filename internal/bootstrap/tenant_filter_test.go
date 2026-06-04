package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/config"
)

func TestEffectiveTenantFilterDefaultsPrincipalTenant(t *testing.T) {
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "writer"},
	})

	tenantID, err := effectiveTenantFilter(ctx, "")
	if err != nil {
		t.Fatalf("effectiveTenantFilter error = %v", err)
	}
	if tenantID != "writer" {
		t.Fatalf("tenantID = %q, want writer", tenantID)
	}
}

func TestEffectiveTenantFilterRejectsAmbiguousAllowedTenantScope(t *testing.T) {
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{AllowedTenants: []string{"writer"}},
		principal: authPrincipal{},
	})

	_, err := effectiveTenantFilter(ctx, "")
	if !errors.Is(err, errTenantForbidden) {
		t.Fatalf("effectiveTenantFilter error = %v, want %v", err, errTenantForbidden)
	}
}

func TestEffectiveTenantFilterRejectsCrossTenantRequest(t *testing.T) {
	ctx := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "writer"},
	})

	_, err := effectiveTenantFilter(ctx, "other")
	if !errors.Is(err, errTenantForbidden) {
		t.Fatalf("effectiveTenantFilter error = %v, want %v", err, errTenantForbidden)
	}
}

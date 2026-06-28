package bootstrap

import (
	"context"
	"errors"
	"net/http"
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

func TestScopeForHTTPRequestCoversPlatformJobAndRuntimeResponseReads(t *testing.T) {
	for _, path := range []string{
		"/platform/jobs",
		"/platform/jobs/job-123",
		"/platform/jobs/job-123/events",
		"/platform/runtime-response/capabilities",
		"/platform/runtime-response/blocklist",
	} {
		request, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q) error = %v", path, err)
		}
		if got := httpRoutePolicyForRequest(request).Scope; got != scopeCosmoSecurityRead {
			t.Fatalf("scopeForHTTPRequest(%s) = %q, want %q", path, got, scopeCosmoSecurityRead)
		}
	}
}

func TestPersonAccessPathsRouteUsesGraphReadScope(t *testing.T) {
	const path = "/platform/graph/person-access-paths"
	request, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q) error = %v", path, err)
	}
	if got := httpRoutePolicyForRequest(request).Scope; got != scopeCosmoSecurityRead {
		t.Fatalf("scopeForHTTPRequest(%s) = %q, want %q", path, got, scopeCosmoSecurityRead)
	}
	if !isKnownStaticAccessPath(path) {
		t.Fatalf("isKnownStaticAccessPath(%s) = false, want true", path)
	}
}

func TestRuntimeResponseTrustedScopeIsServerDerived(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "/platform/runtime-response/actions", nil)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}
	if got := httpRoutePolicyForRequest(request).Scope; got != scopeRuntimeResponseWrite {
		t.Fatalf("scopeForHTTPRequest(runtime response action) = %q, want %q", got, scopeRuntimeResponseWrite)
	}

	restricted := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{Scopes: []string{scopeCosmoSecurityRead}},
	})
	if hasRuntimeResponseTrustedScope(restricted) {
		t.Fatal("read-only scoped principal has trusted runtime response scope")
	}

	writer := context.WithValue(context.Background(), authContextKey{}, authContext{
		principal: authPrincipal{Scopes: []string{scopeRuntimeResponseWrite}},
	})
	if !hasRuntimeResponseTrustedScope(writer) {
		t.Fatal("runtime response write scope was not trusted")
	}
}

func TestGRCInventoryScopeMutationRequiresWriteScope(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/grc/inventory/resource-scope"},
		{method: http.MethodPost, path: "/grc/inventory/accountability"},
		{method: http.MethodPost, path: "/grc/inventory/asset-reports"},
		{method: http.MethodPatch, path: "/grc/inventory/asset-reports/report-1/triage"},
		{method: http.MethodPost, path: "/grc/vendor-discoveries/urn:cerebro:writer:vendor_discovery:grc:shadow/decision"},
	} {
		request, err := http.NewRequest(tc.method, tc.path, nil)
		if err != nil {
			t.Fatalf("NewRequest error = %v", err)
		}
		if got := httpRoutePolicyForRequest(request).Scope; got != scopeGRCInventoryWrite {
			t.Fatalf("scopeForHTTPRequest(%s %s) = %q, want %q", tc.method, tc.path, got, scopeGRCInventoryWrite)
		}
	}

	readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
	if err := authorizePrincipalScope(readOnly, scopeGRCInventoryWrite); err == nil {
		t.Fatal("read-only scoped principal authorized for GRC inventory write scope")
	}
}

func TestGRCPolicyLifecycleActionRequiresWriteScope(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "/grc/policy-lifecycle/actions", nil)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}
	if got := httpRoutePolicyForRequest(request).Scope; got != scopeGRCPolicyLifecycleWrite {
		t.Fatalf("scopeForHTTPRequest(policy action) = %q, want %q", got, scopeGRCPolicyLifecycleWrite)
	}

	readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
	if err := authorizePrincipalScope(readOnly, scopeGRCPolicyLifecycleWrite); err == nil {
		t.Fatal("read-only scoped principal authorized for policy lifecycle write scope")
	}
}

func TestRequireMatchingJobTenantRejectsMismatchedTargetTenant(t *testing.T) {
	if err := requireMatchingJobTenant("tenant-a", "tenant-a"); err != nil {
		t.Fatalf("matching tenants error = %v", err)
	}
	if err := requireMatchingJobTenant("", "tenant-a"); err != nil {
		t.Fatalf("empty job tenant should allow target-derived tenant, got %v", err)
	}
	if err := requireMatchingJobTenant("tenant-a", "tenant-b"); !errors.Is(err, errTenantForbidden) {
		t.Fatalf("mismatched tenants error = %v, want %v", err, errTenantForbidden)
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

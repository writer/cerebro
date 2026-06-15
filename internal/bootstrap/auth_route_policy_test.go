package bootstrap

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
)

func TestPlatformHTTPRoutesHaveAuthPolicies(t *testing.T) {
	root := bootstrapRepoRoot(t)
	// #nosec G304 -- fixed repo-relative guardrail path derived from runtime.Caller.
	body, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "routes.go"))
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	routePattern := regexp.MustCompile(`registerHTTPRoute\(mux, "([A-Z]+) ([^"]+)", (routeSurface[A-Za-z]+)`)
	for _, match := range routePattern.FindAllStringSubmatch(string(body), -1) {
		method := match[1]
		route := match[2]
		surface := match[3]
		if surface != "routeSurfacePlatformHTTP" {
			continue
		}
		path := sampleRoutePath(route)
		policy := httpRoutePolicyFor(method, path)
		if !routePolicyPathMatches(policy, path) {
			t.Fatalf("%s %s has no matching auth route policy", method, route)
		}
		if policy.Scope == "" && !policy.AdminOnly {
			t.Fatalf("%s %s auth policy must declare a scope or be explicitly admin-only", method, route)
		}
	}
}

func TestConnectProceduresHaveAuthPolicies(t *testing.T) {
	root := bootstrapRepoRoot(t)
	// #nosec G304 -- fixed repo-relative guardrail path derived from runtime.Caller.
	body, err := os.ReadFile(filepath.Join(root, "gen", "cerebro", "v1", "cerebrov1connect", "bootstrap.connect.go"))
	if err != nil {
		t.Fatalf("read bootstrap.connect.go: %v", err)
	}
	procedurePattern := regexp.MustCompile(`BootstrapService[A-Za-z0-9]+Procedure\s*=\s*"([^"]+)"`)
	for _, match := range procedurePattern.FindAllStringSubmatch(string(body), -1) {
		procedure := match[1]
		if !connectProcedurePolicyKnown(procedure) {
			t.Fatalf("%s has no explicit Connect auth policy", procedure)
		}
	}
}

func TestFindingLifecycleHTTPRoutesRequireWriteScope(t *testing.T) {
	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/findings/finding-1/resolve"},
		{method: http.MethodPost, path: "/findings/finding-1/suppress"},
		{method: http.MethodPut, path: "/findings/finding-1/assign"},
		{method: http.MethodPut, path: "/findings/finding-1/due"},
		{method: http.MethodPost, path: "/findings/finding-1/notes"},
		{method: http.MethodPost, path: "/findings/finding-1/tickets"},
	} {
		policy := httpRoutePolicyFor(tt.method, tt.path)
		if policy.Scope != scopeFindingLifecycleWrite || policy.AdminOnly {
			t.Fatalf("%s %s policy = %#v, want findings write scope", tt.method, tt.path, policy)
		}
	}
}

func TestFindingLifecycleConnectProceduresRequireWriteScope(t *testing.T) {
	for _, procedure := range []string{
		cerebrov1connect.BootstrapServiceResolveFindingProcedure,
		cerebrov1connect.BootstrapServiceSuppressFindingProcedure,
		cerebrov1connect.BootstrapServiceAssignFindingProcedure,
		cerebrov1connect.BootstrapServiceSetFindingDueDateProcedure,
		cerebrov1connect.BootstrapServiceAddFindingNoteProcedure,
		cerebrov1connect.BootstrapServiceLinkFindingTicketProcedure,
	} {
		policy := connectProcedurePolicyFor(procedure)
		if policy.Scope != scopeFindingLifecycleWrite || policy.AdminOnly {
			t.Fatalf("%s policy = %#v, want findings write scope", procedure, policy)
		}
	}
}

func sampleRoutePath(route string) string {
	placeholder := regexp.MustCompile(`\{[^}]+\}`)
	return placeholder.ReplaceAllString(strings.TrimSpace(route), "sample")
}

func bootstrapRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

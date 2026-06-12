package bootstrap

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
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
		if policy.Scope == "" && !policy.Static {
			t.Fatalf("%s %s auth policy must declare a scope or be explicitly static", method, route)
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

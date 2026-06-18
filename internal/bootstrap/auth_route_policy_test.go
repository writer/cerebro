package bootstrap

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/agentplatform"
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
		{method: http.MethodPost, path: "/findings/finding-1/external-refs"},
	} {
		policy := httpRoutePolicyFor(tt.method, tt.path)
		if policy.Scope != scopeFindingLifecycleWrite || policy.AdminOnly {
			t.Fatalf("%s %s policy = %#v, want findings write scope", tt.method, tt.path, policy)
		}
	}
}

func TestGraphActionHTTPRoutesRequireDedicatedScope(t *testing.T) {
	policy := httpRoutePolicyFor(http.MethodPost, "/platform/graph/actions")
	if policy.Scope != scopeGraphActionsWrite || policy.AdminOnly {
		t.Fatalf("POST /platform/graph/actions policy = %#v, want graph action write scope", policy)
	}
}

func TestConnectorCredentialBrokerHTTPRouteRequiresWriteScope(t *testing.T) {
	policy := httpRoutePolicyFor(http.MethodPost, "/connectors/aws/credentials")
	if policy.Scope != scopeConnectorCredentialsWrite || policy.AdminOnly {
		t.Fatalf("POST /connectors/{sourceID}/credentials policy = %#v, want connector credential write scope", policy)
	}
	for _, path := range []string{
		"/connectors/aws/credentials",
		"/connectors/aws/credentials/cred_123",
	} {
		policy := httpRoutePolicyFor(http.MethodGet, path)
		if policy.Scope != scopeConnectorCredentialsRead || policy.AdminOnly {
			t.Fatalf("GET %s policy = %#v, want connector credential read scope", path, policy)
		}
	}
	for _, path := range []string{
		"/connectors/aws/credentials/cred_123/rotate",
		"/connectors/aws/credentials/cred_123/revoke",
	} {
		policy := httpRoutePolicyFor(http.MethodPost, path)
		if policy.Scope != scopeConnectorCredentialsWrite || policy.AdminOnly {
			t.Fatalf("POST %s policy = %#v, want connector credential write scope", path, policy)
		}
	}
	readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
	if err := authorizePrincipalScope(readOnly, scopeConnectorCredentialsWrite); err == nil {
		t.Fatal("read-only scoped principal authorized for connector credential write scope")
	}
	credentialReader := authPrincipal{Scopes: []string{scopeConnectorCredentialsRead}}
	if err := authorizePrincipalScope(credentialReader, scopeConnectorCredentialsRead); err != nil {
		t.Fatalf("connector credential reader rejected: %v", err)
	}
	writer := authPrincipal{Scopes: []string{scopeConnectorCredentialsWrite}}
	if err := authorizePrincipalScope(writer, scopeConnectorCredentialsWrite); err != nil {
		t.Fatalf("connector credential writer rejected: %v", err)
	}
}

func TestMetricsHTTPRouteRequiresAdminOnly(t *testing.T) {
	policy := httpRoutePolicyFor(http.MethodGet, "/metrics")
	if policy.Scope != "" || !policy.AdminOnly {
		t.Fatalf("GET /metrics policy = %#v, want admin-only", policy)
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	readOnly := authContext{principal: authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}}
	if err := authorizeHTTPRequestScope(readOnly, request); !errors.Is(err, errScopeForbidden) {
		t.Fatalf("read-only authorizeHTTPRequestScope(/metrics) error = %v, want scope forbidden", err)
	}

	operator := authContext{principal: authPrincipal{AuthMode: "api_key"}}
	if err := authorizeHTTPRequestScope(operator, request); err != nil {
		t.Fatalf("operator authorizeHTTPRequestScope(/metrics) error = %v", err)
	}
}

func TestA2AJSONRPCHTTPRouteRequiresAdminOnly(t *testing.T) {
	policy := httpRoutePolicyFor(http.MethodPost, agentplatform.A2AJSONRPCPath)
	if policy.Scope != "" || !policy.AdminOnly {
		t.Fatalf("POST %s policy = %#v, want admin-only", agentplatform.A2AJSONRPCPath, policy)
	}

	request := httptest.NewRequest(http.MethodPost, agentplatform.A2AJSONRPCPath, nil)
	readOnly := authContext{principal: authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}}
	if err := authorizeHTTPRequestScope(readOnly, request); !errors.Is(err, errScopeForbidden) {
		t.Fatalf("read-only authorizeHTTPRequestScope(%s) error = %v, want scope forbidden", agentplatform.A2AJSONRPCPath, err)
	}

	operator := authContext{principal: authPrincipal{AuthMode: "api_key"}}
	if err := authorizeHTTPRequestScope(operator, request); err != nil {
		t.Fatalf("operator authorizeHTTPRequestScope(%s) error = %v", agentplatform.A2AJSONRPCPath, err)
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
		cerebrov1connect.BootstrapServiceLinkFindingExternalRefProcedure,
	} {
		policy := connectProcedurePolicyFor(procedure)
		if policy.Scope != scopeFindingLifecycleWrite || policy.AdminOnly {
			t.Fatalf("%s policy = %#v, want findings write scope", procedure, policy)
		}
	}
}

func TestGraphActionConnectProceduresRequireDedicatedScope(t *testing.T) {
	procedure := cerebrov1connect.BootstrapServiceExecuteGraphActionProcedure
	policy := connectProcedurePolicyFor(procedure)
	if policy.Scope != scopeGraphActionsWrite || policy.AdminOnly {
		t.Fatalf("%s policy = %#v, want graph action write scope", procedure, policy)
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

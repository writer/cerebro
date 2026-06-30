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
	for _, path := range []string{"/platform/graph/actions", "/platform/graph/actions/reconcile"} {
		policy := httpRoutePolicyFor(http.MethodPost, path)
		if policy.Scope != scopeGraphActionsWrite || policy.AdminOnly {
			t.Fatalf("POST %s policy = %#v, want graph action write scope", path, policy)
		}
	}
}

func TestAskQueryHTTPRoutesRequireWriteScope(t *testing.T) {
	readPolicy := httpRoutePolicyFor(http.MethodGet, "/ask-queries")
	if readPolicy.Scope != scopeCosmoSecurityRead || readPolicy.AdminOnly {
		t.Fatalf("GET /ask-queries policy = %#v, want read scope", readPolicy)
	}

	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/ask-queries"},
		{method: http.MethodPatch, path: "/ask-queries/query-1"},
		{method: http.MethodDelete, path: "/ask-queries/query-1"},
	} {
		policy := httpRoutePolicyFor(tt.method, tt.path)
		if policy.Scope != scopeAskQueriesWrite || policy.AdminOnly {
			t.Fatalf("%s %s policy = %#v, want ask queries write scope", tt.method, tt.path, policy)
		}

		readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
		if err := authorizePrincipalHTTPPolicy(readOnly, policy); !errors.Is(err, errScopeForbidden) {
			t.Fatalf("read-only principal authorized for %s %s: %v", tt.method, tt.path, err)
		}

		writer := authPrincipal{Scopes: []string{scopeAskQueriesWrite}}
		if err := authorizePrincipalHTTPPolicy(writer, policy); err != nil {
			t.Fatalf("ask query writer rejected for %s %s: %v", tt.method, tt.path, err)
		}
	}
}

func TestUserPreferenceHTTPRoutesAllowViewerPreferenceWrites(t *testing.T) {
	readPolicy := httpRoutePolicyFor(http.MethodGet, "/user/preferences")
	if readPolicy.Scope != scopeCosmoSecurityRead || readPolicy.AdminOnly {
		t.Fatalf("GET /user/preferences policy = %#v, want read scope", readPolicy)
	}

	writePolicy := httpRoutePolicyFor(http.MethodPut, "/user/preferences")
	if writePolicy.Scope != scopeUserPreferencesWrite || writePolicy.AdminOnly {
		t.Fatalf("PUT /user/preferences policy = %#v, want user preferences write scope", writePolicy)
	}

	viewer := authPrincipal{Roles: []string{roleCerebroViewer}}
	if err := authorizePrincipalHTTPPolicy(viewer, writePolicy); err != nil {
		t.Fatalf("viewer rejected for preference write: %v", err)
	}
}

func TestCustomDashboardHTTPRoutesRequireWriteScope(t *testing.T) {
	readPolicy := httpRoutePolicyFor(http.MethodGet, "/grc/dashboards")
	if readPolicy.Scope != scopeCosmoSecurityRead || readPolicy.AdminOnly {
		t.Fatalf("GET /grc/dashboards policy = %#v, want read scope", readPolicy)
	}

	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/grc/dashboards"},
		{method: http.MethodPatch, path: "/grc/dashboards/dashboard-1"},
		{method: http.MethodDelete, path: "/grc/dashboards/dashboard-1"},
		{method: http.MethodPost, path: "/grc/dashboards/dashboard-1/clone"},
	} {
		policy := httpRoutePolicyFor(tt.method, tt.path)
		if policy.Scope != scopeDashboardsWrite || policy.AdminOnly {
			t.Fatalf("%s %s policy = %#v, want dashboard write scope", tt.method, tt.path, policy)
		}

		readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
		if err := authorizePrincipalHTTPPolicy(readOnly, policy); !errors.Is(err, errScopeForbidden) {
			t.Fatalf("read-only principal authorized for %s %s: %v", tt.method, tt.path, err)
		}

		writer := authPrincipal{Scopes: []string{scopeDashboardsWrite}}
		if err := authorizePrincipalHTTPPolicy(writer, policy); err != nil {
			t.Fatalf("dashboard writer rejected for %s %s: %v", tt.method, tt.path, err)
		}
	}
}

func TestRiskScoringConfigHTTPRoutesRequireWriteScope(t *testing.T) {
	readPolicy := httpRoutePolicyFor(http.MethodGet, "/grc/risk-scoring-config")
	if readPolicy.Scope != scopeCosmoSecurityRead || readPolicy.AdminOnly {
		t.Fatalf("GET /grc/risk-scoring-config policy = %#v, want read scope", readPolicy)
	}

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		policy := httpRoutePolicyFor(method, "/grc/risk-scoring-config")
		if policy.Scope != scopeRiskScoringWrite || policy.AdminOnly {
			t.Fatalf("%s /grc/risk-scoring-config policy = %#v, want risk scoring write scope", method, policy)
		}
		readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
		if err := authorizePrincipalHTTPPolicy(readOnly, policy); !errors.Is(err, errScopeForbidden) {
			t.Fatalf("read-only principal authorized for %s /grc/risk-scoring-config: %v", method, err)
		}
		writer := authPrincipal{Scopes: []string{scopeRiskScoringWrite}}
		if err := authorizePrincipalHTTPPolicy(writer, policy); err != nil {
			t.Fatalf("risk scoring writer rejected for %s /grc/risk-scoring-config: %v", method, err)
		}
	}
}

func TestQuestionnaireRunHTTPRoutesRequireWriteScope(t *testing.T) {
	readPolicy := httpRoutePolicyFor(http.MethodGet, "/grc/questionnaire-runs")
	if readPolicy.Scope != scopeCosmoSecurityRead || readPolicy.AdminOnly {
		t.Fatalf("GET /grc/questionnaire-runs policy = %#v, want read scope", readPolicy)
	}

	for _, tt := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/grc/questionnaire-runs"},
		{method: http.MethodPost, path: "/grc/questionnaire-runs/run-1/process"},
		{method: http.MethodPost, path: "/grc/questionnaire-runs/run-1/assignments"},
		{method: http.MethodPost, path: "/grc/questionnaire-runs/run-1/questions"},
		{method: http.MethodPost, path: "/grc/questionnaire-runs/run-1/decisions"},
		{method: http.MethodPost, path: "/grc/questionnaire-runs/run-1/comments"},
	} {
		policy := httpRoutePolicyFor(tt.method, tt.path)
		if policy.Scope != scopeGRCInventoryWrite || policy.AdminOnly {
			t.Fatalf("%s %s policy = %#v, want GRC inventory write scope", tt.method, tt.path, policy)
		}
		readOnly := authPrincipal{Scopes: []string{scopeCosmoSecurityRead}}
		if err := authorizePrincipalHTTPPolicy(readOnly, policy); !errors.Is(err, errScopeForbidden) {
			t.Fatalf("read-only principal authorized for %s %s: %v", tt.method, tt.path, err)
		}
		writer := authPrincipal{Scopes: []string{scopeGRCInventoryWrite}}
		if err := authorizePrincipalHTTPPolicy(writer, policy); err != nil {
			t.Fatalf("GRC inventory writer rejected for %s %s: %v", tt.method, tt.path, err)
		}
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

	admin := authContext{principal: authPrincipal{Roles: []string{roleCerebroAdmin}}}
	if err := authorizeHTTPRequestScope(admin, request); err != nil {
		t.Fatalf("rbac admin authorizeHTTPRequestScope(/metrics) error = %v", err)
	}
}

func TestRBACRolesAuthorizeRouteScopes(t *testing.T) {
	viewer := authPrincipal{Roles: []string{roleCerebroViewer}}
	if err := authorizePrincipalHTTPPolicy(viewer, httpRoutePolicyFor(http.MethodGet, "/sources")); err != nil {
		t.Fatalf("viewer rejected for read route: %v", err)
	}
	if err := authorizePrincipalHTTPPolicy(viewer, httpRoutePolicyFor(http.MethodPost, "/findings/finding-1/resolve")); err == nil {
		t.Fatal("viewer authorized for finding lifecycle write")
	}

	findingManager := authPrincipal{Roles: []string{roleCerebroFindingManager}}
	if err := authorizePrincipalHTTPPolicy(findingManager, httpRoutePolicyFor(http.MethodPost, "/findings/finding-1/resolve")); err != nil {
		t.Fatalf("finding manager rejected for finding lifecycle write: %v", err)
	}

	connectorManager := authPrincipal{Roles: []string{roleCerebroConnectorManager}}
	if err := authorizePrincipalHTTPPolicy(connectorManager, httpRoutePolicyFor(http.MethodPost, "/connectors/aws/credentials")); err != nil {
		t.Fatalf("connector manager rejected for credential write: %v", err)
	}
	if err := authorizePrincipalHTTPPolicy(connectorManager, httpRoutePolicyFor(http.MethodPut, "/source-runtimes/runtime-1")); err == nil {
		t.Fatal("connector manager authorized for source runtime write")
	}

	sourceManager := authPrincipal{Roles: []string{roleCerebroSourceManager}}
	if err := authorizePrincipalHTTPPolicy(sourceManager, httpRoutePolicyFor(http.MethodPut, "/source-runtimes/runtime-1")); err != nil {
		t.Fatalf("source manager rejected for source runtime write: %v", err)
	}

	admin := authPrincipal{Roles: []string{roleCerebroAdmin}}
	if err := authorizePrincipalHTTPPolicy(admin, httpRoutePolicyFor(http.MethodPost, "/platform/jobs")); err != nil {
		t.Fatalf("admin rejected for job write: %v", err)
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
	for _, procedure := range []string{
		cerebrov1connect.BootstrapServiceExecuteGraphActionProcedure,
		cerebrov1connect.BootstrapServiceReconcileGraphActionProcedure,
	} {
		policy := connectProcedurePolicyFor(procedure)
		if policy.Scope != scopeGraphActionsWrite || policy.AdminOnly {
			t.Fatalf("%s policy = %#v, want graph action write scope", procedure, policy)
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

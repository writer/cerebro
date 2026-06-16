package bootstrap

import (
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
)

const (
	apiCapabilityTokenResource = "cerebro-api"
	mcpCapabilityTokenResource = "cerebro-mcp"
)

type httpAuthRoutePolicy struct {
	Method    string
	Exact     string
	Prefix    string
	Suffix    string
	Scope     string
	Static    bool
	AdminOnly bool
}

var httpAuthRoutePolicies = []httpAuthRoutePolicy{
	{Exact: "/api/v1/mcp", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/metrics", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPost, Prefix: "/reports/", Suffix: "/runs", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/knowledge/decisions", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/knowledge/actions", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/knowledge/actions/recommendation", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/knowledge/outcomes", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/workflow/replay", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Exact: "/sources", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/sources/", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Exact: "/connectors", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/connectors/credential-key", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/connector-definitions", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPost, Exact: "/connector-definitions", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/connector-definitions/validate", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Prefix: "/connector-definitions/", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPut, Prefix: "/connector-definitions/", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/connector-definitions/", Suffix: "/promote", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Prefix: "/connectors/", Suffix: "/activity", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Prefix: "/connectors/", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPost, Prefix: "/connectors/", Suffix: "/preflight", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/connectors/", Suffix: "/connections", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Exact: "/reports", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Exact: "/finding-rules", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Exact: "/endpoint-vulnerability-findings", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Exact: "/source-runtimes", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/source-runtimes/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/findings/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodPost, Prefix: "/findings/", Suffix: "/resolve", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodPost, Prefix: "/findings/", Suffix: "/suppress", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodPut, Prefix: "/findings/", Suffix: "/assign", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodPut, Prefix: "/findings/", Suffix: "/due", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodPost, Prefix: "/findings/", Suffix: "/notes", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodPost, Prefix: "/findings/", Suffix: "/tickets", Scope: scopeFindingLifecycleWrite},
	{Method: http.MethodGet, Prefix: "/finding-candidates/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodPost, Prefix: "/finding-candidates/", Suffix: "/promote", Scope: scopeFindingCandidatePromote},
	{Method: http.MethodPost, Prefix: "/finding-candidates/", Suffix: "/reject", Scope: scopeFindingCandidatePromote},
	{Method: http.MethodGet, Prefix: "/finding-evaluation-runs/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/finding-evidence/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/grc/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodPost, Exact: "/grc/ask", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPost, Exact: "/grc/inventory/resource-scope", Scope: scopeGRCInventoryWrite, Static: true},
	{Method: http.MethodPost, Exact: "/grc/inventory/asset-reports", Scope: scopeGRCInventoryWrite, Static: true},
	{Method: http.MethodPatch, Prefix: "/grc/inventory/asset-reports/", Suffix: "/triage", Scope: scopeGRCInventoryWrite},
	{Method: http.MethodGet, Exact: "/platform/runtime-freshness", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/neighborhood", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/impact/package", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/impact/asset", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Prefix: "/platform/graph/impact/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Exact: "/platform/graph/attack-paths", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/person-access-paths", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/aws-public-endpoint-insights", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/crown-jewel-rankings", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/ingest-health", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/graph/ingest-runs", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Prefix: "/platform/graph/ingest-runs/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/platform/endpoints/", Suffix: "/vulnerability-findings", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodGet, Prefix: "/report-runs/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodPost, Exact: "/platform/jobs", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Exact: "/platform/jobs", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Prefix: "/platform/jobs/", Scope: scopeCosmoSecurityRead},
	{Method: http.MethodPost, Prefix: "/platform/jobs/", Suffix: "/cancel", Static: true, AdminOnly: true},
	{Method: http.MethodGet, Exact: "/platform/runtime-response/capabilities", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodGet, Exact: "/platform/runtime-response/blocklist", Scope: scopeCosmoSecurityRead, Static: true},
	{Method: http.MethodPost, Exact: "/platform/runtime-response/actions", Scope: scopeRuntimeResponseWrite, Static: true},
	{Method: http.MethodPost, Prefix: "/platform/runtime-response/blocklist/", Suffix: "/revoke", Scope: scopeRuntimeResponseWrite},
	{Method: http.MethodPut, Prefix: "/source-runtimes/", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/sync", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/graph-ingest-runs", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/claims", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/finding-candidates/evaluate", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/finding-rules/evaluate", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Prefix: "/source-runtimes/", Suffix: "/findings/evaluate", Static: true, AdminOnly: true},
	{Method: http.MethodPost, Exact: "/platform/devices/enroll", Scope: deviceauth.ScopeDevicesEnroll, Static: true},
	{Method: http.MethodPost, Exact: "/platform/devices/token", Scope: deviceauth.ScopeDevicesToken, Static: true},
	{Method: http.MethodPost, Exact: "/platform/devices/bootstrap-tokens", Scope: deviceauth.ScopeDevicesBootstrapWrite, Static: true},
	{Method: http.MethodPost, Prefix: "/platform/devices/", Suffix: "/revoke", Scope: deviceauth.ScopeDevicesRevoke},
	{Method: http.MethodGet, Exact: "/platform/devices", Scope: deviceauth.ScopeDevicesRead, Static: true},
	{Method: http.MethodGet, Prefix: "/platform/devices/", Scope: deviceauth.ScopeDevicesRead},
	{Method: http.MethodPost, Exact: "/platform/telemetry/ingest", Scope: deviceauth.ScopeTelemetryIngest, Static: true},
	{Method: http.MethodGet, Exact: "/.well-known/device-jwks.json", Static: true},
}

func httpRoutePolicyForRequest(r *http.Request) httpAuthRoutePolicy {
	if r == nil || r.URL == nil {
		return httpAuthRoutePolicy{}
	}
	return httpRoutePolicyFor(r.Method, r.URL.Path)
}

func httpRoutePolicyFor(method string, path string) httpAuthRoutePolicy {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	for _, policy := range httpAuthRoutePolicies {
		if policy.Method != "" && policy.Method != method {
			continue
		}
		if !routePolicyPathMatches(policy, path) {
			continue
		}
		return policy
	}
	return httpAuthRoutePolicy{}
}

func routePolicyPathMatches(policy httpAuthRoutePolicy, path string) bool {
	if policy.Exact != "" && path != policy.Exact {
		return false
	}
	if policy.Prefix != "" && !strings.HasPrefix(path, policy.Prefix) {
		return false
	}
	if policy.Suffix != "" && !strings.HasSuffix(path, policy.Suffix) {
		return false
	}
	return policy.Exact != "" || policy.Prefix != "" || policy.Suffix != ""
}

func httpRouteStaticAccessPathKnown(path string) bool {
	for _, policy := range httpAuthRoutePolicies {
		if policy.Static && routePolicyPathMatches(policy, strings.TrimSpace(path)) {
			return true
		}
	}
	return false
}

func tokenResourceAllowedForRequest(cfg config.AuthConfig, r *http.Request, resource string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return true
	}
	for _, allowed := range tokenResourcesForRequest(cfg, r) {
		if resource == allowed {
			return true
		}
	}
	return false
}

func tokenResourcesForRequest(cfg config.AuthConfig, r *http.Request) []string {
	if r != nil && r.URL != nil && r.URL.Path == mcpEndpointPath {
		return mcpCapabilityTokenResources(cfg, r)
	}
	return apiCapabilityTokenResources(cfg, r)
}

func apiCapabilityTokenResources(cfg config.AuthConfig, r *http.Request) []string {
	resources := []string{apiCapabilityTokenResource}
	if origin := strings.TrimRight(strings.TrimSpace(cfg.RequestOrigin.PublicOrigin), "/"); origin != "" {
		resources = append(resources, origin)
	} else if r != nil {
		resources = append(resources, strings.TrimRight(externalOrigin(r, cfg.RequestOrigin), "/"))
	}
	return normalizeAuthList(resources)
}

func mcpCapabilityTokenResources(cfg config.AuthConfig, r *http.Request) []string {
	resources := []string{mcpCapabilityTokenResource}
	if resource := strings.TrimSpace(cfg.MCPOAuth.Resource); resource != "" {
		resources = append(resources, resource)
	} else if r != nil {
		resources = append(resources, strings.TrimRight(externalOrigin(r, cfg.RequestOrigin), "/")+mcpEndpointPath)
	}
	return normalizeAuthList(resources)
}

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/getkin/kin-openapi/openapi3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	cerebrov1connect "github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
)

const publicContractInventoryPath = "docs/contracts/platform-public-route-inventory.json"

type platformContractInventory struct {
	SchemaVersion int                            `json:"schema_version"`
	Description   string                         `json:"description"`
	GeneratedFrom []string                       `json:"generated_from"`
	Summary       platformContractInventoryStats `json:"summary"`
	Entries       []platformContractEntry        `json:"entries"`
}

type platformContractInventoryStats struct {
	HTTPRoutes         int            `json:"http_routes"`
	ConnectMounts      int            `json:"connect_mounts"`
	ConnectRPCs        int            `json:"connect_rpcs"`
	BySurface          map[string]int `json:"by_surface"`
	ByAuthorityOwner   map[string]int `json:"by_authority_owner"`
	ByAuthClass        map[string]int `json:"by_auth_class"`
	ByContractSource   map[string]int `json:"by_contract_source"`
	DeprecatedSurfaces int            `json:"deprecated_surfaces"`
}

type platformContractEntry struct {
	Identity        string `json:"identity"`
	Kind            string `json:"kind"`
	Method          string `json:"method,omitempty"`
	Path            string `json:"path"`
	RPC             string `json:"rpc,omitempty"`
	Surface         string `json:"surface"`
	AuthorityOwner  string `json:"authority_owner"`
	Owner           string `json:"owner"`
	AuthClass       string `json:"auth_class"`
	TenantScopeRule string `json:"tenant_scope_rule"`
	ContractSource  string `json:"contract_source"`
	MigrationNote   string `json:"migration_note,omitempty"`
}

func TestPublicContractInventoryGolden(t *testing.T) {
	root := bootstrapRepoRoot(t)
	inventory := buildPlatformContractInventory(t, root)
	got := mustMarshalInventory(t, inventory)
	goldenPath := filepath.Join(root, publicContractInventoryPath)
	if os.Getenv("CEREBRO_UPDATE_PUBLIC_CONTRACT_INVENTORY") == "1" {
		if err := os.WriteFile(goldenPath, got, 0o600); err != nil {
			t.Fatalf("update public contract inventory: %v", err)
		}
	}
	// #nosec G304 -- fixed repo-relative golden path derived from runtime.Caller.
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", publicContractInventoryPath, err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
		t.Fatalf("%s drifted; run CEREBRO_UPDATE_PUBLIC_CONTRACT_INVENTORY=1 go test ./internal/bootstrap -run TestPublicContractInventoryGolden -count=1 and review the diff", publicContractInventoryPath)
	}
}

func TestPublicContractInventoryClassifiesEverySurface(t *testing.T) {
	root := bootstrapRepoRoot(t)
	inventory := buildPlatformContractInventory(t, root)
	allowedSurfaces := allowedInventoryValues("go-compatibility", "bridged-to-rust-authority", "rust-authority", "public-exempt", "protected", "internal-only", "deprecated")
	allowedAuth := allowedInventoryValues("public-exempt", "api-key-or-bearer", "api-key-bearer-or-oauth", "connect-api-key-or-bearer", "internal-only")
	allowedTenant := allowedInventoryValues("none", "request-tenant", "tenant-id-required", "tenant-metadata-required", "internal-context")
	allowedSources := allowedInventoryValues("OpenAPI", "proto", "MCP schema", "docs", "internal-only")
	for _, entry := range inventory.Entries {
		if entry.Identity == "" || entry.Path == "" || entry.Owner == "" || entry.AuthorityOwner == "" {
			t.Fatalf("inventory entry has incomplete identity/ownership: %#v", entry)
		}
		if !allowedSurfaces[entry.Surface] {
			t.Fatalf("%s has unsupported surface %q", entry.Identity, entry.Surface)
		}
		if !allowedAuth[entry.AuthClass] {
			t.Fatalf("%s has unsupported auth class %q", entry.Identity, entry.AuthClass)
		}
		if !allowedTenant[entry.TenantScopeRule] {
			t.Fatalf("%s has unsupported tenant scope %q", entry.Identity, entry.TenantScopeRule)
		}
		if !allowedSources[entry.ContractSource] {
			t.Fatalf("%s has unsupported contract source %q", entry.Identity, entry.ContractSource)
		}
		if entry.Surface == "deprecated" && strings.TrimSpace(entry.MigrationNote) == "" {
			t.Fatalf("%s is deprecated without a migration note", entry.Identity)
		}
		if entry.Kind == "http" && (entry.Path == "/graph" || strings.HasPrefix(entry.Path, "/graph/")) {
			t.Fatalf("%s reintroduces legacy /graph/* alias", entry.Identity)
		}
	}
}

func TestPublicHTTPRoutesRemainOpenAPICompatible(t *testing.T) {
	root := bootstrapRepoRoot(t)
	inventory := buildPlatformContractInventory(t, root)
	for _, entry := range inventory.Entries {
		if entry.Kind != "http" || entry.ContractSource != "OpenAPI" {
			continue
		}
		// OpenAPI membership was verified while building the inventory.
		if entry.Method == "" || entry.Path == "" {
			t.Fatalf("OpenAPI-backed route missing method/path: %#v", entry)
		}
	}
}

func TestBootstrapConnectRPCInventoryMatchesGeneratedService(t *testing.T) {
	root := bootstrapRepoRoot(t)
	inventory := buildPlatformContractInventory(t, root)
	procedures := generatedBootstrapConnectProcedures(t, root)
	inventoryRPCs := map[string]struct{}{}
	hasMount := false
	for _, entry := range inventory.Entries {
		switch entry.Kind {
		case "connect-mount":
			if entry.Path == "/cerebro.v1.BootstrapService/" {
				hasMount = true
			}
		case "connect-rpc":
			inventoryRPCs[entry.Path] = struct{}{}
		}
	}
	if !hasMount {
		t.Fatal("inventory missing generated BootstrapService Connect mount")
	}
	for _, procedure := range procedures {
		if _, ok := inventoryRPCs[procedure]; !ok {
			t.Fatalf("inventory missing Connect RPC %s", procedure)
		}
		if !connectProcedurePolicyKnown(procedure) {
			t.Fatalf("Connect RPC %s has no auth policy", procedure)
		}
	}
}

func TestPublicAuthCompatibilityAPIKeyBearerAndTenant(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "legacy-api-key",
				Principal: "legacy-client",
				TenantID:  "tenant-a",
			}},
			APICredentials: []config.APICredential{{
				ID:        "bearer-credential",
				Kind:      "api_key",
				Key:       "bearer-compatible-token",
				Principal: "bearer-client",
				TenantID:  "tenant-a",
				Scopes:    []string{scopeCosmoSecurityRead},
			}},
		},
	}
	app, err := NewWithError(cfg, Dependencies{}, registry)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	for _, tt := range []struct {
		name       string
		headerName string
		headerVal  string
		tenantID   string
		wantStatus int
	}{
		{name: "valid legacy x api key", headerName: "X-Cerebro-API-Key", headerVal: "legacy-api-key", tenantID: "tenant-a", wantStatus: http.StatusOK},
		{name: "valid legacy bearer api key", headerName: "Authorization", headerVal: "Bearer legacy-api-key", tenantID: "tenant-a", wantStatus: http.StatusOK},
		{name: "valid scoped bearer credential", headerName: "Authorization", headerVal: "Bearer bearer-compatible-token", tenantID: "tenant-a", wantStatus: http.StatusOK},
		{name: "invalid key rejected", headerName: "X-Cerebro-API-Key", headerVal: "wrong-key", tenantID: "tenant-a", wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer rejected", headerName: "Authorization", headerVal: "Bearer wrong-token", tenantID: "tenant-a", wantStatus: http.StatusUnauthorized},
		{name: "tenant mismatch rejected before domain success", headerName: "Authorization", headerVal: "Bearer bearer-compatible-token", tenantID: "tenant-b", wantStatus: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+"/sources?tenant_id="+tt.tenantID, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set(tt.headerName, tt.headerVal)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("GET /sources: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("GET /sources status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestConnectWireCompatibilityGeneratedClientRawHTTPAuthAndTenant(t *testing.T) {
	registry, err := newFixtureRegistry()
	if err != nil {
		t.Fatalf("newFixtureRegistry() error = %v", err)
	}
	cfg := config.Config{
		HTTPAddr:        "127.0.0.1:0",
		ShutdownTimeout: time.Second,
		Auth: config.AuthConfig{
			Enabled: true,
			APIKeys: []config.APIKey{{
				Key:       "connect-api-key",
				Principal: "connect-client",
				TenantID:  "tenant-a",
			}},
		},
	}
	app, err := NewWithError(cfg, Dependencies{}, registry)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	client := cerebrov1connect.NewBootstrapServiceClient(server.Client(), server.URL)
	successReq := connect.NewRequest(&cerebrov1.GetVersionRequest{})
	successReq.Header().Set("Authorization", "Bearer connect-api-key")
	successResp, err := client.GetVersion(context.Background(), successReq)
	if err != nil {
		t.Fatalf("generated client GetVersion() error = %v", err)
	}
	if successResp.Msg.GetServiceName() == "" || successResp.Msg.GetApiVersion() == "" {
		t.Fatalf("GetVersion response missing stable fields: %#v", successResp.Msg)
	}

	unauthReq := connect.NewRequest(&cerebrov1.GetVersionRequest{})
	if _, err := client.GetVersion(context.Background(), unauthReq); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated GetVersion code = %s err = %v, want unauthenticated", connect.CodeOf(err), err)
	}

	mismatchReq := connect.NewRequest(&cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id:       "runtime-tenant-b",
		SourceId: "bootstrap_token",
		TenantId: "tenant-b",
	}})
	mismatchReq.Header().Set("Authorization", "Bearer connect-api-key")
	if _, err := client.PutSourceRuntime(context.Background(), mismatchReq); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("tenant mismatch PutSourceRuntime code = %s err = %v, want permission_denied", connect.CodeOf(err), err)
	}

	rawReq, err := http.NewRequest(http.MethodPost, server.URL+cerebrov1connect.BootstrapServiceGetVersionProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest raw Connect: %v", err)
	}
	rawReq.Header.Set("Authorization", "Bearer connect-api-key")
	rawReq.Header.Set("Content-Type", "application/json")
	rawResp, err := server.Client().Do(rawReq)
	if err != nil {
		t.Fatalf("raw Connect GetVersion: %v", err)
	}
	t.Cleanup(func() {
		if err := rawResp.Body.Close(); err != nil {
			t.Errorf("close raw Connect response body: %v", err)
		}
	})
	if rawResp.StatusCode != http.StatusOK {
		t.Fatalf("raw Connect status = %d, want 200", rawResp.StatusCode)
	}
	if contentType := rawResp.Header.Get("Content-Type"); !strings.Contains(contentType, "json") {
		t.Fatalf("raw Connect Content-Type = %q, want JSON-compatible response", contentType)
	}
}

func buildPlatformContractInventory(t *testing.T, root string) platformContractInventory {
	t.Helper()
	openAPI := openAPIHTTPMethods(t, root)
	entries := registeredHTTPContractEntries(t, root, openAPI)
	entries = append(entries, rustAuthorityHTTPContractEntries(t, root, openAPI)...)
	entries = append(entries, bootstrapConnectContractEntries(t, root)...)
	assertUniqueContractEntries(t, entries)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind == entries[j].Kind {
			return entries[i].Identity < entries[j].Identity
		}
		return entries[i].Kind < entries[j].Kind
	})
	inventory := platformContractInventory{
		SchemaVersion: 1,
		Description:   "Deterministic public platform contract inventory for Go compatibility and Rust authority routes.",
		GeneratedFrom: []string{
			"internal/bootstrap/routes.go",
			"crates/cerebro-platform/src/main.rs",
			"api/openapi.yaml",
			"proto/cerebro/v1/bootstrap.proto",
			"gen/cerebro/v1/cerebrov1connect/bootstrap.connect.go",
		},
		Entries: entries,
	}
	inventory.Summary = summarizePlatformContractInventory(entries)
	return inventory
}

func rustAuthorityHTTPContractEntries(t *testing.T, root string, openAPI map[string]map[string]struct{}) []platformContractEntry {
	t.Helper()
	// #nosec G304 -- fixed repo-relative guardrail path derived from runtime.Caller.
	body, err := os.ReadFile(filepath.Join(root, "crates", "cerebro-platform", "src", "main.rs"))
	if err != nil {
		t.Fatalf("read Rust platform router: %v", err)
	}
	routes := []struct {
		method string
		path   string
		marker string
	}{
		{method: http.MethodGet, path: "/platform/graph/neighborhood", marker: "get(product_neighborhood_route)"},
		{method: http.MethodGet, path: "/platform/graph/provenance", marker: "get(graph_provenance_route)"},
	}
	entries := make([]platformContractEntry, 0, len(routes))
	for _, route := range routes {
		if !strings.Contains(string(body), `"`+route.path+`"`) || !strings.Contains(string(body), route.marker) {
			t.Fatalf("Rust platform router is missing %s %s", route.method, route.path)
		}
		methods := openAPI[route.path]
		if _, ok := methods[strings.ToLower(route.method)]; !ok {
			t.Fatalf("Rust authority route %s %s is missing from OpenAPI", route.method, route.path)
		}
		entries = append(entries, platformContractEntry{
			Identity:        route.method + " " + route.path,
			Kind:            "http",
			Method:          route.method,
			Path:            route.path,
			Surface:         "rust-authority",
			AuthorityOwner:  "rust-authority",
			Owner:           contractOwnerForPath(route.path),
			AuthClass:       "api-key-or-bearer",
			TenantScopeRule: "tenant-id-required",
			ContractSource:  "OpenAPI",
		})
	}
	return entries
}

func assertUniqueContractEntries(t *testing.T, entries []platformContractEntry) {
	t.Helper()
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key := entry.Kind + " " + entry.Identity
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate public contract entry %s", key)
		}
		seen[key] = struct{}{}
	}
}

func registeredHTTPContractEntries(t *testing.T, root string, openAPI map[string]map[string]struct{}) []platformContractEntry {
	t.Helper()
	// #nosec G304 -- fixed repo-relative guardrail path derived from runtime.Caller.
	body, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "routes.go"))
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	routePattern := regexp.MustCompile(`registerHTTPRoute\(mux,\s*"([A-Z]+) ([^"]+)",\s*(routeSurface[A-Za-z]+)`)
	matches := routePattern.FindAllStringSubmatch(string(body), -1)
	entries := make([]platformContractEntry, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		method := strings.ToUpper(strings.TrimSpace(match[1]))
		routePath := strings.TrimSpace(match[2])
		surface := strings.TrimSpace(match[3])
		identity := method + " " + routePath
		if _, ok := seen[identity]; ok {
			t.Fatalf("duplicate HTTP route registration %s", identity)
		}
		seen[identity] = struct{}{}
		if routePath == "/graph" || strings.HasPrefix(routePath, "/graph/") {
			t.Fatalf("legacy /graph/* alias registered as %s", identity)
		}
		contractSource := "internal-only"
		if methods := openAPI[routePath]; methods != nil {
			if _, ok := methods[strings.ToLower(method)]; !ok {
				t.Fatalf("OpenAPI path %s exists but method %s is missing", routePath, method)
			}
			contractSource = "OpenAPI"
		} else if surface == "routeSurfacePublicHTTP" {
			t.Fatalf("public route %s is missing from OpenAPI", identity)
		}
		entries = append(entries, httpContractEntry(method, routePath, surface, contractSource))
	}
	return entries
}

func httpContractEntry(method string, routePath string, routeSurface string, contractSource string) platformContractEntry {
	surface := "protected"
	authClass := "api-key-or-bearer"
	tenantScope := "tenant-id-required"
	switch routeSurface {
	case "routeSurfacePublicHTTP":
		surface = "public-exempt"
		authClass = "public-exempt"
		tenantScope = "none"
	case "routeSurfaceInternalHTTP":
		surface = "internal-only"
		authClass = "internal-only"
		tenantScope = "internal-context"
		contractSource = "internal-only"
	}
	if routePath == mcpEndpointPath {
		authClass = "api-key-bearer-or-oauth"
		contractSource = "MCP schema"
	}
	if strings.HasPrefix(routePath, "/oauth/") || strings.HasPrefix(routePath, "/.well-known/oauth-") {
		tenantScope = "none"
	}
	if strings.HasPrefix(routePath, "/platform/graph/") || routePath == "/platform/runtime-freshness" {
		surface = "bridged-to-rust-authority"
	}
	return platformContractEntry{
		Identity:        method + " " + routePath,
		Kind:            "http",
		Method:          method,
		Path:            routePath,
		Surface:         surface,
		AuthorityOwner:  authorityOwnerForSurface(surface),
		Owner:           contractOwnerForPath(routePath),
		AuthClass:       authClass,
		TenantScopeRule: tenantScope,
		ContractSource:  contractSource,
	}
}

func bootstrapConnectContractEntries(t *testing.T, root string) []platformContractEntry {
	t.Helper()
	procedures := generatedBootstrapConnectProcedures(t, root)
	entries := []platformContractEntry{{
		Identity:        "CONNECT /cerebro.v1.BootstrapService/*",
		Kind:            "connect-mount",
		Path:            "/cerebro.v1.BootstrapService/",
		Surface:         "protected",
		AuthorityOwner:  "go-compatibility",
		Owner:           "connect",
		AuthClass:       "connect-api-key-or-bearer",
		TenantScopeRule: "tenant-metadata-required",
		ContractSource:  "proto",
	}}
	for _, procedure := range procedures {
		rpc := procedure[strings.LastIndex(procedure, "/")+1:]
		surface := "protected"
		if strings.Contains(rpc, "Graph") || strings.Contains(rpc, "Neighborhood") {
			surface = "bridged-to-rust-authority"
		}
		entries = append(entries, platformContractEntry{
			Identity:        "POST " + procedure,
			Kind:            "connect-rpc",
			Method:          "POST",
			Path:            procedure,
			RPC:             rpc,
			Surface:         surface,
			AuthorityOwner:  authorityOwnerForSurface(surface),
			Owner:           connectOwnerForRPC(rpc),
			AuthClass:       "connect-api-key-or-bearer",
			TenantScopeRule: "tenant-metadata-required",
			ContractSource:  "proto",
		})
	}
	return entries
}

func generatedBootstrapConnectProcedures(t *testing.T, root string) []string {
	t.Helper()
	// #nosec G304 -- fixed repo-relative generated file path derived from runtime.Caller.
	body, err := os.ReadFile(filepath.Join(root, "gen", "cerebro", "v1", "cerebrov1connect", "bootstrap.connect.go"))
	if err != nil {
		t.Fatalf("read generated bootstrap.connect.go: %v", err)
	}
	pattern := regexp.MustCompile(`BootstrapService[A-Za-z0-9]+Procedure\s*=\s*"([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(string(body), -1)
	procedures := make([]string, 0, len(matches))
	for _, match := range matches {
		procedures = append(procedures, match[1])
	}
	sort.Strings(procedures)
	if len(procedures) == 0 {
		t.Fatal("no generated BootstrapService procedures found")
	}
	return procedures
}

func openAPIHTTPMethods(t *testing.T, root string) map[string]map[string]struct{} {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("load OpenAPI: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI: %v", err)
	}
	out := map[string]map[string]struct{}{}
	for path, item := range doc.Paths.Map() {
		if item == nil {
			continue
		}
		methods := map[string]struct{}{}
		for method := range item.Operations() {
			methods[strings.ToLower(method)] = struct{}{}
		}
		out[path] = methods
	}
	return out
}

func summarizePlatformContractInventory(entries []platformContractEntry) platformContractInventoryStats {
	stats := platformContractInventoryStats{
		BySurface:        map[string]int{},
		ByAuthorityOwner: map[string]int{},
		ByAuthClass:      map[string]int{},
		ByContractSource: map[string]int{},
	}
	for _, entry := range entries {
		switch entry.Kind {
		case "http":
			stats.HTTPRoutes++
		case "connect-mount":
			stats.ConnectMounts++
		case "connect-rpc":
			stats.ConnectRPCs++
		}
		stats.BySurface[entry.Surface]++
		stats.ByAuthorityOwner[entry.AuthorityOwner]++
		stats.ByAuthClass[entry.AuthClass]++
		stats.ByContractSource[entry.ContractSource]++
		if entry.Surface == "deprecated" {
			stats.DeprecatedSurfaces++
		}
	}
	return stats
}

func authorityOwnerForSurface(surface string) string {
	switch surface {
	case "bridged-to-rust-authority", "rust-authority":
		return surface
	default:
		return "go-compatibility"
	}
}

func contractOwnerForPath(routePath string) string {
	switch {
	case routePath == mcpEndpointPath:
		return "mcp"
	case strings.HasPrefix(routePath, "/.well-known/"), strings.HasPrefix(routePath, "/oauth/"):
		return "oauth"
	case strings.HasPrefix(routePath, "/api/v1/agent"), strings.HasPrefix(routePath, "/api/v1/a2a"):
		return "agent-platform"
	case strings.HasPrefix(routePath, "/api/v1/platform/decision-packets"):
		return "decision-packets"
	case strings.HasPrefix(routePath, "/credential-stores"), strings.HasPrefix(routePath, "/connector"):
		return "connector"
	case strings.HasPrefix(routePath, "/source-runtimes"):
		return "source-runtime"
	case strings.HasPrefix(routePath, "/sources"):
		return "source"
	case strings.HasPrefix(routePath, "/platform/graph"), strings.HasPrefix(routePath, "/platform/runtime-freshness"):
		return "graph"
	case strings.HasPrefix(routePath, "/platform/runtime-response"):
		return "runtime-response"
	case strings.HasPrefix(routePath, "/platform/knowledge"), strings.HasPrefix(routePath, "/platform/workflow"):
		return "workflow"
	case strings.HasPrefix(routePath, "/platform/jobs"):
		return "jobs"
	case strings.HasPrefix(routePath, "/platform/devices"), strings.HasPrefix(routePath, "/platform/telemetry"):
		return "device"
	case strings.HasPrefix(routePath, "/platform/audit-events"):
		return "audit"
	case strings.HasPrefix(routePath, "/reports"), strings.HasPrefix(routePath, "/report-"):
		return "report"
	case strings.HasPrefix(routePath, "/grc"):
		return "grc"
	case strings.HasPrefix(routePath, "/finding"):
		return "finding"
	case strings.HasPrefix(routePath, "/endpoint-vulnerability-findings"), strings.Contains(routePath, "/vulnerability-findings"):
		return "finding"
	case strings.HasPrefix(routePath, "/policy-"):
		return "policy"
	case strings.HasPrefix(routePath, "/ask-queries"):
		return "ask"
	case strings.HasPrefix(routePath, "/identity"):
		return "identity"
	case strings.HasPrefix(routePath, "/user/preferences"):
		return "user-preferences"
	case routePath == "/health" || routePath == "/healthz" || routePath == "/livez" || routePath == "/metrics" || routePath == "/openapi.yaml":
		return "platform"
	default:
		return "platform"
	}
}

func connectOwnerForRPC(rpc string) string {
	switch {
	case strings.Contains(rpc, "SourceRuntime"):
		return "source-runtime"
	case strings.Contains(rpc, "Source"):
		return "source"
	case strings.Contains(rpc, "Finding"):
		return "finding"
	case strings.Contains(rpc, "Graph") || strings.Contains(rpc, "Neighborhood"):
		return "graph"
	case strings.Contains(rpc, "Report"):
		return "report"
	case strings.Contains(rpc, "Decision"):
		return "decision-packets"
	case strings.Contains(rpc, "Action") || strings.Contains(rpc, "Outcome") || strings.Contains(rpc, "Workflow"):
		return "workflow"
	default:
		return "platform"
	}
}

func mustMarshalInventory(t *testing.T, inventory platformContractInventory) []byte {
	t.Helper()
	payload, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	return append(payload, '\n')
}

func allowedInventoryValues(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func TestPublicContractInventoryReferencesGeneratedConnectPackage(t *testing.T) {
	if cerebrov1connect.BootstrapServiceName != "cerebro.v1.BootstrapService" {
		t.Fatalf("unexpected BootstrapServiceName %q", cerebrov1connect.BootstrapServiceName)
	}
	if !strings.HasPrefix(cerebrov1connect.BootstrapServiceGetVersionProcedure, "/cerebro.v1.BootstrapService/") {
		t.Fatalf("unexpected BootstrapService procedure path %q", cerebrov1connect.BootstrapServiceGetVersionProcedure)
	}
}

func TestPublicContractInventoryPathIsStable(t *testing.T) {
	if strings.Contains(publicContractInventoryPath, "..") || filepath.IsAbs(publicContractInventoryPath) {
		t.Fatalf("inventory path must stay repo-relative: %s", publicContractInventoryPath)
	}
	if got := fmt.Sprint(publicContractInventoryPath); got != "docs/contracts/platform-public-route-inventory.json" {
		t.Fatalf("inventory path = %s", got)
	}
}

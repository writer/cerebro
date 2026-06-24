package archtests

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/writer/cerebro/tools/droidreview/bodyread"
)

func TestOpenAPIContractDescribesCurrentBootstrapSurface(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	for _, stale := range []string{"Snowflake", "Kuzu", "API_AUTH_ENABLED", "RATE_LIMIT"} {
		if bytes.Contains(body, []byte(stale)) {
			t.Fatalf("api/openapi.yaml contains stale marker %q", stale)
		}
	}
	for _, current := range []string{
		"/openapi.yaml:",
		"/platform/knowledge/outcomes:",
		"/platform/graph/neighborhood:",
		"/platform/endpoints/{deviceKey}/vulnerability-findings:",
		"x-cerebro-required-any-query:",
		"bearerAuth:",
	} {
		if !bytes.Contains(body, []byte(current)) {
			t.Fatalf("api/openapi.yaml missing current marker %q", current)
		}
	}
	runtimeFindings, endpointFindings, ok := strings.Cut(string(body), "  /endpoint-vulnerability-findings:")
	if !ok {
		t.Fatal("api/openapi.yaml missing /endpoint-vulnerability-findings section")
	}
	if strings.Contains(runtimeFindings, "#/components/schemas/EndpointVulnerabilityFindingsResponse") {
		t.Fatal("/source-runtimes/{runtimeID}/findings must keep the ordinary findings response contract")
	}
	if !strings.Contains(endpointFindings, "#/components/schemas/EndpointVulnerabilityFindingsResponse") {
		t.Fatal("/endpoint-vulnerability-findings must use the endpoint vulnerability response contract")
	}
	bootstrapTokenSchema, _, ok := strings.Cut(string(body), "    IssueBootstrapTokenResponse:")
	if !ok {
		t.Fatal("api/openapi.yaml missing IssueBootstrapTokenResponse schema")
	}
	if !strings.Contains(bootstrapTokenSchema, "        ttl_seconds:\n          type: integer\n          minimum: 0") {
		t.Fatal("IssueBootstrapTokenRequest.ttl_seconds must allow 0 to select the default TTL")
	}
	endpointTenantParam, _, ok := strings.Cut(endpointFindings, "        - name: device_id")
	if !ok {
		t.Fatal("/endpoint-vulnerability-findings must document the device_id query parameter")
	}
	if !strings.Contains(endpointTenantParam, "        - name: tenant_id\n          in: query\n          required: true") {
		t.Fatal("/endpoint-vulnerability-findings must require tenant_id in the OpenAPI contract")
	}
	_, platformEndpoint, ok := strings.Cut(string(body), "  /platform/endpoints/{deviceKey}/vulnerability-findings:")
	if !ok {
		t.Fatal("api/openapi.yaml missing /platform/endpoints/{deviceKey}/vulnerability-findings section")
	}
	platformTenantParam, _, ok := strings.Cut(platformEndpoint, "        - name: include_stale")
	if !ok {
		t.Fatal("/platform/endpoints/{deviceKey}/vulnerability-findings must document include_stale")
	}
	if !strings.Contains(platformTenantParam, "        - name: tenant_id\n          in: query\n          required: true") {
		t.Fatal("/platform/endpoints/{deviceKey}/vulnerability-findings must require tenant_id in the OpenAPI contract")
	}
}

func TestSDKHTTPRoutesExistInOpenAPI(t *testing.T) {
	root := repoRoot(t)
	openAPI, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	contracts := map[string][]string{
		filepath.Join("sdk", "typescript", "src", "index.ts"): {
			"/source-runtimes/{runtimeID}:",
			"/source-runtimes/{runtimeID}/claims:",
			"/platform/graph/neighborhood:",
		},
		filepath.Join("sdk", "python", "cerebro_sdk", "client.py"): {
			"/source-runtimes/{runtimeID}:",
			"/source-runtimes/{runtimeID}/claims:",
			"/platform/graph/neighborhood:",
		},
	}
	for rel, routes := range contracts {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, route := range routes {
			if !bytes.Contains(openAPI, []byte("  "+route)) {
				t.Fatalf("api/openapi.yaml missing SDK route %s required by %s", route, rel)
			}
		}
		for _, marker := range []string{"/source-runtimes/", "/platform/graph/neighborhood"} {
			if !bytes.Contains(body, []byte(marker)) {
				t.Fatalf("%s no longer references expected SDK route marker %q; update SDK route parity guardrail", rel, marker)
			}
		}
	}
	for _, rel := range []string{
		filepath.Join("sdk", "python", "pyproject.toml"),
		filepath.Join("sdk", "typescript", "package.json"),
	} {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, stale := range []string{"Agent SDK", "report runtime"} {
			if bytes.Contains(body, []byte(stale)) {
				t.Fatalf("%s contains retired SDK marker %q", rel, stale)
			}
		}
	}
}

func TestBootstrapPublicHTTPRoutesStayMethodScopedAndDocumented(t *testing.T) {
	root := repoRoot(t)
	routes, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "routes.go"))
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	for _, marker := range []string{
		`registerHTTPRoute(mux, "GET /health", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /healthz", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /livez", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /openapi.yaml", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /.well-known/agent-card.json", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /.well-known/agent.json", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /.well-known/device-jwks.json", routeSurfacePublicHTTP`,
		`registerHTTPRoute(mux, "GET /sources", routeSurfacePlatformHTTP`,
	} {
		if !bytes.Contains(routes, []byte(marker)) {
			t.Fatalf("routes.go missing method-scoped route marker %q", marker)
		}
	}
	for _, stale := range []string{
		`registerHTTPRoute(mux, "/health"`,
		`registerHTTPRoute(mux, "/healthz"`,
		`registerHTTPRoute(mux, "/livez"`,
		`registerHTTPRoute(mux, "/sources"`,
		`"GET /.well-known/device-jwks.json", routeSurfaceInternalHTTP`,
	} {
		if bytes.Contains(routes, []byte(stale)) {
			t.Fatalf("routes.go contains stale route marker %q", stale)
		}
	}

	auth, err := os.ReadFile(filepath.Join(root, "internal", "bootstrap", "auth.go"))
	if err != nil {
		t.Fatalf("read auth.go: %v", err)
	}
	for _, public := range []string{
		`agentplatform.A2AAgentCardPath`,
		`agentplatform.A2ALegacyAgentCardPath`,
		`"/.well-known/device-jwks.json"`,
		`oauthProtectedResourceMetadataPath`,
		`oauthAuthorizationServerMetadataPath`,
		`oauthTokenPath`,
		`oauthRegisterPath`,
	} {
		if !bytes.Contains(auth, []byte(public)) {
			t.Fatalf("auth.go missing public route marker %q", public)
		}
	}
	for _, doc := range []string{"docs/reference/api-reference.md", "docs/reference/api-contracts.md"} {
		body, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, marker := range []string{
			"/.well-known/device-jwks.json",
			"/.well-known/oauth-authorization-server",
			"/oauth/token",
			"/oauth/register",
		} {
			if !bytes.Contains(body, []byte(marker)) {
				t.Fatalf("%s missing public route marker %q", doc, marker)
			}
		}
	}
}

func TestSourceCDKOwnsExternalHTTPClients(t *testing.T) {
	root := repoRoot(t)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "gen", "sdk":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := shortPath(root, path)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, importSpec := range file.Imports {
			if strings.Trim(importSpec.Path.Value, `"`) != "net/http" {
				continue
			}
			if strings.HasPrefix(rel, "sources"+string(filepath.Separator)) ||
				strings.HasPrefix(rel, filepath.Join("internal", "bootstrap")+string(filepath.Separator)) ||
				strings.HasPrefix(rel, filepath.Join("internal", "observability")+string(filepath.Separator)) ||
				strings.HasPrefix(rel, filepath.Join("internal", "sourceplanapi")+string(filepath.Separator)) ||
				strings.HasPrefix(rel, filepath.Join("internal", "sourcehttp")+string(filepath.Separator)) ||
				strings.HasPrefix(rel, filepath.Join("tools", "connectorimport")+string(filepath.Separator)) {
				continue
			}
			t.Fatalf("%s imports net/http outside Source CDK or bootstrap boundary", rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("scan net/http imports: %v", err)
	}
}

func TestSourcesUseSharedHTTPSafety(t *testing.T) {
	root := repoRoot(t)
	if err := filepath.WalkDir(filepath.Join(root, "sources"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel := shortPath(root, path)
		for _, marker := range []string{
			"http.DefaultClient",
			"&http.Client{",
			"io.ReadAll(resp.Body)",
			"io.ReadAll(response.Body)",
			"func readLimitedBody(",
			"type safeRoundTripper",
		} {
			if bytes.Contains(body, []byte(marker)) {
				t.Fatalf("%s uses %s; source connectors must go through internal/sourcehttp", rel, marker)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("scan source HTTP safety: %v", err)
	}
}

func TestProductionBodyReadsAreBounded(t *testing.T) {
	root := repoRoot(t)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor", "gen", "sdk", "testdata":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(body, []byte("io.ReadAll(")) {
			return nil
		}
		rel := shortPath(root, path)
		findings, err := bodyread.FindUnboundedReadAll(rel, body)
		if err != nil {
			return err
		}
		if len(findings) > 0 {
			var lines []string
			for _, finding := range findings {
				lines = append(lines, finding.File+":"+strconv.Itoa(finding.Line))
			}
			t.Fatalf("production io.ReadAll calls must use io.LimitReader; unbounded reads: %s", strings.Join(lines, ", "))
		}
		return nil
	}); err != nil {
		t.Fatalf("scan bounded body reads: %v", err)
	}
}

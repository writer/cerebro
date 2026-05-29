package archtests

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"deprecated: true",
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
				strings.HasPrefix(rel, filepath.Join("internal", "sourcehttp")+string(filepath.Separator)) {
				continue
			}
			t.Fatalf("%s imports net/http outside Source CDK or bootstrap boundary", rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("scan net/http imports: %v", err)
	}
}

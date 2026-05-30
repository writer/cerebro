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
		rel := shortPath(root, path)
		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "io.ReadAll(") {
				continue
			}
			if boundedReadAllContext(lines, i) {
				continue
			}
			t.Fatalf("%s uses io.ReadAll without a nearby io.LimitReader or shared limited reader", rel)
		}
		return nil
	}); err != nil {
		t.Fatalf("scan bounded body reads: %v", err)
	}
}

func boundedReadAllContext(lines []string, index int) bool {
	start := index - 4
	if start < 0 {
		start = 0
	}
	end := index + 1
	if end >= len(lines) {
		end = len(lines) - 1
	}
	context := strings.Join(lines[start:end+1], "\n")
	for _, marker := range []string{
		"io.LimitReader(",
		"sourcehttp.ReadLimitedBody(",
		"sourcehttp.ReadLimitedBodyWithLimit(",
		"readLimitedVulnDBFeed(",
	} {
		if strings.Contains(context, marker) {
			return true
		}
	}
	return false
}

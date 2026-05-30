package archtests

import (
	"bytes"
	"go/ast"
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
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, body, 0)
		if err != nil {
			return err
		}
		if lines := unboundedReadAllLines(fset, file); len(lines) > 0 {
			t.Fatalf("%s:%d uses io.ReadAll without an explicit io.LimitReader", rel, lines[0])
		}
		return nil
	}); err != nil {
		t.Fatalf("scan bounded body reads: %v", err)
	}
}

func TestProductionBodyReadGuardAcceptsMultilineLimitReader(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader) ([]byte, error) {
	return io.ReadAll(
		io.LimitReader(reader, 1025),
	)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 0 {
		t.Fatalf("unbounded lines = %v, want multiline io.LimitReader accepted", lines)
	}
}

func TestProductionBodyReadGuardIgnoresCommentsAndStrings(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader) ([]byte, error) {
	_ = "io.LimitReader(reader, 1025)"
	// TODO: limited := io.LimitReader(reader, 1025)
	return io.ReadAll(reader)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want comment/string markers ignored", lines)
	}
}

func unboundedReadAllLinesForSource(t *testing.T, source string) []int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "sample.go", source, 0)
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return unboundedReadAllLines(fset, file)
}

func unboundedReadAllLines(fset *token.FileSet, file *ast.File) []int {
	var lines []int
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		limitedVars := limitedReaderAssignments(fn.Body)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isSelectorCall(call.Fun, "io", "ReadAll") {
				return true
			}
			if readAllCallIsBounded(call, limitedVars) {
				return true
			}
			lines = append(lines, fset.Position(call.Pos()).Line)
			return true
		})
		return false
	})
	return lines
}

func limitedReaderAssignments(body *ast.BlockStmt) map[string][]token.Pos {
	assignments := map[string][]token.Pos{}
	ast.Inspect(body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, rhs := range assign.Rhs {
			if !isIOLimitReaderCall(rhs) {
				continue
			}
			lhsIndex := index
			if len(assign.Lhs) == 1 {
				lhsIndex = 0
			}
			if lhsIndex >= len(assign.Lhs) {
				continue
			}
			if ident, ok := assign.Lhs[lhsIndex].(*ast.Ident); ok {
				assignments[ident.Name] = append(assignments[ident.Name], assign.Pos())
			}
		}
		return true
	})
	return assignments
}

func readAllCallIsBounded(call *ast.CallExpr, limitedVars map[string][]token.Pos) bool {
	if len(call.Args) == 0 {
		return false
	}
	arg := unwrapParen(call.Args[0])
	if isIOLimitReaderCall(arg) {
		return true
	}
	ident, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	for _, pos := range limitedVars[ident.Name] {
		if pos < call.Pos() {
			return true
		}
	}
	return false
}

func isIOLimitReaderCall(expr ast.Expr) bool {
	call, ok := unwrapParen(expr).(*ast.CallExpr)
	return ok && isSelectorCall(call.Fun, "io", "LimitReader")
}

func isSelectorCall(expr ast.Expr, qualifier string, name string) bool {
	selector, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == qualifier
}

func unwrapParen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

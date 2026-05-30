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
		if !bytes.Contains(body, []byte("io.ReadAll(")) {
			return nil
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

func TestProductionBodyReadGuardRejectsShadowedLimitReader(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, cond bool) ([]byte, error) {
	body := reader
	if cond {
		body := io.LimitReader(reader, 1025)
		_ = body
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want shadowed limited reader rejected", lines)
	}
}

func TestProductionBodyReadGuardKeepsIfInitializerScoped(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, cond bool) ([]byte, error) {
	body := reader
	if body := io.LimitReader(reader, 1025); cond {
		_ = body
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want if initializer limited reader scoped to if", lines)
	}
}

func TestProductionBodyReadGuardPreservesIfBodyOuterReassignment(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, cond bool) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	if cond {
		body = reader
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want if body outer reassignment rejected", lines)
	}
}

func TestProductionBodyReadGuardScopesSwitchAndSelectCases(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, ch <-chan struct{}, mode string) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	switch mode {
	case "raw":
		body = reader
		return io.ReadAll(body)
	}
	select {
	case <-ch:
		body = reader
		return io.ReadAll(body)
	default:
		return io.ReadAll(body)
	}
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 2 {
		t.Fatalf("unbounded lines = %v, want switch/select case resets rejected", lines)
	}
}

func TestProductionBodyReadGuardPreservesBareBlockReassignment(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	{
		body = reader
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want bare block outer reassignment rejected", lines)
	}
}

func TestProductionBodyReadGuardModelsFunctionLiteralReassignment(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	func() {
		body = reader
	}()
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want function literal reassignment rejected", lines)
	}
}

func TestProductionBodyReadGuardIgnoresNonExecutedFunctionLiteral(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	_ = func() {
		body = reader
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 0 {
		t.Fatalf("unbounded lines = %v, want non-executed function literal ignored", lines)
	}
}

func TestProductionBodyReadGuardStopsBareBlockAfterContinue(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, cond bool) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	for cond {
		continue
		body = reader
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 0 {
		t.Fatalf("unbounded lines = %v, want unreachable assignment after continue ignored", lines)
	}
}

func TestProductionBodyReadGuardCarriesContinueMutation(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, cond bool) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	for cond {
		body = reader
		continue
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want mutation before continue rejected", lines)
	}
}

func TestProductionBodyReadGuardCarriesSwitchFallthrough(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, mode string) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	switch mode {
	case "raw":
		body = reader
		fallthrough
	default:
		return io.ReadAll(body)
	}
	return nil, nil
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want fallthrough reassignment rejected", lines)
	}
}

func TestProductionBodyReadGuardTreatsBreakAsContinuing(t *testing.T) {
	source := `package sample

import "io"

func readBody(reader io.Reader, mode string) ([]byte, error) {
	body := io.LimitReader(reader, 1025)
	switch mode {
	case "raw":
		body = reader
		break
	}
	return io.ReadAll(body)
}`
	if lines := unboundedReadAllLinesForSource(t, source); len(lines) != 1 {
		t.Fatalf("unbounded lines = %v, want break branch reassignment rejected", lines)
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
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		collectUnboundedReadAllLines(fset, fn.Body.List, map[*ast.Object]bool{}, &lines)
	}
	return lines
}

func collectUnboundedReadAllLines(fset *token.FileSet, statements []ast.Stmt, limitedVars map[*ast.Object]bool, lines *[]int) {
	for _, statement := range statements {
		switch stmt := statement.(type) {
		case *ast.AssignStmt:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, lines)
			recordLimitedAssignments(stmt.Lhs, stmt.Rhs, limitedVars)
		case *ast.DeclStmt:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, lines)
			recordLimitedValueSpecs(stmt, limitedVars)
		case *ast.BlockStmt:
			blockVars := cloneLimitedVars(limitedVars)
			collectUnboundedReadAllLines(fset, stmt.List, blockVars, lines)
			mergeLimitedVars(limitedVars, blockVars)
		case *ast.IfStmt:
			ifVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, ifVars, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Cond, ifVars, lines)
			thenVars := cloneLimitedVars(ifVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, thenVars, lines)
			elseVars := cloneLimitedVars(ifVars)
			if stmt.Else != nil {
				collectUnboundedReadAllInElse(fset, stmt.Else, elseVars, lines)
			}
			var branches []map[*ast.Object]bool
			if statementsMayContinue(stmt.Body.List) {
				branches = append(branches, thenVars)
			}
			if stmt.Else == nil || statementMayContinue(stmt.Else) {
				branches = append(branches, elseVars)
			}
			mergeLimitedVars(limitedVars, branches...)
		case *ast.ForStmt:
			loopVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, loopVars, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Cond, loopVars, lines)
			if stmt.Post != nil {
				recordUnboundedReadAllInNode(fset, stmt.Post, loopVars, lines)
			}
			bodyVars := cloneLimitedVars(loopVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, bodyVars, lines)
			mergeLimitedVars(limitedVars, loopVars, bodyVars)
		case *ast.RangeStmt:
			recordUnboundedReadAllInNode(fset, stmt.X, limitedVars, lines)
			bodyVars := cloneLimitedVars(limitedVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, bodyVars, lines)
			mergeLimitedVars(limitedVars, bodyVars)
		case *ast.SwitchStmt:
			switchVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, switchVars, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Tag, switchVars, lines)
			caseVars, hasDefault := collectUnboundedReadAllInCaseClauses(fset, stmt.Body, switchVars, lines)
			if !hasDefault {
				caseVars = append(caseVars, switchVars)
			}
			mergeLimitedVars(limitedVars, caseVars...)
		case *ast.TypeSwitchStmt:
			switchVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, switchVars, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Assign, switchVars, lines)
			caseVars, hasDefault := collectUnboundedReadAllInCaseClauses(fset, stmt.Body, switchVars, lines)
			if !hasDefault {
				caseVars = append(caseVars, switchVars)
			}
			mergeLimitedVars(limitedVars, caseVars...)
		case *ast.SelectStmt:
			commVars, hasDefault := collectUnboundedReadAllInCommClauses(fset, stmt.Body, limitedVars, lines)
			if !hasDefault {
				commVars = append(commVars, limitedVars)
			}
			mergeLimitedVars(limitedVars, commVars...)
		default:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, lines)
		}
		if !statementMayReachNextStatement(statement) {
			return
		}
	}
}

func collectUnboundedReadAllInCaseClauses(fset *token.FileSet, body *ast.BlockStmt, limitedVars map[*ast.Object]bool, lines *[]int) ([]map[*ast.Object]bool, bool) {
	if body == nil {
		return nil, false
	}
	var branches []map[*ast.Object]bool
	hasDefault := false
	var fallthroughVars map[*ast.Object]bool
	for _, statement := range body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			recordUnboundedReadAllInNode(fset, statement, limitedVars, lines)
			continue
		}
		if len(clause.List) == 0 {
			hasDefault = true
		}
		caseVars := cloneLimitedVars(limitedVars)
		if fallthroughVars != nil {
			mergeLimitedVars(caseVars, caseVars, fallthroughVars)
			fallthroughVars = nil
		}
		for _, expr := range clause.List {
			recordUnboundedReadAllInNode(fset, expr, caseVars, lines)
		}
		collectUnboundedReadAllLines(fset, clause.Body, caseVars, lines)
		if statementsFallThrough(clause.Body) {
			fallthroughVars = caseVars
			continue
		}
		if statementsMayContinue(clause.Body) {
			branches = append(branches, caseVars)
		}
	}
	return branches, hasDefault
}

func collectUnboundedReadAllInCommClauses(fset *token.FileSet, body *ast.BlockStmt, limitedVars map[*ast.Object]bool, lines *[]int) ([]map[*ast.Object]bool, bool) {
	if body == nil {
		return nil, false
	}
	var branches []map[*ast.Object]bool
	hasDefault := false
	for _, statement := range body.List {
		clause, ok := statement.(*ast.CommClause)
		if !ok {
			recordUnboundedReadAllInNode(fset, statement, limitedVars, lines)
			continue
		}
		if clause.Comm == nil {
			hasDefault = true
		}
		commVars := cloneLimitedVars(limitedVars)
		if clause.Comm != nil {
			collectUnboundedReadAllLines(fset, []ast.Stmt{clause.Comm}, commVars, lines)
		}
		collectUnboundedReadAllLines(fset, clause.Body, commVars, lines)
		if statementsMayContinue(clause.Body) {
			branches = append(branches, commVars)
		}
	}
	return branches, hasDefault
}

func collectUnboundedReadAllInElse(fset *token.FileSet, statement ast.Stmt, limitedVars map[*ast.Object]bool, lines *[]int) {
	switch stmt := statement.(type) {
	case *ast.BlockStmt:
		collectUnboundedReadAllLines(fset, stmt.List, limitedVars, lines)
	case *ast.IfStmt:
		collectUnboundedReadAllLines(fset, []ast.Stmt{stmt}, limitedVars, lines)
	default:
		recordUnboundedReadAllInNode(fset, stmt, limitedVars, lines)
	}
}

func recordUnboundedReadAllInNode(fset *token.FileSet, node ast.Node, limitedVars map[*ast.Object]bool, lines *[]int) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := unwrapParen(call.Fun).(*ast.FuncLit); ok {
			funcVars := cloneLimitedVars(limitedVars)
			collectUnboundedReadAllLines(fset, fn.Body.List, funcVars, lines)
			mergeLimitedVars(limitedVars, funcVars)
			return false
		}
		if !ok || !isSelectorCall(call.Fun, "io", "ReadAll") {
			return true
		}
		if !readAllCallIsBounded(call, limitedVars) {
			*lines = append(*lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
}

func recordLimitedAssignments(lhs []ast.Expr, rhs []ast.Expr, limitedVars map[*ast.Object]bool) {
	for index, left := range lhs {
		ident, ok := left.(*ast.Ident)
		if !ok || ident.Obj == nil {
			continue
		}
		rhsIndex := index
		if len(rhs) == 1 {
			rhsIndex = 0
		}
		limitedVars[ident.Obj] = rhsIndex < len(rhs) && isIOLimitReaderCall(rhs[rhsIndex])
	}
}

func recordLimitedValueSpecs(statement *ast.DeclStmt, limitedVars map[*ast.Object]bool) {
	decl, ok := statement.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for index, name := range valueSpec.Names {
			if name.Obj == nil {
				continue
			}
			valueIndex := index
			if len(valueSpec.Values) == 1 {
				valueIndex = 0
			}
			limitedVars[name.Obj] = valueIndex < len(valueSpec.Values) && isIOLimitReaderCall(valueSpec.Values[valueIndex])
		}
	}
}

func cloneLimitedVars(values map[*ast.Object]bool) map[*ast.Object]bool {
	clone := make(map[*ast.Object]bool, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func statementsMayContinue(statements []ast.Stmt) bool {
	if len(statements) == 0 {
		return true
	}
	return statementMayContinue(statements[len(statements)-1])
}

func statementsFallThrough(statements []ast.Stmt) bool {
	if len(statements) == 0 {
		return false
	}
	branch, ok := statements[len(statements)-1].(*ast.BranchStmt)
	return ok && branch.Tok == token.FALLTHROUGH
}

func statementMayContinue(statement ast.Stmt) bool {
	switch stmt := statement.(type) {
	case *ast.ReturnStmt:
		return false
	case *ast.BranchStmt:
		return true
	case *ast.BlockStmt:
		return statementsMayContinue(stmt.List)
	case *ast.IfStmt:
		return stmt.Else == nil || statementMayContinue(stmt.Body) || statementMayContinue(stmt.Else)
	default:
		return true
	}
}

func statementMayReachNextStatement(statement ast.Stmt) bool {
	switch stmt := statement.(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return false
	case *ast.BlockStmt:
		return statementsMayContinue(stmt.List)
	case *ast.IfStmt:
		return stmt.Else == nil || statementMayReachNextStatement(stmt.Body) || statementMayReachNextStatement(stmt.Else)
	default:
		return true
	}
}

func mergeLimitedVars(target map[*ast.Object]bool, branches ...map[*ast.Object]bool) {
	if len(branches) == 0 {
		return
	}
	keys := map[*ast.Object]struct{}{}
	for key := range target {
		keys[key] = struct{}{}
	}
	for _, branch := range branches {
		for key := range branch {
			keys[key] = struct{}{}
		}
	}
	for key := range keys {
		limited := true
		for _, branch := range branches {
			limited = limited && branch[key]
		}
		target[key] = limited
	}
}

func readAllCallIsBounded(call *ast.CallExpr, limitedVars map[*ast.Object]bool) bool {
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
	if ident.Obj == nil {
		return false
	}
	return limitedVars[ident.Obj]
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

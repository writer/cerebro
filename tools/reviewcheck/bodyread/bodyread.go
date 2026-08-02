package bodyread

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

type Finding struct {
	File string
	Line int
}

func FindUnboundedReadAll(filePath string, source []byte) ([]Finding, error) {
	if !bytes.Contains(source, []byte("io.ReadAll(")) {
		return nil, nil
	}
	if strings.HasSuffix(filePath, "_test.go") || !strings.HasSuffix(filePath, ".go") {
		return nil, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, source, 0)
	if err != nil {
		return nil, err
	}
	ioImports := ioImportNames(file)
	if len(ioImports) == 0 {
		return nil, nil
	}
	var lines []int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		collectUnboundedReadAllLines(fset, fn.Body.List, map[*ast.Object]bool{}, ioImports, &lines)
	}
	findings := make([]Finding, 0, len(lines))
	for _, line := range lines {
		findings = append(findings, Finding{File: filepath.ToSlash(filePath), Line: line})
	}
	return findings, nil
}

func ioImportNames(file *ast.File) map[string]struct{} {
	names := map[string]struct{}{}
	for _, importSpec := range file.Imports {
		if strings.Trim(importSpec.Path.Value, `"`) != "io" {
			continue
		}
		name := "io"
		if importSpec.Name != nil {
			if importSpec.Name.Name == "." || importSpec.Name.Name == "_" {
				continue
			}
			name = importSpec.Name.Name
		}
		names[name] = struct{}{}
	}
	return names
}

func collectUnboundedReadAllLines(fset *token.FileSet, statements []ast.Stmt, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}, lines *[]int) {
	for _, statement := range statements {
		switch stmt := statement.(type) {
		case *ast.AssignStmt:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, ioImports, lines)
			recordLimitedAssignments(stmt.Lhs, stmt.Rhs, limitedVars, ioImports)
		case *ast.DeclStmt:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, ioImports, lines)
			recordLimitedValueSpecs(stmt, limitedVars, ioImports)
		case *ast.BlockStmt:
			blockVars := cloneLimitedVars(limitedVars)
			collectUnboundedReadAllLines(fset, stmt.List, blockVars, ioImports, lines)
			mergeLimitedVars(limitedVars, blockVars)
		case *ast.LabeledStmt:
			collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Stmt}, limitedVars, ioImports, lines)
		case *ast.IfStmt:
			ifVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, ifVars, ioImports, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Cond, ifVars, ioImports, lines)
			thenVars := cloneLimitedVars(ifVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, thenVars, ioImports, lines)
			elseVars := cloneLimitedVars(ifVars)
			if stmt.Else != nil {
				collectUnboundedReadAllInElse(fset, stmt.Else, elseVars, ioImports, lines)
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
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, loopVars, ioImports, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Cond, loopVars, ioImports, lines)
			if stmt.Post != nil {
				recordUnboundedReadAllInNode(fset, stmt.Post, loopVars, ioImports, lines)
			}
			bodyVars := cloneLimitedVars(loopVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, bodyVars, ioImports, lines)
			mergeLimitedVars(limitedVars, loopVars, bodyVars)
		case *ast.RangeStmt:
			recordUnboundedReadAllInNode(fset, stmt.X, limitedVars, ioImports, lines)
			rangeVars := cloneLimitedVars(limitedVars)
			bodyVars := cloneLimitedVars(rangeVars)
			collectUnboundedReadAllLines(fset, stmt.Body.List, bodyVars, ioImports, lines)
			mergeLimitedVars(limitedVars, rangeVars, bodyVars)
		case *ast.SwitchStmt:
			switchVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, switchVars, ioImports, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Tag, switchVars, ioImports, lines)
			caseVars, hasDefault := collectUnboundedReadAllInCaseClauses(fset, stmt.Body, switchVars, ioImports, lines)
			if !hasDefault {
				caseVars = append(caseVars, switchVars)
			}
			mergeLimitedVars(limitedVars, caseVars...)
		case *ast.TypeSwitchStmt:
			switchVars := cloneLimitedVars(limitedVars)
			if stmt.Init != nil {
				collectUnboundedReadAllLines(fset, []ast.Stmt{stmt.Init}, switchVars, ioImports, lines)
			}
			recordUnboundedReadAllInNode(fset, stmt.Assign, switchVars, ioImports, lines)
			caseVars, hasDefault := collectUnboundedReadAllInCaseClauses(fset, stmt.Body, switchVars, ioImports, lines)
			if !hasDefault {
				caseVars = append(caseVars, switchVars)
			}
			mergeLimitedVars(limitedVars, caseVars...)
		case *ast.SelectStmt:
			commVars, hasDefault := collectUnboundedReadAllInCommClauses(fset, stmt.Body, limitedVars, ioImports, lines)
			if !hasDefault {
				commVars = append(commVars, limitedVars)
			}
			mergeLimitedVars(limitedVars, commVars...)
		default:
			recordUnboundedReadAllInNode(fset, stmt, limitedVars, ioImports, lines)
		}
	}
}

func collectUnboundedReadAllInCaseClauses(fset *token.FileSet, body *ast.BlockStmt, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}, lines *[]int) ([]map[*ast.Object]bool, bool) {
	if body == nil {
		return nil, false
	}
	var branches []map[*ast.Object]bool
	hasDefault := false
	var fallthroughVars map[*ast.Object]bool
	for _, statement := range body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			recordUnboundedReadAllInNode(fset, statement, limitedVars, ioImports, lines)
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
			recordUnboundedReadAllInNode(fset, expr, caseVars, ioImports, lines)
		}
		collectUnboundedReadAllLines(fset, clause.Body, caseVars, ioImports, lines)
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

func collectUnboundedReadAllInCommClauses(fset *token.FileSet, body *ast.BlockStmt, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}, lines *[]int) ([]map[*ast.Object]bool, bool) {
	if body == nil {
		return nil, false
	}
	var branches []map[*ast.Object]bool
	hasDefault := false
	for _, statement := range body.List {
		clause, ok := statement.(*ast.CommClause)
		if !ok {
			recordUnboundedReadAllInNode(fset, statement, limitedVars, ioImports, lines)
			continue
		}
		if clause.Comm == nil {
			hasDefault = true
		}
		commVars := cloneLimitedVars(limitedVars)
		if clause.Comm != nil {
			collectUnboundedReadAllLines(fset, []ast.Stmt{clause.Comm}, commVars, ioImports, lines)
		}
		collectUnboundedReadAllLines(fset, clause.Body, commVars, ioImports, lines)
		if statementsMayContinue(clause.Body) {
			branches = append(branches, commVars)
		}
	}
	return branches, hasDefault
}

func collectUnboundedReadAllInElse(fset *token.FileSet, statement ast.Stmt, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}, lines *[]int) {
	switch stmt := statement.(type) {
	case *ast.BlockStmt:
		collectUnboundedReadAllLines(fset, stmt.List, limitedVars, ioImports, lines)
	case *ast.IfStmt:
		collectUnboundedReadAllLines(fset, []ast.Stmt{stmt}, limitedVars, ioImports, lines)
	default:
		recordUnboundedReadAllInNode(fset, stmt, limitedVars, ioImports, lines)
	}
}

func recordUnboundedReadAllInNode(fset *token.FileSet, node ast.Node, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}, lines *[]int) {
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
			collectUnboundedReadAllLines(fset, fn.Body.List, funcVars, ioImports, lines)
			mergeLimitedVars(limitedVars, funcVars)
			return false
		}
		if !isSelectorCall(call.Fun, ioImports, "ReadAll") {
			return true
		}
		if !readAllCallIsBounded(call, limitedVars, ioImports) {
			*lines = append(*lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
}

func recordLimitedAssignments(lhs []ast.Expr, rhs []ast.Expr, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}) {
	for index, left := range lhs {
		ident, ok := left.(*ast.Ident)
		if !ok || ident.Obj == nil {
			continue
		}
		rhsIndex := index
		if len(rhs) == 1 {
			rhsIndex = 0
		}
		limitedVars[ident.Obj] = rhsIndex < len(rhs) && isIOLimitReaderCall(rhs[rhsIndex], ioImports)
	}
}

func recordLimitedValueSpecs(statement *ast.DeclStmt, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}) {
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
			limitedVars[name.Obj] = valueIndex < len(valueSpec.Values) && isIOLimitReaderCall(valueSpec.Values[valueIndex], ioImports)
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

func readAllCallIsBounded(call *ast.CallExpr, limitedVars map[*ast.Object]bool, ioImports map[string]struct{}) bool {
	if len(call.Args) == 0 {
		return false
	}
	arg := unwrapParen(call.Args[0])
	if isIOLimitReaderCall(arg, ioImports) {
		return true
	}
	ident, ok := arg.(*ast.Ident)
	if !ok || ident.Obj == nil {
		return false
	}
	return limitedVars[ident.Obj]
}

func isIOLimitReaderCall(expr ast.Expr, ioImports map[string]struct{}) bool {
	call, ok := unwrapParen(expr).(*ast.CallExpr)
	return ok && isSelectorCall(call.Fun, ioImports, "LimitReader")
}

func isSelectorCall(expr ast.Expr, ioImports map[string]struct{}, name string) bool {
	selector, ok := unwrapParen(expr).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	if !ok || ident.Obj != nil {
		return false
	}
	_, ok = ioImports[ident.Name]
	return ok
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

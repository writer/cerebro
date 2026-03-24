package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const graphImportPath = "github.com/writer/cerebro/internal/graph"

type identifierKind int

const (
	identifierKindUnknown identifierKind = iota
	identifierKindNode
	identifierKindEdge
)

type identifierEnv struct {
	node map[string]struct{}
	edge map[string]struct{}
}

func newIdentifierEnv() *identifierEnv {
	return &identifierEnv{
		node: make(map[string]struct{}),
		edge: make(map[string]struct{}),
	}
}

func (e *identifierEnv) clone() *identifierEnv {
	if e == nil {
		return newIdentifierEnv()
	}
	cloned := newIdentifierEnv()
	for name := range e.node {
		cloned.node[name] = struct{}{}
	}
	for name := range e.edge {
		cloned.edge[name] = struct{}{}
	}
	return cloned
}

func (e *identifierEnv) mark(name string, kind identifierKind) {
	if e == nil || strings.TrimSpace(name) == "" {
		return
	}
	delete(e.node, name)
	delete(e.edge, name)
	switch kind {
	case identifierKindNode:
		e.node[name] = struct{}{}
	case identifierKindEdge:
		e.edge[name] = struct{}{}
	}
}

func (e *identifierEnv) kind(name string) identifierKind {
	if e == nil {
		return identifierKindUnknown
	}
	if _, ok := e.node[name]; ok {
		return identifierKindNode
	}
	if _, ok := e.edge[name]; ok {
		return identifierKindEdge
	}
	return identifierKindUnknown
}

func main() {
	diagnostics, err := checkFiles(filteredGoPaths(os.Args[1:]))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(diagnostics) == 0 {
		return
	}
	for _, diagnostic := range diagnostics {
		fmt.Fprintln(os.Stderr, diagnostic)
	}
	fmt.Fprintln(os.Stderr, "graph identifier safety: move graph node/edge IDs into typed ...NodeID/...EdgeID helpers")
	os.Exit(1)
}

func filteredGoPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if filepath.Ext(path) != ".go" {
			continue
		}
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		out = append(out, path)
	}
	return out
}

func checkFiles(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	fset := token.NewFileSet()
	diagnostics := make([]string, 0)
	for _, path := range paths {
		fileDiagnostics, err := analyzeFile(fset, path)
		if err != nil {
			return nil, err
		}
		diagnostics = append(diagnostics, fileDiagnostics...)
	}
	sort.Strings(diagnostics)
	return diagnostics, nil
}

func analyzeFile(fset *token.FileSet, path string) ([]string, error) {
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	graphAliases := graphImportAliases(file)
	diagnostics := make([]string, 0)

	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.FuncDecl:
			if typed.Body != nil {
				checkBlock(fset, path, typed.Body, file.Name.Name, graphAliases, newIdentifierEnv(), &diagnostics)
			}
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, value := range valueSpec.Values {
					checkNode(value, fset, path, file.Name.Name, graphAliases, newIdentifierEnv(), &diagnostics)
				}
			}
		}
	}

	return diagnostics, nil
}

func graphImportAliases(file *ast.File) map[string]struct{} {
	aliases := make(map[string]struct{})
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path != graphImportPath {
			continue
		}
		name := "graph"
		if imp.Name != nil && strings.TrimSpace(imp.Name.Name) != "" {
			name = strings.TrimSpace(imp.Name.Name)
		}
		aliases[name] = struct{}{}
	}
	return aliases
}

func checkBlock(fset *token.FileSet, path string, block *ast.BlockStmt, packageName string, graphAliases map[string]struct{}, env *identifierEnv, diagnostics *[]string) {
	if block == nil {
		return
	}
	if env == nil {
		env = newIdentifierEnv()
	}
	for _, stmt := range block.List {
		checkStmt(fset, path, stmt, packageName, graphAliases, env, diagnostics)
	}
}

func checkStmt(fset *token.FileSet, path string, stmt ast.Stmt, packageName string, graphAliases map[string]struct{}, env *identifierEnv, diagnostics *[]string) {
	switch typed := stmt.(type) {
	case *ast.BlockStmt:
		checkBlock(fset, path, typed, packageName, graphAliases, env.clone(), diagnostics)
	case *ast.AssignStmt:
		checkNode(typed, fset, path, packageName, graphAliases, env, diagnostics)
		recordAssignedIdentifiers(typed.Lhs, typed.Rhs, env)
	case *ast.DeclStmt:
		checkNode(typed, fset, path, packageName, graphAliases, env, diagnostics)
		recordDeclaredIdentifiers(typed, env)
	case *ast.IfStmt:
		scopeEnv := env.clone()
		if typed.Init != nil {
			checkStmt(fset, path, typed.Init, packageName, graphAliases, scopeEnv, diagnostics)
		}
		checkNode(typed.Cond, fset, path, packageName, graphAliases, scopeEnv, diagnostics)
		checkBlock(fset, path, typed.Body, packageName, graphAliases, scopeEnv.clone(), diagnostics)
		if typed.Else != nil {
			checkStmt(fset, path, typed.Else, packageName, graphAliases, scopeEnv.clone(), diagnostics)
		}
	case *ast.ForStmt:
		scopeEnv := env.clone()
		if typed.Init != nil {
			checkStmt(fset, path, typed.Init, packageName, graphAliases, scopeEnv, diagnostics)
		}
		if typed.Cond != nil {
			checkNode(typed.Cond, fset, path, packageName, graphAliases, scopeEnv, diagnostics)
		}
		if typed.Post != nil {
			checkStmt(fset, path, typed.Post, packageName, graphAliases, scopeEnv, diagnostics)
		}
		checkBlock(fset, path, typed.Body, packageName, graphAliases, scopeEnv.clone(), diagnostics)
	case *ast.RangeStmt:
		checkNode(typed.X, fset, path, packageName, graphAliases, env, diagnostics)
		checkBlock(fset, path, typed.Body, packageName, graphAliases, env.clone(), diagnostics)
	case *ast.SwitchStmt:
		scopeEnv := env.clone()
		if typed.Init != nil {
			checkStmt(fset, path, typed.Init, packageName, graphAliases, scopeEnv, diagnostics)
		}
		if typed.Tag != nil {
			checkNode(typed.Tag, fset, path, packageName, graphAliases, scopeEnv, diagnostics)
		}
		for _, stmt := range typed.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			clauseEnv := scopeEnv.clone()
			for _, expr := range clause.List {
				checkNode(expr, fset, path, packageName, graphAliases, scopeEnv, diagnostics)
			}
			for _, clauseStmt := range clause.Body {
				checkStmt(fset, path, clauseStmt, packageName, graphAliases, clauseEnv, diagnostics)
			}
		}
	default:
		checkNode(stmt, fset, path, packageName, graphAliases, env, diagnostics)
	}
}

func recordDeclaredIdentifiers(stmt *ast.DeclStmt, env *identifierEnv) {
	genDecl, ok := stmt.Decl.(*ast.GenDecl)
	if !ok || genDecl.Tok != token.VAR {
		return
	}
	for _, spec := range genDecl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range valueSpec.Names {
			if name == nil {
				continue
			}
			kind := identifierKindUnknown
			if i < len(valueSpec.Values) {
				kind = classifySafeIdentifierExpr(valueSpec.Values[i], env)
			}
			env.mark(name.Name, kind)
		}
	}
}

func recordAssignedIdentifiers(lhs []ast.Expr, rhs []ast.Expr, env *identifierEnv) {
	for i, left := range lhs {
		name, ok := left.(*ast.Ident)
		if !ok || name == nil {
			continue
		}
		kind := identifierKindUnknown
		switch {
		case len(rhs) == 1:
			if i == 0 {
				kind = classifySafeIdentifierExpr(rhs[0], env)
			}
		case i < len(rhs):
			kind = classifySafeIdentifierExpr(rhs[i], env)
		}
		env.mark(name.Name, kind)
	}
}

func checkNode(node ast.Node, fset *token.FileSet, path string, packageName string, graphAliases map[string]struct{}, env *identifierEnv, diagnostics *[]string) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(current ast.Node) bool {
		lit, ok := current.(*ast.CompositeLit)
		if !ok {
			return true
		}
		kind := compositeIdentifierKind(lit, packageName, graphAliases)
		if kind == identifierKindUnknown {
			return true
		}
		for _, elt := range lit.Elts {
			field, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok || key == nil || key.Name != "ID" {
				continue
			}
			if isSafeIdentifierExpr(field.Value, kind, env) {
				continue
			}
			position := fset.Position(field.Value.Pos())
			*diagnostics = append(*diagnostics, fmt.Sprintf("%s:%d: graph %s ID must come from a typed %sID helper or safe propagated identifier", path, position.Line, kindLabel(kind), kindLabel(kind)))
		}
		return true
	})
}

func compositeIdentifierKind(lit *ast.CompositeLit, packageName string, graphAliases map[string]struct{}) identifierKind {
	switch typed := lit.Type.(type) {
	case *ast.Ident:
		if packageName != "graph" {
			return identifierKindUnknown
		}
		switch typed.Name {
		case "Node":
			return identifierKindNode
		case "Edge":
			return identifierKindEdge
		}
	case *ast.SelectorExpr:
		pkg, ok := typed.X.(*ast.Ident)
		if !ok || pkg == nil {
			return identifierKindUnknown
		}
		if _, ok := graphAliases[pkg.Name]; !ok {
			return identifierKindUnknown
		}
		switch typed.Sel.Name {
		case "Node":
			return identifierKindNode
		case "Edge":
			return identifierKindEdge
		}
	}
	return identifierKindUnknown
}

func isSafeIdentifierExpr(expr ast.Expr, want identifierKind, env *identifierEnv) bool {
	return classifySafeIdentifierExpr(expr, env) == want
}

func classifySafeIdentifierExpr(expr ast.Expr, env *identifierEnv) identifierKind {
	switch typed := expr.(type) {
	case *ast.CallExpr:
		return classifySafeIdentifierExpr(typed.Fun, env)
	case *ast.Ident:
		switch {
		case strings.HasSuffix(typed.Name, "NodeID"):
			return identifierKindNode
		case strings.HasSuffix(typed.Name, "EdgeID"):
			return identifierKindEdge
		default:
			return env.kind(typed.Name)
		}
	case *ast.SelectorExpr:
		switch {
		case strings.HasSuffix(typed.Sel.Name, "NodeID"):
			return identifierKindNode
		case strings.HasSuffix(typed.Sel.Name, "EdgeID"):
			return identifierKindEdge
		default:
			return identifierKindUnknown
		}
	case *ast.ParenExpr:
		return classifySafeIdentifierExpr(typed.X, env)
	default:
		return identifierKindUnknown
	}
}

func kindLabel(kind identifierKind) string {
	switch kind {
	case identifierKindNode:
		return "node"
	case identifierKindEdge:
		return "edge"
	default:
		return "identifier"
	}
}

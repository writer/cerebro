package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type routeMethodSet map[string]map[string]struct{}

var routeCallToHTTPMethod = map[string]string{
	"Get":     http.MethodGet,
	"Post":    http.MethodPost,
	"Put":     http.MethodPut,
	"Delete":  http.MethodDelete,
	"Patch":   http.MethodPatch,
	"Head":    http.MethodHead,
	"Options": http.MethodOptions,
}

func TestRoutePermission_CoversAllRegisteredAPIRoutes(t *testing.T) {
	routes, err := collectRegisteredRoutes("server_routes.go")
	if err != nil {
		t.Fatalf("collect routes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes collected from server_routes.go")
	}

	missing := make([]string, 0)
	for path, methods := range routes {
		if !strings.HasPrefix(path, "/api/v1") {
			continue
		}
		for method := range methods {
			if routePermission(method, path) == "" {
				missing = append(missing, method+" "+path)
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("routePermission missing mapping for routes: %s", strings.Join(missing, ", "))
	}
}

func collectRegisteredRoutes(routesPath string) (routeMethodSet, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, routesPath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	routes := make(routeMethodSet)
	var setupRoutesDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "setupRoutes" {
			continue
		}
		setupRoutesDecl = fn
		break
	}
	if setupRoutesDecl == nil || setupRoutesDecl.Body == nil {
		return nil, nil
	}

	walkRouteStatements(setupRoutesDecl.Body.List, "", routes)
	return routes, nil
}

func walkRouteStatements(stmts []ast.Stmt, prefix string, routes routeMethodSet) {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			walkRouteExpr(s.X, prefix, routes)
		case *ast.BlockStmt:
			walkRouteStatements(s.List, prefix, routes)
		case *ast.IfStmt:
			walkRouteStatements(s.Body.List, prefix, routes)
			if s.Else != nil {
				walkRouteStatements([]ast.Stmt{s.Else}, prefix, routes)
			}
		case *ast.ForStmt:
			walkRouteStatements(s.Body.List, prefix, routes)
		case *ast.RangeStmt:
			walkRouteStatements(s.Body.List, prefix, routes)
		}
	}
}

func walkRouteExpr(expr ast.Expr, prefix string, routes routeMethodSet) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return
	}

	switch sel.Sel.Name {
	case "Route":
		if len(call.Args) < 2 {
			return
		}
		segment, ok := stringLiteral(call.Args[0])
		if !ok {
			return
		}
		fn, ok := call.Args[1].(*ast.FuncLit)
		if !ok || fn.Body == nil {
			return
		}
		walkRouteStatements(fn.Body.List, joinRoutePath(prefix, segment), routes)
	default:
		method, ok := routeCallToHTTPMethod[sel.Sel.Name]
		if !ok || len(call.Args) < 1 {
			return
		}

		segment, ok := stringLiteral(call.Args[0])
		if !ok {
			return
		}

		fullPath := joinRoutePath(prefix, segment)
		if _, ok := routes[fullPath]; !ok {
			routes[fullPath] = make(map[string]struct{})
		}
		routes[fullPath][method] = struct{}{}
	}
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func joinRoutePath(base, segment string) string {
	base = strings.TrimSpace(base)
	segment = strings.TrimSpace(segment)

	if base == "" {
		return normalizeRoutePath(segment)
	}
	if segment == "" {
		return normalizeRoutePath(base)
	}
	if base == "/" {
		return normalizeRoutePath(segment)
	}
	if segment == "/" {
		return normalizeRoutePath(base)
	}

	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(segment, "/") {
		return normalizeRoutePath(base + segment)
	}
	return normalizeRoutePath(base + "/" + segment)
}

func normalizeRoutePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.ReplaceAll(path, "//", "/")
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

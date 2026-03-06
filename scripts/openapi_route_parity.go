//go:build ignore

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var httpMethods = map[string]struct{}{
	"Get":     {},
	"Post":    {},
	"Put":     {},
	"Delete":  {},
	"Patch":   {},
	"Head":    {},
	"Options": {},
}

type routeSet map[string]map[string]struct{}

func main() {
	var (
		routesPath  string
		openAPIPath string
		write       bool
	)
	flag.StringVar(&routesPath, "routes", "internal/api/server_routes.go", "Path to chi route definition file")
	flag.StringVar(&openAPIPath, "openapi", "api/openapi.yaml", "Path to OpenAPI spec")
	flag.BoolVar(&write, "write", false, "Write missing paths/methods into the OpenAPI spec")
	flag.Parse()

	routes, err := collectRoutes(routesPath)
	if err != nil {
		fatalf("collect routes: %v", err)
	}
	if len(routes) == 0 {
		fatalf("no routes found in %s", routesPath)
	}

	doc, pathsNode, err := loadOpenAPINode(openAPIPath)
	if err != nil {
		fatalf("load openapi: %v", err)
	}

	missingPaths, missingMethods := findMissing(routes, pathsNode)
	if len(missingPaths) == 0 && len(missingMethods) == 0 {
		fmt.Printf("OpenAPI route parity check passed (%d routes)\n", len(routes))
		return
	}

	if !write {
		printMissing(missingPaths, missingMethods)
		os.Exit(1)
	}

	for _, p := range missingPaths {
		addPathNode(pathsNode, p, routes[p])
	}
	for _, entry := range missingMethods {
		parts := strings.SplitN(entry, " ", 2)
		if len(parts) != 2 {
			continue
		}
		method := parts[0]
		path := parts[1]
		pathNode := findPathNode(pathsNode, path)
		if pathNode == nil {
			continue
		}
		addMethodNode(pathNode, method)
	}

	out, err := encodeYAML(doc)
	if err != nil {
		fatalf("encode openapi: %v", err)
	}
	if err := os.WriteFile(openAPIPath, out, 0o600); err != nil {
		fatalf("write openapi: %v", err)
	}

	fmt.Printf("Updated %s with %d missing paths and %d missing methods\n", openAPIPath, len(missingPaths), len(missingMethods))
}

func collectRoutes(routesPath string) (routeSet, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, routesPath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	routes := make(routeSet)
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
		return nil, fmt.Errorf("setupRoutes function not found")
	}

	walkStatements(setupRoutesDecl.Body.List, "", routes)
	return routes, nil
}

func walkStatements(stmts []ast.Stmt, prefix string, routes routeSet) {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			walkExpr(s.X, prefix, routes)
		case *ast.BlockStmt:
			walkStatements(s.List, prefix, routes)
		case *ast.IfStmt:
			walkStatements(s.Body.List, prefix, routes)
			if s.Else != nil {
				walkStatements([]ast.Stmt{s.Else}, prefix, routes)
			}
		case *ast.ForStmt:
			walkStatements(s.Body.List, prefix, routes)
		case *ast.RangeStmt:
			walkStatements(s.Body.List, prefix, routes)
		}
	}
}

func walkExpr(expr ast.Expr, prefix string, routes routeSet) {
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
		walkStatements(fn.Body.List, joinPath(prefix, segment), routes)
	default:
		if _, ok := httpMethods[sel.Sel.Name]; !ok {
			return
		}
		if len(call.Args) < 1 {
			return
		}
		segment, ok := stringLiteral(call.Args[0])
		if !ok {
			return
		}
		fullPath := joinPath(prefix, segment)
		method := strings.ToLower(sel.Sel.Name)
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

func joinPath(base, segment string) string {
	base = strings.TrimSpace(base)
	segment = strings.TrimSpace(segment)

	if base == "" {
		return normalizePath(segment)
	}
	if segment == "" {
		return normalizePath(base)
	}
	if base == "/" {
		return normalizePath(segment)
	}
	if segment == "/" {
		return normalizePath(base)
	}

	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(segment, "/") {
		return normalizePath(base + segment)
	}
	return normalizePath(base + "/" + segment)
}

func normalizePath(path string) string {
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

func loadOpenAPINode(openAPIPath string) (*yaml.Node, *yaml.Node, error) {
	data, err := os.ReadFile(filepath.Clean(openAPIPath))
	if err != nil {
		return nil, nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil, errors.New("invalid yaml document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, errors.New("expected root mapping")
	}
	paths := mappingValue(root, "paths")
	if paths == nil {
		return nil, nil, errors.New("openapi file missing paths section")
	}
	if paths.Kind != yaml.MappingNode {
		return nil, nil, errors.New("openapi paths is not a mapping")
	}
	return &doc, paths, nil
}

func findMissing(routes routeSet, pathsNode *yaml.Node) ([]string, []string) {
	var missingPaths []string
	var missingMethods []string

	routePaths := make([]string, 0, len(routes))
	for p := range routes {
		routePaths = append(routePaths, p)
	}
	sort.Strings(routePaths)

	for _, routePath := range routePaths {
		methods := routes[routePath]
		pathNode := findPathNode(pathsNode, routePath)
		if pathNode == nil {
			missingPaths = append(missingPaths, routePath)
			continue
		}

		existingMethods := existingMethods(pathNode)
		sortedMethods := sortedMethodKeys(methods)
		for _, method := range sortedMethods {
			if _, ok := existingMethods[method]; ok {
				continue
			}
			missingMethods = append(missingMethods, method+" "+routePath)
		}
	}
	return missingPaths, missingMethods
}

func printMissing(missingPaths, missingMethods []string) {
	if len(missingPaths) > 0 {
		fmt.Println("Missing OpenAPI paths:")
		for _, p := range missingPaths {
			fmt.Printf("- %s\n", p)
		}
	}
	if len(missingMethods) > 0 {
		fmt.Println("Missing OpenAPI methods:")
		for _, entry := range missingMethods {
			fmt.Printf("- %s\n", entry)
		}
	}
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func findPathNode(pathsNode *yaml.Node, path string) *yaml.Node {
	return mappingValue(pathsNode, path)
}

func existingMethods(pathNode *yaml.Node) map[string]struct{} {
	methods := make(map[string]struct{})
	if pathNode == nil || pathNode.Kind != yaml.MappingNode {
		return methods
	}
	for i := 0; i+1 < len(pathNode.Content); i += 2 {
		key := strings.ToLower(strings.TrimSpace(pathNode.Content[i].Value))
		if key == "" {
			continue
		}
		methods[key] = struct{}{}
	}
	return methods
}

func sortedMethodKeys(methods map[string]struct{}) []string {
	keys := make([]string, 0, len(methods))
	for m := range methods {
		keys = append(keys, m)
	}
	sort.Strings(keys)
	return keys
}

func addPathNode(pathsNode *yaml.Node, path string, methods map[string]struct{}) {
	pathValue := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, method := range sortedMethodKeys(methods) {
		addMethodNode(pathValue, method)
	}
	pathsNode.Content = append(pathsNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: path},
		pathValue,
	)
}

func addMethodNode(pathNode *yaml.Node, method string) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return
	}
	if mappingValue(pathNode, method) != nil {
		return
	}

	pathNode.Content = append(pathNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: method},
		buildStubOperation(method),
	)
}

func buildStubOperation(method string) *yaml.Node {
	return mapNode(
		mapEntry("tags", sequenceNode("Undocumented")),
		mapEntry("summary", scalarNode(fmt.Sprintf("%s endpoint (placeholder)", strings.ToUpper(method)))),
		mapEntry("description", scalarNode("Auto-generated placeholder to keep OpenAPI route coverage in sync with server routes.")),
		mapEntry("x-cerebro-generated", scalarNode("true")),
		mapEntry("responses", mapNode(
			mapEntry("200", mapNode(
				mapEntry("description", scalarNode("OK")),
			)),
		)),
	)
}

type yamlMapEntry struct {
	key   string
	value *yaml.Node
}

func mapEntry(key string, value *yaml.Node) yamlMapEntry {
	return yamlMapEntry{key: key, value: value}
}

func mapNode(entries ...yamlMapEntry) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, entry := range entries {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: entry.key},
			entry.value,
		)
	}
	return node
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func sequenceNode(values ...string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range values {
		node.Content = append(node.Content, scalarNode(v))
	}
	return node
}

func encodeYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

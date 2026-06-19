package urnlinter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

type Finding struct {
	File        string
	Line        int
	Function    string
	DisplayName string
}

var displayNameFields = map[string]bool{
	"workload_name":  true,
	"resource_name":  true,
	"name":           true,
	"label":          true,
	"display_name":   true,
	"email":          true,
	"username":       true,
	"login":          true,
	"target_name":    true,
	"principal":      true,
	"setting_name":   true,
	"service_name":   true,
	"ingress_name":   true,
	"node_name":      true,
	"binding_name":   true,
	"role_name":      true,
	"container_name": true,
	"vault_name":     true,
}

func FindDisplayNameInURN(filePath string, source []byte) ([]Finding, error) {
	if !strings.HasSuffix(filePath, ".go") || strings.HasSuffix(filePath, "_test.go") {
		return nil, nil
	}
	if !strings.Contains(string(source), "URN") && !strings.Contains(string(source), "firstNonEmpty") {
		return nil, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, source, 0)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		if !strings.HasSuffix(fn.Name.Name, "URN") {
			continue
		}
		ast.Inspect(fn, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isCallTo(call, "firstNonEmpty") {
				return true
			}
			for _, arg := range call.Args {
				fieldName := extractMapKey(arg)
				if fieldName == "" {
					continue
				}
				if displayNameFields[fieldName] {
					findings = append(findings, Finding{
						File:        filepath.ToSlash(filePath),
						Line:        fset.Position(call.Pos()).Line,
						Function:    fn.Name.Name,
						DisplayName: fieldName,
					})
				}
			}
			return true
		})
	}
	return findings, nil
}

func isCallTo(call *ast.CallExpr, name string) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == name
}

func extractMapKey(expr ast.Expr) string {
	index, ok := expr.(*ast.IndexExpr)
	if !ok {
		return ""
	}
	lit, ok := index.Index.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	value, err := literalString(lit.Value)
	if err != nil {
		return ""
	}
	return value
}

func literalString(raw string) (string, error) {
	return strings.Trim(raw, `"`), nil
}

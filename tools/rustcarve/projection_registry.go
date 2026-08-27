package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type projectionRegistryEntry struct {
	Kind     string
	Function string
}

func inspectProjectionRegistry(root string) ([]projectionRegistryEntry, map[string]string, []string, error) {
	directory := filepath.Join(root, "internal/sourceprojection")
	entries := make([]projectionRegistryEntry, 0)
	functionFiles := make(map[string]string)
	inputs := make([]string, 0)
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		inputs = append(inputs, relative)
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relative, err)
		}
		if !strings.HasSuffix(path, "_test.go") {
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if ok && function.Recv == nil {
					if existing := functionFiles[function.Name.Name]; existing != "" && existing != relative {
						return fmt.Errorf("duplicate source projection function %s", function.Name.Name)
					}
					functionFiles[function.Name.Name] = relative
				}
			}
		}
		if relative == "internal/sourceprojection/registry_builtins.go" {
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, element := range literal.Elts {
					pair, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := goStringLiteral(pair.Key)
					identifier, valueOK := pair.Value.(*ast.Ident)
					if ok && valueOK {
						entries = append(entries, projectionRegistryEntry{Kind: key, Function: identifier.Name})
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("inspect source projection registry: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind == entries[j].Kind {
			return entries[i].Function < entries[j].Function
		}
		return entries[i].Kind < entries[j].Kind
	})
	sort.Strings(inputs)
	return entries, functionFiles, inputs, nil
}

func goStringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func eventSourceID(kind string) string {
	sourceID, _, ok := strings.Cut(kind, ".")
	if !ok {
		return ""
	}
	return sourceID
}

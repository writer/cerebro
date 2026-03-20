//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"

	appcfg "github.com/writer/cerebro/internal/app"
)

const (
	sourceDir  = "internal/app"
	outputPath = "docs/CONFIG_ENV_VARS.md"
)

var envReaders = map[string]struct{}{
	"getEnv":               {},
	"getEnvInt":            {},
	"getEnvBool":           {},
	"getEnvDuration":       {},
	"bootstrapConfigValue": {},
	"bootstrapConfigInt":   {},
}

type envDoc struct {
	Helpers     map[string]struct{}
	Defaults    map[string]struct{}
	Fields      map[string]struct{}
	Validations map[string]struct{}
}

func main() {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, sourceDir, nil, parser.ParseComments)
	if err != nil {
		fatalf("parse %s: %v", sourceDir, err)
	}
	if len(pkgs) == 0 {
		fatalf("no packages found in %s", sourceDir)
	}

	loadConfig, loadConfigSource := findFuncAcrossPackage(fset, pkgs, "LoadConfig")
	if loadConfig == nil || loadConfig.Body == nil {
		fatalf("LoadConfig not found in %s", sourceDir)
	}

	docs := collectEnvDocs(fset, loadConfig)
	annotateConfigFields(loadConfig, docs)
	annotateValidationRules(docs)

	rendered := renderMarkdown(loadConfigSource, docs)
	if err := os.WriteFile(outputPath, []byte(rendered), 0o644); err != nil {
		fatalf("write %s: %v", outputPath, err)
	}
}

func findFuncAcrossPackage(fset *token.FileSet, pkgs map[string]*ast.Package, name string) (*ast.FuncDecl, string) {
	var (
		match       *ast.FuncDecl
		matchSource string
	)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			fn := findFunc(file, name)
			if fn == nil {
				continue
			}
			pos := fset.Position(fn.Pos())
			match = fn
			matchSource = pos.Filename
			break
		}
		if match != nil {
			break
		}
	}
	return match, matchSource
}

func findFunc(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != name {
			continue
		}
		// Ignore methods (e.g. type receivers) and only match package-level funcs.
		if fn.Recv != nil {
			continue
		}
		return fn
	}
	return nil
}

func collectEnvDocs(fset *token.FileSet, fn *ast.FuncDecl) map[string]*envDoc {
	docs := make(map[string]*envDoc)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		name, ok := callName(call.Fun)
		if !ok {
			return true
		}
		if _, ok := envReaders[name]; !ok {
			return true
		}

		envVar, ok := firstArgString(call)
		if !ok || !looksLikeEnvVar(envVar) {
			return true
		}

		doc := ensureDoc(docs, envVar)
		doc.Helpers[name] = struct{}{}

		defaultValue := ""
		if len(call.Args) >= 2 {
			defaultValue = strings.TrimSpace(exprString(fset, call.Args[1]))
		}
		if defaultValue == "" {
			defaultValue = "-"
		}
		doc.Defaults[defaultValue] = struct{}{}
		return true
	})

	return docs
}

func annotateConfigFields(loadConfig *ast.FuncDecl, docs map[string]*envDoc) {
	ast.Inspect(loadConfig.Body, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		field, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}

		ast.Inspect(kv.Value, func(v ast.Node) bool {
			call, ok := v.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := callName(call.Fun)
			if !ok {
				return true
			}
			if _, ok := envReaders[name]; !ok {
				return true
			}
			envVar, ok := firstArgString(call)
			if !ok || !looksLikeEnvVar(envVar) {
				return true
			}
			doc := ensureDoc(docs, envVar)
			doc.Fields[field.Name] = struct{}{}
			return true
		})

		return true
	})
}

func callName(fun ast.Expr) (string, bool) {
	switch t := fun.(type) {
	case *ast.Ident:
		return t.Name, true
	case *ast.SelectorExpr:
		if t.Sel == nil {
			return "", false
		}
		return t.Sel.Name, true
	default:
		return "", false
	}
}

func firstArgString(call *ast.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func looksLikeEnvVar(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' {
			continue
		}
		return false
	}
	return true
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, expr); err != nil {
		return ""
	}
	return buf.String()
}

func ensureDoc(docs map[string]*envDoc, envVar string) *envDoc {
	if existing, ok := docs[envVar]; ok {
		return existing
	}
	doc := &envDoc{
		Helpers:     make(map[string]struct{}),
		Defaults:    make(map[string]struct{}),
		Fields:      make(map[string]struct{}),
		Validations: make(map[string]struct{}),
	}
	docs[envVar] = doc
	return doc
}

func annotateValidationRules(docs map[string]*envDoc) {
	for _, rule := range appcfg.ConfigValidationRules() {
		for _, envVar := range rule.EnvVars {
			doc := ensureDoc(docs, envVar)
			doc.Validations[rule.Summary] = struct{}{}
		}
	}
}

func renderMarkdown(loadConfigSource string, docs map[string]*envDoc) string {
	var names []string
	for env := range docs {
		names = append(names, env)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# Generated Config Environment Variables\n\n")
	b.WriteString("Generated from `")
	b.WriteString(loadConfigSource)
	b.WriteString("` (`LoadConfig`) via `go run ./scripts/generate_config_docs/main.go`.\n\n")
	fmt.Fprintf(&b, "Total variables: **%d**\n\n", len(names))
	b.WriteString("| Variable | Reader(s) | Default(s) | Config Field(s) | Validation rule(s) |\n")
	b.WriteString("|---|---|---|---|---|\n")

	for _, name := range names {
		doc := docs[name]
		helpers := sortedKeys(doc.Helpers)
		defaults := sortedKeys(doc.Defaults)
		fields := sortedKeys(doc.Fields)
		validations := sortedKeys(doc.Validations)
		if len(fields) == 0 {
			fields = []string{"-"}
		}
		if len(validations) == 0 {
			validations = []string{"-"}
		}
		b.WriteString("| `")
		b.WriteString(name)
		b.WriteString("` | `")
		b.WriteString(strings.Join(helpers, "`, `"))
		b.WriteString("` | `")
		b.WriteString(strings.Join(escapePipes(defaults), "`, `"))
		b.WriteString("` | `")
		b.WriteString(strings.Join(fields, "`, `"))
		b.WriteString("` | `")
		b.WriteString(strings.Join(escapePipes(validations), "`, `"))
		b.WriteString("` |\n")
	}

	return b.String()
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func escapePipes(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ReplaceAll(v, "|", "\\|")
	}
	return out
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

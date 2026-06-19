package urnlinter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestFindDisplayNameInURNFlagsWorkloadName(t *testing.T) {
	source := []byte(`package test

func testURN(tenantID string, attrs map[string]string) string {
	id := firstNonEmpty(attrs["resource_id"], attrs["uid"], attrs["workload_name"])
	return id
}
`)
	findings, err := FindDisplayNameInURN("test.go", source)
	if err != nil {
		t.Fatalf("FindDisplayNameInURN() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].DisplayName != "workload_name" {
		t.Fatalf("expected workload_name, got %q", findings[0].DisplayName)
	}
	if findings[0].Function != "testURN" {
		t.Fatalf("expected testURN, got %q", findings[0].Function)
	}
}

func TestFindDisplayNameInURNFlagsName(t *testing.T) {
	source := []byte(`package test

func kubernetesServiceURN(tenantID string, attrs map[string]string) string {
	name := firstNonEmpty(attrs["service_name"], attrs["resource_name"], attrs["name"])
	return name
}
`)
	findings, err := FindDisplayNameInURN("kubernetes.go", source)
	if err != nil {
		t.Fatalf("FindDisplayNameInURN() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for display-name fields in URN function")
	}
	displayNames := map[string]bool{}
	for _, f := range findings {
		displayNames[f.DisplayName] = true
	}
	for _, want := range []string{"service_name", "resource_name", "name"} {
		if !displayNames[want] {
			t.Fatalf("expected finding for %q, not found in %#v", want, findings)
		}
	}
}

func TestFindDisplayNameInURNSkipsSafeURN(t *testing.T) {
	source := []byte(`package test

func safeURN(tenantID string, attrs map[string]string) string {
	id := firstNonEmpty(attrs["resource_id"], attrs["uid"])
	return id
}
`)
	findings, err := FindDisplayNameInURN("safe.go", source)
	if err != nil {
		t.Fatalf("FindDisplayNameInURN() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe URN, got %d: %#v", len(findings), findings)
	}
}

func TestFindDisplayNameInURNSkipsNonURNFunctions(t *testing.T) {
	source := []byte(`package test

func buildLabel(attrs map[string]string) string {
	return firstNonEmpty(attrs["name"], attrs["display_name"])
}
`)
	findings, err := FindDisplayNameInURN("label.go", source)
	if err != nil {
		t.Fatalf("FindDisplayNameInURN() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-URN function, got %d: %#v", len(findings), findings)
	}
}

func TestFindDisplayNameInURNSkipsTestFiles(t *testing.T) {
	source := []byte(`package test

func testURN(attrs map[string]string) string {
	return firstNonEmpty(attrs["name"])
}
`)
	findings, err := FindDisplayNameInURN("projector_test.go", source)
	if err != nil {
		t.Fatalf("FindDisplayNameInURN() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for test file, got %d", len(findings))
	}
}

func TestLiteralString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`"resource_id"`, "resource_id"},
		{`"uid"`, "uid"},
	}
	for _, tc := range cases {
		got, err := literalString(tc.input)
		if err != nil {
			t.Fatalf("literalString(%q) error = %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("literalString(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestExtractMapKey(t *testing.T) {
	source := []byte(`package test
func f() { _ = attrs["resource_id"] }
`)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", source, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	var found string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(node ast.Node) bool {
			index, ok := node.(*ast.IndexExpr)
			if !ok {
				return true
			}
			found = extractMapKey(index)
			return false
		})
	}
	if found != "resource_id" {
		t.Fatalf("extractMapKey = %q, want resource_id", found)
	}
}

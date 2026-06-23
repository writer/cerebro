package templateengine

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestRenderBasicTemplate(t *testing.T) {
	fs := fstest.MapFS{
		"templates/hello.txt.tmpl": {Data: []byte("Hello, {{ .Name }}!")},
	}
	engine, err := New(fs, "templates", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := engine.RenderString("hello.txt", map[string]string{"Name": "World"})
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	if result != "Hello, World!" {
		t.Errorf("got %q, want %q", result, "Hello, World!")
	}
}

func TestRenderGoTemplate(t *testing.T) {
	fs := fstest.MapFS{
		"templates/main.go.tmpl": {Data: []byte("package main\n\nfunc main() {\n_ = {{ quote .Value }}\n}\n")},
	}
	engine, err := New(fs, "templates", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := engine.RenderGo("main.go", map[string]string{"Value": "hello"})
	if err != nil {
		t.Fatalf("RenderGo: %v", err)
	}
	if !strings.Contains(string(result.Content), "package main") {
		t.Errorf("expected formatted Go source, got:\n%s", string(result.Content))
	}
}

func TestGoSliceFuncMap(t *testing.T) {
	fs := fstest.MapFS{
		"templates/slice.txt.tmpl": {Data: []byte("{{ goSlice .Items }}")},
	}
	engine, err := New(fs, "templates", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := engine.RenderString("slice.txt", map[string][]string{
		"Items": {"a", "b", "c"},
	})
	if err != nil {
		t.Fatalf("RenderString: %v", err)
	}
	expected := `[]string{"a", "b", "c"}`
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

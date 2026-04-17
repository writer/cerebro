package iacrender

import (
	"strings"
	"testing"
)

func TestHCLStringEscapesInterpolationAndDirectives(t *testing.T) {
	got := HCLString(`repo:${danger} %{ if danger }`)
	want := `"repo:$${danger} %%{ if danger }"`
	if got != want {
		t.Fatalf("HCLString() = %q, want %q", got, want)
	}
}

func TestJSONStringReturnsErrorOnUnsupportedValue(t *testing.T) {
	_, err := JSONString(make(chan int))
	if err == nil {
		t.Fatal("expected JSONString to return an error")
	}
	if !strings.Contains(err.Error(), "marshal template JSON value") {
		t.Fatalf("expected wrapped marshal error, got %v", err)
	}
}

func TestRenderTemplateReturnsParseError(t *testing.T) {
	_, err := RenderTemplate("broken", `{{ if .Value }}`, map[string]string{"Value": "x"})
	if err == nil {
		t.Fatal("expected template parse error")
	}
	if !strings.Contains(err.Error(), "parse template broken") {
		t.Fatalf("expected parse context in error, got %v", err)
	}
}

func TestRenderTemplateReturnsExecutionError(t *testing.T) {
	_, err := RenderTemplate("broken", `{{ jsonString .Value }}`, map[string]any{"Value": make(chan int)})
	if err == nil {
		t.Fatal("expected template execution error")
	}
	if !strings.Contains(err.Error(), "execute template broken") {
		t.Fatalf("expected execution context in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("expected marshal cause in error, got %v", err)
	}
}

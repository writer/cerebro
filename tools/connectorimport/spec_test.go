package main

import (
	"slices"
	"strings"
	"testing"
)

func TestSanitizeControlChars(t *testing.T) {
	// U+0085 (NEL) is a multi-byte C1 control character that the YAML parser
	// rejects; tab/newline/CR and ordinary text must be preserved.
	input := []byte("openapi: 3.0.0\ninfo:\n\ttitle: a\u0085b\n")
	got := string(sanitizeControlChars(input))
	if strings.ContainsRune(got, '\u0085') {
		t.Fatalf("sanitizeControlChars left a C1 control char: %q", got)
	}
	if !strings.Contains(got, "openapi: 3.0.0") || !strings.Contains(got, "\t") || !strings.Contains(got, "\n") {
		t.Fatalf("sanitizeControlChars dropped allowed content: %q", got)
	}
	if !strings.Contains(got, "ab") {
		t.Fatalf("expected control char removed between a and b, got %q", got)
	}
}

func TestIsSwaggerV2(t *testing.T) {
	if !isSwaggerV2([]byte(`{"swagger":"2.0"}`)) {
		t.Error("expected swagger 2.0 JSON to be detected")
	}
	if isSwaggerV2([]byte("openapi: 3.0.0\n")) {
		t.Error("expected OpenAPI 3 not to be detected as swagger 2.0")
	}
}

func TestTargetWithProviderAPIReferencesDoesNotDuplicateManifestReferences(t *testing.T) {
	entry := manifestTarget{
		SourceID:              "example",
		SpecURL:               "https://provider.example/openapi.json",
		ProviderAPIReferences: []string{"https://provider.example/openapi.json"},
	}

	got := targetWithProviderAPIReferences(apisGuruRegistry{}, entry).ProviderAPIReferences
	want := []string{"https://provider.example/openapi.json"}
	if !slices.Equal(got, want) {
		t.Fatalf("ProviderAPIReferences = %v, want %v", got, want)
	}
}

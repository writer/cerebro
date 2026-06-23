package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectorimport"
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

func TestWriteDefinitionJSONSanitizesSourceID(t *testing.T) {
	dir := t.TempDir()
	outcomes := []connectorimport.Outcome{{
		SourceID: "../../evil/source",
		Verdict:  connectorimport.VerdictSupported,
		Definition: connectordefinitions.Definition{
			ID:       "test",
			SourceID: "evil/source",
		},
	}}
	written, err := writeDefinitionJSON(dir, outcomes)
	if err != nil {
		t.Fatalf("writeDefinitionJSON() error = %v", err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1", written)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil_source.json")); err != nil {
		t.Fatalf("expected sanitized definition file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil", "source.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected escaped definition file stat error = %v", err)
	}
}

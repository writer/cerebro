package jsonl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSinkWriteAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events", "out.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink() error = %v", err)
	}

	if err := sink.Write(map[string]any{"id": 1}); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := sink.Write(map[string]any{"id": 2}); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL records, got %d from %q", len(lines), string(content))
	}
	if !strings.Contains(lines[0], `"id":1`) || !strings.Contains(lines[1], `"id":2`) {
		t.Fatalf("unexpected JSONL contents: %q", string(content))
	}
}

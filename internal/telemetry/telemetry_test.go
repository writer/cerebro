package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestEventEmitsParseableJSONLine(t *testing.T) {
	output := captureStdout(t, func() {
		Event(context.Background(), "test.event", Attrs(Field{Key: "value", Value: 42}))
	})
	line := strings.TrimSpace(output)
	if !strings.HasPrefix(line, "{") {
		t.Fatalf("telemetry line = %q, want JSON object without log prefix", line)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("telemetry line is not JSON: %v", err)
	}
	if got := payload["kind"]; got != "event" {
		t.Fatalf("kind = %v, want event", got)
	}
	if got := payload["name"]; got != "test.event" {
		t.Fatalf("name = %v, want test.event", got)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(output)
}

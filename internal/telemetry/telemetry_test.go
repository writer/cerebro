package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestEventEmitsParseableJSONLineOnStderr(t *testing.T) {
	stdout, stderr := captureOutput(t, func() {
		Event(context.Background(), "test.event", Attrs(Field{Key: "value", Value: 42}))
	})
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	line := strings.TrimSpace(stderr)
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

func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	fn()
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(stdout), string(stderr)
}

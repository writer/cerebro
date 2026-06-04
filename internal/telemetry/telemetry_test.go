package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

func TestTelemetryFieldsDoNotUseRawErrorKey(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	pattern := regexp.MustCompile(`telemetry\.Field\s*\{\s*Key:\s*"` + `error"`)
	var matches []string
	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".idea", ".vscode", "bin", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if pattern.Match(contents) {
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				rel = path
			}
			matches = append(matches, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("telemetry raw error field is forbidden; use bounded error_kind instead: %s", strings.Join(matches, ", "))
	}
}

func TestParseTraceParentValidatesTraceFlags(t *testing.T) {
	traceID, spanID, ok := ParseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok {
		t.Fatal("valid traceparent was rejected")
	}
	if traceID != "4bf92f3577b34da6a3ce929d0e0e4736" || spanID != "00f067aa0ba902b7" {
		t.Fatalf("traceparent parsed as traceID=%q spanID=%q", traceID, spanID)
	}
	for _, header := range []string{
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-001",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz",
	} {
		if _, _, ok := ParseTraceParent(header); ok {
			t.Fatalf("malformed traceparent flags accepted: %q", header)
		}
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

package archtests

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHookIntegrityManifestMatchesTrackedHooks(t *testing.T) {
	root := repoRoot(t)
	manifestPath := filepath.Join(root, "tools", "hooks", "integrity.sha256")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	entries := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatalf("invalid manifest line: %q", line)
		}
		entries[parts[1]] = parts[0]
	}

	for _, path := range []string{".githooks/pre-commit", ".githooks/pre-push"} {
		want, ok := entries[path]
		if !ok {
			t.Fatalf("manifest missing %s", path)
		}
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if got != want {
			t.Fatalf("hook hash mismatch for %s: got %s want %s", path, got, want)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

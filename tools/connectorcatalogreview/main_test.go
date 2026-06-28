package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileDoesNotChmodExistingParentDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	path := filepath.Join(dir, "review.json")
	if err := writeFile(path, []byte("{}\n")); err != nil {
		t.Fatalf("writeFile() error = %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent dir mode = %#o, want 0755", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("output file mode = %#o, want 0600", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackDirectoriesReturnsOnlyRegularManifestDirectories(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid")
	if err := os.MkdirAll(valid, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(valid, "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	directories, err := packDirectories(root)
	if err != nil {
		t.Fatalf("packDirectories() error = %v", err)
	}
	if len(directories) != 1 || directories[0] != valid {
		t.Fatalf("packDirectories() = %v", directories)
	}
}

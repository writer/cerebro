package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectSymlinkRejectsCatalogPath(t *testing.T) {
	root := t.TempDir()
	linkPath := filepath.Join(root, "public_detection_catalog.json")
	if err := os.Symlink(filepath.Join(root, "missing.json"), linkPath); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	if err := rejectSymlink(linkPath); err == nil {
		t.Fatal("rejectSymlink() error = nil, want symlink rejection")
	}
}

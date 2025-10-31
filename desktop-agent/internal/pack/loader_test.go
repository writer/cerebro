package pack

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDirectoryParsesYAML(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`name: sample
version: "1.0"
tasks:
  - name: gather
    collector: snapshot.basic
    interval: 1m
    tags:
      env: test
`)

	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pack: %v", err)
	}

	packs, err := Loader{}.LoadDirectory(dir)
	if err != nil {
		t.Fatalf("LoadDirectory returned error: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packs))
	}
	pack := packs[0]
	if pack.Name != "sample" {
		t.Fatalf("expected pack name 'sample', got %q", pack.Name)
	}
	if len(pack.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(pack.Tasks))
	}
	if pack.Tasks[0].Interval.Duration != time.Minute {
		t.Fatalf("expected interval of 1m, got %s", pack.Tasks[0].Interval.Duration)
	}
	if pack.Tasks[0].Tags["env"] != "test" {
		t.Fatalf("expected tag env=test, got %q", pack.Tasks[0].Tags["env"])
	}
}

func TestLoadDirectoryMissingReturnsNil(t *testing.T) {
	packs, err := Loader{}.LoadDirectory(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("expected no error for missing directory, got %v", err)
	}
	if packs != nil {
		t.Fatalf("expected nil packs for missing directory")
	}
}

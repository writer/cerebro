package stampfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFilesIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	file1 := filepath.Join(dir, "a.txt")
	file2 := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(file1, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}

	hash1, err := HashFiles([]string{file1, file2})
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := HashFiles([]string{file2, file1})
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Errorf("hashes differ for reversed order: %s vs %s", hash1, hash2)
	}
}

func TestHashDirWithExtensions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("key: value"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	hashYAML, err := HashDir(dir, []string{".yaml"})
	if err != nil {
		t.Fatal(err)
	}
	hashAll, err := HashDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hashYAML == hashAll {
		t.Error("expected different hashes when filtering by extension")
	}
}

func TestHashChangesWhenContentChanges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "data.yaml")
	if err := os.WriteFile(file, []byte("version: 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash1, err := HashFiles([]string{file})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(file, []byte("version: 2"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash2, err := HashFiles([]string{file})
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 {
		t.Error("expected different hashes after content change")
	}
}

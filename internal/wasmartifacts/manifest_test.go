package wasmartifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildIsDeterministicAndContainsArtifactEvidence(t *testing.T) {
	root := t.TempDir()
	specs := testSpecs(t, root)
	manifest, err := build(root, specs)
	if err != nil {
		t.Fatal(err)
	}
	body, err := Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"sha256": "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"`) {
		t.Fatalf("manifest missing deterministic digest: %s", text)
	}
	if !strings.Contains(text, `"size_bytes": 3`) || !strings.Contains(text, `"abi_version": 7`) {
		t.Fatalf("manifest missing size or ABI evidence: %s", text)
	}
	if strings.Contains(text, root) || strings.Contains(text, "timestamp") {
		t.Fatalf("manifest contains environment-dependent data: %s", text)
	}
}

func TestBuildRejectsArtifactOverBudgetWithActionableError(t *testing.T) {
	root := t.TempDir()
	specs := testSpecs(t, root)
	specs[0].MaxSizeBytes = 2
	_, err := build(root, specs)
	if err == nil {
		t.Fatal("expected size budget failure")
	}
	for _, fragment := range []string{"test-module", "3 bytes", "2-byte budget", "by 1 byte", "reviewed budget change"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q missing %q", err, fragment)
		}
	}
}

func TestCompareReportsDigestAndBudgetDrift(t *testing.T) {
	root := t.TempDir()
	specs := testSpecs(t, root)
	expected, err := build(root, specs)
	if err != nil {
		t.Fatal(err)
	}
	actual := expected
	actual.Modules = append([]ModuleArtifact(nil), expected.Modules...)
	actual.Modules[0].SHA256 = strings.Repeat("0", 64)
	if err := compare(expected, actual); err == nil || !strings.Contains(err.Error(), "manifest SHA-256") {
		t.Fatalf("expected digest drift error, got %v", err)
	}
	actual.Modules[0] = expected.Modules[0]
	actual.Modules[0].MaxSizeBytes++
	if err := compare(expected, actual); err == nil || !strings.Contains(err.Error(), "size budget") {
		t.Fatalf("expected budget drift error, got %v", err)
	}
}

func testSpecs(t *testing.T, root string) []ModuleSpec {
	t.Helper()
	path := filepath.Join(root, "artifacts", "test.wasm")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	return []ModuleSpec{{
		Name:         "test-module",
		ArtifactPath: "artifacts/test.wasm",
		SourcePath:   "src/lib.rs",
		ABIVersion:   7,
		MaxSizeBytes: 10,
	}}
}

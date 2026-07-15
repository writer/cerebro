package wasmartifacts

import (
	"errors"
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
	if !errors.Is(err, ErrArtifactOverBudget) {
		t.Fatalf("build() error = %v, want ErrArtifactOverBudget", err)
	}
	var budgetError *ArtifactBudgetError
	if !errors.As(err, &budgetError) {
		t.Fatalf("build() error = %v, want ArtifactBudgetError", err)
	}
	if budgetError.Module != "test-module" || budgetError.SizeBytes != 3 || budgetError.BudgetBytes != 2 {
		t.Fatalf("ArtifactBudgetError = %+v, want module=test-module size=3 budget=2", budgetError)
	}
}

func TestBuildRejectsSymlinkedArtifact(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.wasm")
	if err := os.WriteFile(target, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "artifact.wasm")
	if err := os.Symlink(target, artifact); err != nil {
		t.Fatal(err)
	}
	_, err := build(root, []ModuleSpec{{Name: "test", ArtifactPath: "artifact.wasm", MaxSizeBytes: 10}})
	if !errors.Is(err, ErrUnsafeArtifactPath) {
		t.Fatalf("build() error = %v, want ErrUnsafeArtifactPath", err)
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
	if err := compare(expected, actual); !errors.Is(err, ErrManifestDigestDrift) {
		t.Fatalf("compare() error = %v, want ErrManifestDigestDrift", err)
	}
	actual.Modules[0] = expected.Modules[0]
	actual.Modules[0].MaxSizeBytes++
	if err := compare(expected, actual); !errors.Is(err, ErrManifestBudgetDrift) {
		t.Fatalf("compare() error = %v, want ErrManifestBudgetDrift", err)
	}
}

func testSpecs(t *testing.T, root string) []ModuleSpec {
	t.Helper()
	path := filepath.Join(root, "artifacts", "test.wasm")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
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

package devex

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuiltInCodegenCatalogIsValid(t *testing.T) {
	catalog, err := LoadBuiltInCodegenCatalog()
	if err != nil {
		t.Fatalf("load built-in codegen catalog: %v", err)
	}
	if err := ValidateCodegenCatalogReferences(catalog, filepath.Join(repoRoot(t), "Makefile"), filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml")); err != nil {
		t.Fatalf("validate catalog references: %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func TestValidateCodegenCatalogRejectsGeneratedPRCheckWithoutMakeTarget(t *testing.T) {
	catalog := CodegenCatalog{
		APIVersion: "devex.cerebro/v1alpha1",
		Kind:       "CodegenCatalog",
		Families: []CodegenFamily{
			{
				ID:           "broken-family",
				Title:        "Broken Family",
				Summary:      "Broken summary",
				ChangeReason: "broken",
				Triggers:     []string{"broken/**"},
				Checks: []CodegenStep{
					{
						Key:                      "broken-check",
						Summary:                  "Broken check",
						Command:                  []string{"make", "broken-check"},
						IncludeInPRGeneratedStep: true,
					},
				},
			},
		},
	}

	err := ValidateCodegenCatalog(catalog)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "include_in_pr_generated_step requires make_target") {
		t.Fatalf("expected make_target validation error, got %v", err)
	}
}

package codegencatalog

import (
	"strings"
	"testing"
)

func TestCatalogValidateAndSelect(t *testing.T) {
	catalog := Catalog{
		APIVersion: APIVersion,
		Kind:       Kind,
		Families: []Family{{
			ID:           "source-runtime",
			Title:        "Source Runtime",
			Summary:      "Generates source runtimes.",
			ChangeReason: "Source definitions changed",
			Triggers:     []string{"internal/sourcegen/**", "Makefile"},
			Generator:    Command{MakeTarget: "sourcegen-test", Command: []string{"make", "sourcegen-test"}},
			Checks:       []Check{{Key: "sourcegen-check", MakeTarget: "sourcegen-check", Command: []string{"make", "sourcegen-check"}}},
			Outputs:      []string{"sources/<source-id>"},
			CIJobs:       []string{"codegen"},
		}},
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := catalog.Select([]string{"internal/sourcegen/generator.go"}); len(got) != 1 || got[0].ID != "source-runtime" {
		t.Fatalf("Select() = %#v", got)
	}
	if got := catalog.Select([]string{"README.md"}); len(got) != 0 {
		t.Fatalf("Select(unrelated) = %#v", got)
	}
	if markdown := string(catalog.Markdown()); !strings.Contains(markdown, "Families: **1**") || !strings.Contains(markdown, "`source-runtime`") {
		t.Fatalf("Markdown() missing catalog data:\n%s", markdown)
	}
}

func TestCatalogValidateRejectsDuplicateFamilies(t *testing.T) {
	family := Family{
		ID:        "proto",
		Title:     "Proto",
		Triggers:  []string{"proto/**"},
		Generator: Command{MakeTarget: "proto-generate", Command: []string{"make", "proto-generate"}},
		Checks:    []Check{{Key: "proto-check", MakeTarget: "proto-check", Command: []string{"make", "proto-check"}}},
		Outputs:   []string{"gen"},
	}
	catalog := Catalog{APIVersion: APIVersion, Kind: Kind, Families: []Family{family, family}}
	if err := catalog.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate family id") {
		t.Fatalf("Validate() error = %v", err)
	}
}

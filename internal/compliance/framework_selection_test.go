package compliance

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolveEnabledFrameworksCanonicalizesSelection(t *testing.T) {
	catalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("LoadBuiltinControlCatalog() error = %v", err)
	}
	got, err := ResolveEnabledFrameworks(catalog, []string{" cis aws foundations benchmark v2.0 ", "SOC 2", "soc 2", "dora", ""})
	if err != nil {
		t.Fatalf("ResolveEnabledFrameworks() error = %v", err)
	}
	// Catalog order puts SOC 2 first and DORA after the CIS benchmarks.
	if len(got) != 3 || got[0] != "SOC 2" || got[1] != "CIS AWS Foundations Benchmark v2.0" {
		t.Fatalf("ResolveEnabledFrameworks() = %#v, want SOC 2, CIS AWS, then DORA by canonical name", got)
	}
	if got[2] == "dora" || got[2] == "" {
		t.Fatalf("DORA resolved to %q, want its catalog name", got[2])
	}
}

func TestResolveEnabledFrameworksRejectsUnknownAndUpcoming(t *testing.T) {
	catalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("LoadBuiltinControlCatalog() error = %v", err)
	}
	for _, value := range []string{"SOC 3", "nist-ai-rmf-1.0"} {
		if _, err := ResolveEnabledFrameworks(catalog, []string{value}); !errors.Is(err, ErrUnknownFramework) {
			t.Fatalf("ResolveEnabledFrameworks(%q) error = %v, want ErrUnknownFramework", value, err)
		}
	}
}

func TestDefaultEnabledFrameworksAreActiveCatalogFrameworks(t *testing.T) {
	catalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		t.Fatalf("LoadBuiltinControlCatalog() error = %v", err)
	}
	got, err := ResolveEnabledFrameworks(catalog, DefaultEnabledFrameworkNames)
	if err != nil {
		t.Fatalf("default frameworks do not resolve: %v", err)
	}
	if len(got) != len(DefaultEnabledFrameworkNames) {
		t.Fatalf("defaults resolved to %#v, want all of %#v", got, DefaultEnabledFrameworkNames)
	}
	if !reflect.DeepEqual(got, []string{"SOC 2", "ISO 27001:2022", "CIS AWS Foundations Benchmark v2.0"}) {
		t.Fatalf("defaults resolved to %#v", got)
	}
}

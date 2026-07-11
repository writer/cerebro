package sourcecoverage

import (
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCertificationTiersAreBoundedAndOrdered(t *testing.T) {
	if tier, ok := ParseCertificationTier(""); !ok || tier != CertificationUnknown {
		t.Fatalf("ParseCertificationTier(empty) = %q, %t", tier, ok)
	}
	if tier, ok := ParseCertificationTier("future_tier"); ok || tier != CertificationUnknown {
		t.Fatalf("ParseCertificationTier(future) = %q, %t", tier, ok)
	}
	if !CertificationMeetsMinimum(CertificationLiveValidated, CertificationFixtureValidated) {
		t.Fatal("live validation did not satisfy fixture minimum")
	}
	if CertificationMeetsMinimum(CertificationCatalogDeclared, CertificationFixtureValidated) {
		t.Fatal("catalog declaration satisfied fixture minimum")
	}
	if CertificationMeetsMinimum(CertificationUnknown, CertificationCatalogDeclared) {
		t.Fatal("unknown certification satisfied known minimum")
	}
	if CertificationMeetsMinimum(CertificationTier("future_tier"), CertificationCatalogDeclared) {
		t.Fatal("unrecognized certification satisfied known minimum")
	}
}

func TestRuntimeCertificationFailsClosedWithoutCatalogInference(t *testing.T) {
	if got := runtimeCertificationTier(""); got != CertificationUnknown {
		t.Fatalf("runtimeCertificationTier(empty) = %q, want unknown", got)
	}
	if got := runtimeCertificationTier("fixture_validated"); got != CertificationFixtureValidated {
		t.Fatalf("runtimeCertificationTier(fixture) = %q", got)
	}
	if got := runtimeCertificationTier("tenant_specific_future_tier"); got != CertificationUnknown {
		t.Fatalf("runtimeCertificationTier(invalid) = %q, want unknown", got)
	}
}

func TestEvaluateCarriesOnlyExplicitRuntimeCertification(t *testing.T) {
	contracts := []sourcecdk.CoverageContract{{
		SourceID: "example", Dimensions: []sourcecdk.CoverageDimension{{
			ID: "users", Type: "entity_family", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported,
		}},
	}}
	records := Evaluate(contracts, []RuntimeObservation{{
		RuntimeID: "runtime-a", SourceID: "example", Family: "user", Status: "healthy", CertificationTier: CertificationFixtureValidated,
	}}, Options{})
	if len(records) != 1 || records[0].CertificationTier != CertificationFixtureValidated {
		t.Fatalf("Evaluate(explicit certification) = %#v", records)
	}
	records = Evaluate(contracts, []RuntimeObservation{{RuntimeID: "runtime-a", SourceID: "example", Family: "user", Status: "healthy"}}, Options{})
	if len(records) != 1 || records[0].CertificationTier != CertificationUnknown {
		t.Fatalf("Evaluate(missing certification) = %#v, want unknown", records)
	}
}

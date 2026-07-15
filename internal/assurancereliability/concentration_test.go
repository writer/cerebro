package assurancereliability

import (
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
)

func TestAnalyzeConcentrationSeparatesNominalAndIndependentCoverage(t *testing.T) {
	units := concentrationFixture()
	report, err := AnalyzeConcentration("tenant-a", units)
	if err != nil {
		t.Fatalf("AnalyzeConcentration() error = %v", err)
	}
	coverage := report.Coverage
	if coverage.ApplicableUnits != 4 || coverage.NominalQualifiedUnits != 3 || coverage.EffectiveIndependentUnits != 1 {
		t.Fatalf("coverage units = %#v", coverage)
	}
	if coverage.NominalCoverageBPS != 7500 || coverage.EffectiveCoverageBPS != 2500 || coverage.LargestCorrelatedLossBPS != 6666 {
		t.Fatalf("coverage basis points = %#v", coverage)
	}
	if len(report.CorrelatedExposures) != 2 || report.CorrelatedExposures[0].FailureDomain.ID != "provider-a" || report.CorrelatedExposures[0].QualifiedUnitsAtRisk != 2 {
		t.Fatalf("correlated exposures = %#v", report.CorrelatedExposures)
	}
	provider := findConcentration(report.Concentrations, ConcentrationProvider, "provider-a")
	if provider.QualifiedUnits != 2 || provider.DependencyShareBPS != 6666 {
		t.Fatalf("provider concentration = %#v", provider)
	}
	owner := findConcentration(report.Concentrations, ConcentrationOwner, "owner-a")
	if owner.QualifiedUnits != 2 {
		t.Fatalf("owner concentration = %#v", owner)
	}
	if report.ReportDigest == "" {
		t.Fatal("report digest is empty")
	}
}

func TestAnalyzeConcentrationIsDeterministicAcrossInputOrder(t *testing.T) {
	units := concentrationFixture()
	first, err := AnalyzeConcentration("tenant-a", units)
	if err != nil {
		t.Fatal(err)
	}
	units[0], units[3] = units[3], units[0]
	units[1].SourceIDs = []string{"source-b", "source-b"}
	units[1].FailureDomains = append(units[1].FailureDomains, units[1].FailureDomains[0])
	second, err := AnalyzeConcentration("tenant-a", units)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReportDigest != second.ReportDigest {
		t.Fatalf("report digest changed with input order: %s != %s", first.ReportDigest, second.ReportDigest)
	}
}

func TestAnalyzeConcentrationFailsClosedOnTenantOrDependencyGap(t *testing.T) {
	units := concentrationFixture()
	units[0].TenantID = "tenant-b"
	if _, err := AnalyzeConcentration("tenant-a", units); !errors.Is(err, ErrInvalidReliabilityInput) {
		t.Fatalf("tenant mismatch error = %v", err)
	}
	units = concentrationFixture()
	units[0].FailureDomains = nil
	if _, err := AnalyzeConcentration("tenant-a", units); !errors.Is(err, ErrInvalidReliabilityInput) {
		t.Fatalf("dependency gap error = %v", err)
	}
}

func concentrationFixture() []AssuranceUnit {
	qualified := complianceassessment.QualifiedDecision{
		Version: "qualified-decision/v1", Qualified: true, ProofDigest: "sha256:proof", DecisionDigest: "sha256:decision",
	}
	return []AssuranceUnit{
		{
			TenantID: "tenant-a", ObligationID: "obligation-a", Decision: qualified, CoverageUnits: 1,
			SourceIDs: []string{"source-a"}, ProviderIDs: []string{"provider-a"},
			Control: compliance.ControlRef{FrameworkName: "Framework", ControlID: "C-1"}, OwnerID: "owner-a",
			FailureDomains: []FailureDomainRef{{Kind: "provider", ID: "provider-a"}},
		},
		{
			TenantID: "tenant-a", ObligationID: "obligation-b", Decision: qualified, CoverageUnits: 1,
			SourceIDs: []string{"source-b"}, ProviderIDs: []string{"provider-a"},
			Control: compliance.ControlRef{FrameworkName: "Framework", ControlID: "C-2"}, OwnerID: "owner-a",
			FailureDomains: []FailureDomainRef{{Kind: "provider", ID: "provider-a"}},
		},
		{
			TenantID: "tenant-a", ObligationID: "obligation-c", Decision: qualified, CoverageUnits: 1,
			SourceIDs: []string{"source-c"}, ProviderIDs: []string{"provider-b"},
			Control: compliance.ControlRef{FrameworkName: "Framework", ControlID: "C-3"}, OwnerID: "owner-b",
			FailureDomains: []FailureDomainRef{{Kind: "provider", ID: "provider-b"}},
		},
		{
			TenantID: "tenant-a", ObligationID: "obligation-d", CoverageUnits: 1,
			Control: compliance.ControlRef{FrameworkName: "Framework", ControlID: "C-4"}, OwnerID: "owner-c",
		},
	}
}

func findConcentration(values []ConcentrationEntry, dimension ConcentrationDimension, key string) ConcentrationEntry {
	for _, value := range values {
		if value.Dimension == dimension && value.Key == key {
			return value
		}
	}
	return ConcentrationEntry{}
}

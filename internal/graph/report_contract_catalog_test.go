package graph

import (
	"testing"
	"time"
)

func TestCompareReportContractCatalogs_NoDrift(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	baseline := BuildReportContractCatalog(time.Time{})
	current := BuildReportContractCatalog(time.Time{})
	report := CompareReportContractCatalogs(baseline, current, now)
	if !report.Compatible {
		t.Fatalf("expected compatible catalog report, got %+v", report)
	}
	if len(report.BreakingChanges) != 0 || len(report.VersioningViolations) != 0 {
		t.Fatalf("expected no drift, got %+v", report)
	}
}

func TestCompareReportContractCatalogs_EnvelopeChangeWithoutVersionBumpViolates(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 5, 0, 0, time.UTC)
	baseline := BuildReportContractCatalog(time.Time{})
	current := BuildReportContractCatalog(time.Time{})
	for i := range current.SectionEnvelopes {
		if current.SectionEnvelopes[i].ID == "summary" {
			current.SectionEnvelopes[i].Description = "changed without version bump"
			break
		}
	}

	report := CompareReportContractCatalogs(baseline, current, now)
	if report.Compatible {
		t.Fatalf("expected incompatible report for versioning violation, got %+v", report)
	}
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected one breaking change, got %+v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 1 {
		t.Fatalf("expected one versioning violation, got %+v", report.VersioningViolations)
	}
	if report.VersioningViolations[0].ContractType != "section_envelope" || report.VersioningViolations[0].ContractID != "summary" {
		t.Fatalf("unexpected violation payload: %+v", report.VersioningViolations[0])
	}
}

func TestCompareReportContractCatalogs_BenchmarkChangeWithVersionBumpAvoidsViolation(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 10, 0, 0, time.UTC)
	baseline := BuildReportContractCatalog(time.Time{})
	current := BuildReportContractCatalog(time.Time{})
	for i := range current.BenchmarkPacks {
		if current.BenchmarkPacks[i].ID == "graph-quality.default" {
			current.BenchmarkPacks[i].Version = "2.0.0"
			current.BenchmarkPacks[i].MeasureBindings[0].Description = "tightened quality semantics"
			break
		}
	}

	report := CompareReportContractCatalogs(baseline, current, now)
	if !report.Compatible {
		t.Fatalf("expected compatible report when version is bumped, got %+v", report)
	}
	if len(report.BreakingChanges) != 1 {
		t.Fatalf("expected one breaking change, got %+v", report.BreakingChanges)
	}
	if len(report.VersioningViolations) != 0 {
		t.Fatalf("expected no versioning violations, got %+v", report.VersioningViolations)
	}
	if report.BreakingChanges[0].ContractType != "benchmark_pack" || report.BreakingChanges[0].ContractID != "graph-quality.default" {
		t.Fatalf("unexpected breaking-change payload: %+v", report.BreakingChanges[0])
	}
}

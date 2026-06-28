package findings

import (
	"testing"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCoverageControlDomainRefsLoad(t *testing.T) {
	if coverageControlDomainRefSet.Version == "" {
		t.Fatal("coverage control domain refs version is empty")
	}
	refs := controlRefsForControlDomains([]string{"identity_access"})
	if len(refs) == 0 {
		t.Fatal("identity_access produced no control refs")
	}
	found := false
	for _, ref := range refs {
		if ref.FrameworkName == "SOC 2" && ref.ControlID == "CC6.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity_access refs missing SOC 2 CC6.1: %+v", refs)
	}
}

func TestEffectiveCoverageControlRefsUnionsDerived(t *testing.T) {
	dimension := sourcecdk.CoverageDimension{
		ID:             "datasets",
		ControlDomains: []string{"data_protection"},
		ControlRefs: []sourcecdk.CoverageControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC1.1"},
		},
	}
	refs := effectiveCoverageControlRefs(dimension)
	var hasDeclared, hasDerived bool
	for _, ref := range refs {
		if ref.FrameworkName == "SOC 2" && ref.ControlID == "CC1.1" {
			hasDeclared = true
		}
		if ref.FrameworkName == "NIST 800-53 r5" && ref.ControlID == "SC-28" {
			hasDerived = true
		}
	}
	if !hasDeclared || !hasDerived {
		t.Fatalf("effectiveCoverageControlRefs union incomplete: declared=%v derived=%v refs=%+v", hasDeclared, hasDerived, refs)
	}
}

func TestSourceCoverageDerivedRefsAreSourceBounded(t *testing.T) {
	detection := PublicDetection{
		ID:       "gcp-storage-bucket-encryption-disabled",
		SourceID: "gcp",
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "NIST 800-53 r5", ControlID: "SC-28"},
		},
	}
	loggingDimension := func(id string) sourcecdk.CoverageDimension {
		return sourcecdk.CoverageDimension{
			ID:             id,
			Type:           "entity_family",
			Title:          id,
			Support:        sourcecdk.CoverageSupportSupported,
			HighValue:      true,
			ControlDomains: []string{"data_protection"},
		}
	}
	contracts := []sourcecdk.CoverageContract{
		{SourceID: "gcp", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("buckets")}},
		{SourceID: "github", Dimensions: []sourcecdk.CoverageDimension{loggingDimension("repositories")}},
	}

	refs := sourceCoverageRefsForDetection(detection, contracts)
	if len(refs) == 0 {
		t.Fatal("expected derived source coverage for the detection's own source")
	}
	for _, ref := range refs {
		if ref.SourceID != "gcp" {
			t.Fatalf("derived coverage crossed sources: got %q, want only gcp", ref.SourceID)
		}
	}
}

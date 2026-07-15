package complianceassessment

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

func TestCanonicalObjectiveSourceRequirementNormalizesSemanticContent(t *testing.T) {
	requirement, err := CanonicalObjectiveSourceRequirement(ObjectiveSourceRequirement{
		ObjectiveID: " objective-a ",
		Sources: []SourceCheckRequirement{
			{SourceID: " source-b ", DimensionID: "dimension-b", MinimumCertification: sourcecoverage.CertificationFixtureValidated, RequiredFields: []string{" field-b ", "field-a", "field-a"}},
			{SourceID: "source-a", DimensionID: " dimension-a ", MinimumCertification: sourcecoverage.CertificationLiveValidated},
		},
	})
	if err != nil {
		t.Fatalf("CanonicalObjectiveSourceRequirement() error = %v", err)
	}
	if requirement.ObjectiveID != "objective-a" || requirement.Sources[0].SourceID != "source-a" || requirement.Sources[1].SourceID != "source-b" {
		t.Fatalf("canonical requirement = %+v", requirement)
	}
	if !reflect.DeepEqual(requirement.Sources[1].RequiredFields, []string{"field-a", "field-b"}) {
		t.Fatalf("canonical required fields = %v", requirement.Sources[1].RequiredFields)
	}
}

func TestCanonicalObjectiveSourceRequirementRejectsDuplicateDimension(t *testing.T) {
	_, err := CanonicalObjectiveSourceRequirement(ObjectiveSourceRequirement{
		ObjectiveID: "objective-a",
		Sources: []SourceCheckRequirement{
			{SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated},
			{SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationLiveValidated},
		},
	})
	if err == nil {
		t.Fatal("CanonicalObjectiveSourceRequirement(duplicate) error = nil")
	}
}

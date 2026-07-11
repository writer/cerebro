package compliance

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeControlMappingIsDeterministicWithoutMutatingCaller(t *testing.T) {
	digest := ContentDigest("sha256:" + strings.Repeat("b", 64))
	mapping := ControlMapping{
		ID: " mapping ", RevisionID: " revision ", Granularity: " statement ",
		Source:       RevisionRef{ID: "source", RevisionID: "source-r1", Version: 1, ContentDigest: digest, LastModified: time.Unix(1, 0)},
		Target:       RevisionRef{ID: "target", RevisionID: "target-r1", Version: 1, ContentDigest: digest, LastModified: time.Unix(1, 0)},
		Relationship: MappingOverlap, Method: " manual ", Rationale: " scoped overlap ", CoverageBasisPoints: 7500,
		Gaps:          []string{" gap-b ", "gap-a", "gap-a"},
		Provenance:    []SubjectRef{{Type: " source ", ID: "b"}, {Type: "source", ID: "a"}, {Type: "source", ID: "a"}},
		DecisionState: MappingApproved, AuthorID: " author ", ReviewerID: " reviewer ",
	}
	normalized := NormalizeControlMapping(mapping)
	if got := strings.Join(normalized.Gaps, ","); got != "gap-a,gap-b" {
		t.Fatalf("normalized gaps = %q", got)
	}
	if len(normalized.Provenance) != 2 || normalized.Provenance[0].ID != "a" || normalized.Provenance[1].ID != "b" {
		t.Fatalf("normalized provenance = %#v", normalized.Provenance)
	}
	if mapping.Provenance[0].Type != " source " {
		t.Fatal("NormalizeControlMapping mutated caller provenance")
	}
	if normalized.Source.LastModified.Nanosecond()%int(time.Millisecond) != 0 {
		t.Fatalf("source revision time was not normalized: %s", normalized.Source.LastModified)
	}
	if err := normalized.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestControlMappingRelationshipCoverageInvariants(t *testing.T) {
	base := validControlMapping()
	base.Relationship = MappingNone
	base.CoverageBasisPoints = 1
	if err := base.Validate(); err == nil {
		t.Fatal("none relationship with coverage was accepted")
	}
	base = validControlMapping()
	base.Relationship = MappingEquivalent
	base.CoverageBasisPoints = 9999
	if err := base.Validate(); err == nil {
		t.Fatal("equivalent relationship without full coverage was accepted")
	}
	base = validControlMapping()
	base.DecisionState = MappingApproved
	base.ReviewerID = ""
	if err := base.Validate(); err == nil {
		t.Fatal("decided mapping without reviewer was accepted")
	}
}

func validControlMapping() ControlMapping {
	digest := ContentDigest("sha256:" + strings.Repeat("c", 64))
	modified := time.Unix(1, 123456789).UTC()
	return ControlMapping{
		ID: "mapping", RevisionID: "mapping-r1", Granularity: "objective",
		Source:       RevisionRef{ID: "source", RevisionID: "source-r1", Version: 1, ContentDigest: digest, LastModified: modified},
		Target:       RevisionRef{ID: "target", RevisionID: "target-r1", Version: 1, ContentDigest: digest, LastModified: modified},
		Relationship: MappingOverlap, Method: "manual", Rationale: "overlap", CoverageBasisPoints: 5000,
		DecisionState: MappingProposed, AuthorID: "author",
	}
}

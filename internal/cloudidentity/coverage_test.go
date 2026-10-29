package cloudidentity

import (
	"encoding/json"
	"testing"
)

func TestSourcePinExactRequiresRepositoryAndRevision(t *testing.T) {
	cases := []struct {
		name string
		pin  SourcePin
		want bool
	}{
		{"exactWithRepoAndRevision", SourcePin{Exact: true, Repository: "r", Revision: "v"}, true},
		{"exactButEmpty", SourcePin{Exact: true}, false},
		{"exactMissingRevision", SourcePin{Exact: true, Repository: "r"}, false},
		{"notExactButPopulated", SourcePin{Repository: "r", Revision: "v"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sourcePinExact(c.pin); got != c.want {
				t.Errorf("sourcePinExact(%+v) = %v, want %v", c.pin, got, c.want)
			}
		})
	}
}

func TestAssessConsumerCoverageMissingSecondConsumerBlocksPromotion(t *testing.T) {
	e := excessEvidence(testNow)
	e.Consumers = append(e.Consumers, Workload{ID: "w2", Service: "billing", Namespace: "ns1", ServiceAccount: "sa2", Source: exactPin()})
	// Only w1 (from excessEvidence) has a bound investigation; w2 has none.
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Supported {
		t.Fatalf("Status = %v, want not Supported: consumer w2 has no investigation at all", a.Status)
	}
	if !hasGapCode(a.Gaps, "cloudidentity.missing_consumer_investigation") {
		t.Errorf("expected missing_consumer_investigation gap, got %+v", a.Gaps)
	}
}

func TestAssessConsumerCoverageMismatchedSourceExcludesInvestigation(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Investigations[0].Source.Digest = "sha256:wrong"

	ok, gaps, bound := assessConsumerCoverage(e)
	if ok {
		t.Fatal("expected coverage to fail: investigation source digest does not match the consumer's own source digest")
	}
	if len(bound) != 0 {
		t.Errorf("mismatched-source investigation must not be bound/used, got %+v", bound)
	}
	if !hasGapCode(gaps, "cloudidentity.investigation_source_mismatch") {
		t.Errorf("expected investigation_source_mismatch gap, got %+v", gaps)
	}

	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("Status must not be Clear when the only investigation's source doesn't match its consumer")
	}
}

func TestAssessConsumerCoverageMismatchedValidationSourceDigest(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Investigations[0].Validation.SourceDigest = "sha256:different-than-source"

	ok, gaps, bound := assessConsumerCoverage(e)
	if ok {
		t.Fatal("expected coverage to fail: Validation.SourceDigest does not match Investigation.Source.Digest")
	}
	if len(bound) != 0 {
		t.Errorf("investigation with mismatched Validation.SourceDigest must not be bound, got %+v", bound)
	}
	if !hasGapCode(gaps, "cloudidentity.investigation_source_digest_mismatch") {
		t.Errorf("expected investigation_source_digest_mismatch gap, got %+v", gaps)
	}
}

func TestAssessConsumerCoverageDuplicateConflictingInvestigation(t *testing.T) {
	e := cleanEvidence(testNow)
	conflicting := e.Investigations[0]
	conflicting.Requirements = []Requirement{{
		Provider: AWS, Action: "s3:PutObject", Resources: []string{"arn:aws:s3:::bucket/other"}, ConsumerIDs: []string{"w1"},
	}}
	e.Investigations = append(e.Investigations, conflicting)

	ok, gaps, bound := assessConsumerCoverage(e)
	if ok {
		t.Fatal("expected coverage to fail: consumer w1 has two investigations")
	}
	if len(bound) != 0 {
		t.Errorf("neither of two conflicting investigations for the same consumer should be used, got %+v", bound)
	}
	if !hasGapCode(gaps, "cloudidentity.duplicate_consumer_investigation") {
		t.Errorf("expected duplicate_consumer_investigation gap, got %+v", gaps)
	}

	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("Status must not be Clear with a duplicate/ambiguous investigation for the only consumer")
	}
}

func TestAssessConsumerCoverageUnmatchedInvestigationExcludedFromUnion(t *testing.T) {
	e := cleanEvidence(testNow)
	// A rogue investigation for a consumer absent from the reviewed
	// inventory must never inject extra justification into the union.
	e.Investigations = append(e.Investigations, Investigation{
		ConsumerID: "ghost",
		Source:     exactPin(),
		Requirements: []Requirement{{
			Provider: AWS, Action: "s3:PutObject", Resources: []string{"arn:aws:s3:::bucket/obj1"}, ConsumerIDs: []string{"ghost"},
		}},
		Validation: validInvestigationValidation(),
	})
	e.Declared.Grants[0].Actions = append(e.Declared.Grants[0].Actions, "s3:PutObject")
	e.Observed.Grants[0].Actions = append(e.Observed.Grants[0].Actions, "s3:PutObject")

	ok, gaps, bound := assessConsumerCoverage(e)
	if ok {
		t.Fatal("expected coverage to fail: an investigation references an unknown consumer")
	}
	if !hasGapCode(gaps, "cloudidentity.unmatched_investigation_consumer") {
		t.Errorf("expected unmatched_investigation_consumer gap, got %+v", gaps)
	}
	for _, inv := range bound {
		if inv.ConsumerID == "ghost" {
			t.Fatal("the unmatched ghost investigation must not be bound/used")
		}
	}

	a := Assess(e, testNow, testMaxAge)
	if _, found := findExcess(a.DeclaredExcess, "s3:PutObject"); !found {
		t.Error("s3:PutObject must still be flagged excess: the ghost consumer's requirement must not justify it")
	}
}

func TestAssessExactFlagAloneDoesNotPermitEmptySource(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Consumers[0].Source = SourcePin{Exact: true} // Exact=true, no repository/revision at all
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("an Exact=true SourcePin with no repository/revision must not be treated as a real pin")
	}
	if !hasGapCode(a.Gaps, "cloudidentity.inexact_source_pin") {
		t.Errorf("expected inexact_source_pin gap, got %+v", a.Gaps)
	}
}

func TestDefinitionsDigestConsistentWhenCorrectlyComputed(t *testing.T) {
	defs := Definitions{Actions: []ActionDefinition{{Name: "s3:GetObject"}, {Name: "s3:PutObject"}}}
	defs.Digest = Digest(struct {
		Actions    []ActionDefinition
		Operations []OperationDefinition
		Roles      []RoleDefinition
		Policies   []ManagedPolicy
	}{sortedActionDefinitions(defs.Actions), nil, nil, nil})

	if !definitionsDigestConsistent(defs) {
		t.Fatal("expected a correctly-computed canonical Digest to be consistent")
	}
}

func TestDefinitionsDigestInconsistentIsFlagged(t *testing.T) {
	defs := Definitions{Actions: []ActionDefinition{{Name: "s3:GetObject"}}, Digest: "sha256:stale"}
	if definitionsDigestConsistent(defs) {
		t.Fatal("expected a stale/wrong Digest to be flagged inconsistent")
	}
}

func TestDefinitionsDigestEmptyIsNotInconsistent(t *testing.T) {
	defs := Definitions{Actions: []ActionDefinition{{Name: "s3:GetObject"}}}
	if !definitionsDigestConsistent(defs) {
		t.Fatal("an empty Digest should not itself be treated as inconsistent")
	}
}

func TestAssessFlagsInconsistentDefinitionsDigest(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Definitions.Digest = "sha256:not-the-real-digest"
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("Status must not be Clear when Definitions.Digest is inconsistent with its own content")
	}
	if !hasGapCode(a.Gaps, "cloudidentity.definitions_digest_mismatch") {
		t.Errorf("expected definitions_digest_mismatch gap, got %+v", a.Gaps)
	}
}

func TestMergedDefinitionsRemainValidAcrossEventSerialization(t *testing.T) {
	for _, original := range []Definitions{
		{Actions: []ActionDefinition{{Name: "s3:GetObject"}}, Complete: true},
		{Roles: []RoleDefinition{{Name: "roles/storage.objectViewer", Permissions: []string{"storage.objects.get"}}}, Complete: true},
	} {
		merged := MergeDefinitions(original)
		raw, err := json.Marshal(merged)
		if err != nil {
			t.Fatal(err)
		}
		var replayed Definitions
		if err := json.Unmarshal(raw, &replayed); err != nil {
			t.Fatal(err)
		}
		if !definitionsDigestConsistent(merged) || !definitionsDigestConsistent(replayed) {
			t.Fatal("empty definition categories invalidated an intact merged snapshot")
		}
		if len(replayed.Actions) != 0 {
			replayed.Actions[0].Name = "s3:PutObject"
		} else {
			replayed.Roles[0].Permissions = []string{"storage.objects.delete"}
		}
		if definitionsDigestConsistent(replayed) {
			t.Fatal("changed permissions retained a valid content digest")
		}
	}
}

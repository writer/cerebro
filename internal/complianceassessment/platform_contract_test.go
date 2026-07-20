package complianceassessment

import "testing"

func TestSemanticModelNamesCanonicalAuthorities(t *testing.T) {
	model := SemanticModel()
	if model.Version != AssuranceSemanticModelVersion || len(model.Entities) != 5 {
		t.Fatalf("SemanticModel() = %+v", model)
	}
	want := map[string]string{
		"assessment_run":       "compliance assessment event log",
		"objective_result":     "content-addressed assessment result chunks",
		"assurance_decision":   "immutable assurance decision record",
		"assessment_snapshot":  "immutable assessment snapshot record",
		"compliance_work_item": "replayable compliance work projection",
	}
	for _, entity := range model.Entities {
		if authority, ok := want[entity.Name]; !ok || authority != entity.Authority {
			t.Fatalf("unexpected semantic entity: %+v", entity)
		}
		delete(want, entity.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing semantic entities: %+v", want)
	}
}

func TestLegacyCompatibilityViewPreservesStatusAndCanonicalRefs(t *testing.T) {
	result := ObjectiveResult{
		ID: "result-1", ObjectiveID: "objective-1", AutomatedOutcome: OutcomeNotSatisfied,
		ReasonCodes: []ReasonCode{"control_failed"}, EvidenceIDs: []string{"evidence-1"},
	}
	view := NewLegacyCompatibilityView(result, "decision-1", "snapshot-1")
	if view.Version != LegacyCompatibilityVersion || view.Status != LegacyStatusFailing {
		t.Fatalf("NewLegacyCompatibilityView() = %+v", view)
	}
	if view.ResultID != result.ID || view.AssuranceDecisionID != "decision-1" || view.AssessmentSnapshotID != "snapshot-1" {
		t.Fatalf("compatibility refs = %+v", view)
	}
	view.EvidenceIDs[0] = "changed"
	if result.EvidenceIDs[0] != "evidence-1" {
		t.Fatalf("compatibility view aliases source evidence ids")
	}
}

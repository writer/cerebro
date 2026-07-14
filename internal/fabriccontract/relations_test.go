package fabriccontract

import "testing"

func TestRelationsAreSortedAndKnown(t *testing.T) {
	relations := Relations()
	if len(relations) == 0 {
		t.Fatal("Relations() empty")
	}
	for i := 1; i < len(relations); i++ {
		if relations[i-1] > relations[i] {
			t.Fatalf("Relations() not sorted: %q before %q", relations[i-1], relations[i])
		}
	}
	for _, relation := range []string{RelationBelongsTo, RelationDependsOn, RelationHasFinding, RelationRepresentsIdentity} {
		if !IsRelation(relation) {
			t.Fatalf("IsRelation(%q) = false", relation)
		}
	}
	if IsRelation("BELONGS_TO") || IsRelation("not_a_relation") {
		t.Fatal("IsRelation accepted non-canonical relation")
	}
}

func TestFindingRelationDefinitionsConstrainResourceKinds(t *testing.T) {
	tests := []struct {
		relation string
		target   string
	}{
		{relation: RelationSelf, target: "finding"},
		{relation: RelationHasContext, target: "finding_investigation"},
		{relation: RelationHasEvidence, target: "finding_evidence_collection"},
		{relation: RelationObservedOn, target: "source_runtime"},
		{relation: RelationAffects, target: "graph_entity"},
	}
	for _, test := range tests {
		definition, ok := LookupRelation(test.relation)
		if !ok {
			t.Fatalf("LookupRelation(%q) missing", test.relation)
		}
		if definition.Class != RelationClassStructural {
			t.Fatalf("LookupRelation(%q).Class = %q, want structural", test.relation, definition.Class)
		}
		if len(definition.SourceKinds) != 1 || definition.SourceKinds[0] != "finding" {
			t.Fatalf("LookupRelation(%q).SourceKinds = %v, want [finding]", test.relation, definition.SourceKinds)
		}
		if len(definition.TargetKinds) != 1 || definition.TargetKinds[0] != test.target {
			t.Fatalf("LookupRelation(%q).TargetKinds = %v, want [%s]", test.relation, definition.TargetKinds, test.target)
		}
	}
}

func TestLookupRelationReturnsCopy(t *testing.T) {
	definition, ok := LookupRelation(RelationSelf)
	if !ok {
		t.Fatal("LookupRelation(self) missing")
	}
	definition.SourceKinds[0] = "changed"

	got, _ := LookupRelation(RelationSelf)
	if got.SourceKinds[0] != "finding" {
		t.Fatalf("LookupRelation(self).SourceKinds = %v after caller mutation", got.SourceKinds)
	}
}

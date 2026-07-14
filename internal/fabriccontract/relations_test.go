package fabriccontract

import (
	"reflect"
	"testing"
)

func TestRelationsAreSortedAndKnown(t *testing.T) {
	relations := Relations()
	if len(relations) == 0 {
		t.Fatal("Relations() returned no relations")
	}
	for i, relation := range relations {
		if !IsRelation(relation) {
			t.Fatalf("Relations()[%d] = %q is not known", i, relation)
		}
		if i > 0 && relations[i-1] >= relation {
			t.Fatalf("relations not strictly sorted: %q before %q", relations[i-1], relation)
		}
	}
	if IsRelation("not_registered") {
		t.Fatal("IsRelation accepted unknown relation")
	}
}

func TestRelationDefinitionsHaveStableSemantics(t *testing.T) {
	definitions := RelationDefinitions()
	if len(definitions) != len(Relations()) {
		t.Fatalf("definitions = %d, relations = %d", len(definitions), len(Relations()))
	}
	for i, definition := range definitions {
		if definition.Name == "" || definition.Class == "" || definition.DefaultDirection == "" {
			t.Fatalf("definition %d incomplete: %#v", i, definition)
		}
		if i > 0 && definitions[i-1].Name >= definition.Name {
			t.Fatalf("definitions not strictly sorted: %q before %q", definitions[i-1].Name, definition.Name)
		}
		for _, kind := range append(append([]ResourceKind(nil), definition.SourceKinds...), definition.TargetKinds...) {
			if !IsResourceKind(string(kind)) {
				t.Fatalf("definition %q uses unknown kind %q", definition.Name, kind)
			}
		}
		if definition.Inverse == "" {
			continue
		}
		inverse, ok := RelationDefinitionFor(definition.Inverse)
		if !ok || inverse.Inverse != definition.Name {
			t.Fatalf("definition %q inverse is not reciprocal: %#v", definition.Name, inverse)
		}
	}
}

func TestRelationDefinitionsAreCopiedAndEnforceKinds(t *testing.T) {
	definition, ok := RelationDefinitionFor(RelationApprovedBy)
	if !ok {
		t.Fatalf("RelationDefinitionFor(%q) missing", RelationApprovedBy)
	}
	if !definition.Allows(ResourceKindActionProposal, ResourceKindApprovalReceipt) {
		t.Fatal("approved_by rejected action proposal to approval receipt")
	}
	if definition.Allows(ResourceKindApprovalReceipt, ResourceKindActionProposal) {
		t.Fatal("approved_by accepted inverse kind direction")
	}
	wantSources := append([]ResourceKind(nil), definition.SourceKinds...)
	definition.SourceKinds[0] = ResourceKindJob
	fresh, _ := RelationDefinitionFor(RelationApprovedBy)
	if !reflect.DeepEqual(fresh.SourceKinds, wantSources) {
		t.Fatalf("registry mutated through returned definition: %v", fresh.SourceKinds)
	}
}

func TestFindingLinkRelationsUseCanonicalResourceKinds(t *testing.T) {
	tests := []struct {
		relation string
		target   ResourceKind
	}{
		{relation: RelationSelf, target: ResourceKindFinding},
		{relation: RelationHasContext, target: ResourceKindFindingInvestigation},
		{relation: RelationHasEvidence, target: ResourceKindFindingEvidenceCollection},
		{relation: RelationObservedOn, target: ResourceKindSourceRuntime},
		{relation: RelationAffects, target: ResourceKindGraphEntity},
	}
	for _, test := range tests {
		definition, ok := RelationDefinitionFor(test.relation)
		if !ok {
			t.Fatalf("RelationDefinitionFor(%q) missing", test.relation)
		}
		if !definition.Allows(ResourceKindFinding, test.target) {
			t.Fatalf("relation %q rejected finding -> %s", test.relation, test.target)
		}
	}
}

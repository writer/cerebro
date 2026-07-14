package fabriccontract

import "testing"

func TestResourceKindDefinitionsAreSortedAndOwned(t *testing.T) {
	definitions := ResourceKindDefinitions()
	if len(definitions) == 0 {
		t.Fatal("ResourceKindDefinitions() empty")
	}
	for i, definition := range definitions {
		if definition.Kind == "" || definition.Owner == "" {
			t.Fatalf("definition %d missing kind or owner: %#v", i, definition)
		}
		if definition.Identifier != ResourceIdentifierID && definition.Identifier != ResourceIdentifierURN {
			t.Fatalf("definition %q identifier = %q", definition.Kind, definition.Identifier)
		}
		if i > 0 && definitions[i-1].Kind >= definition.Kind {
			t.Fatalf("definitions not strictly sorted: %q before %q", definitions[i-1].Kind, definition.Kind)
		}
	}
}

func TestResourceKindDefinitionsPreserveOwnershipBoundaries(t *testing.T) {
	tests := []struct {
		kind       ResourceKind
		owner      ResourceOwner
		identifier ResourceIdentifierKind
	}{
		{ResourceKindFinding, ResourceOwnerFindings, ResourceIdentifierID},
		{ResourceKindGraphEntity, ResourceOwnerGraphProjection, ResourceIdentifierURN},
		{ResourceKindRule, ResourceOwnerRuleCatalog, ResourceIdentifierID},
		{ResourceKindActionExecution, ResourceOwnerActionWorkflow, ResourceIdentifierID},
	}
	for _, test := range tests {
		definition, ok := ResourceKindDefinitionFor(string(test.kind))
		if !ok {
			t.Fatalf("ResourceKindDefinitionFor(%q) missing", test.kind)
		}
		if definition.Owner != test.owner || definition.Identifier != test.identifier {
			t.Fatalf("ResourceKindDefinitionFor(%q) = %#v", test.kind, definition)
		}
	}
	if IsResourceKind("GRAPH_ENTITY") || IsResourceKind("not_a_resource") {
		t.Fatal("IsResourceKind accepted a non-canonical kind")
	}
}

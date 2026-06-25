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

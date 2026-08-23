package connectorcatalog

import "testing"

func TestOktaGroupMembershipDeclaresProviderPathScope(t *testing.T) {
	entry, ok, err := BuiltinEntry("okta")
	if err != nil {
		t.Fatalf("BuiltinEntry(okta) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(okta) ok = false, want true")
	}

	var hasGroupID bool
	for _, field := range entry.Definition.ConfigFields {
		if field.Key == "group_id" {
			hasGroupID = true
			if field.Required {
				t.Fatal("group_id is globally required; want family-scoped optional configuration")
			}
		}
	}
	if !hasGroupID {
		t.Fatal("Okta config fields omit group_id")
	}

	family := catalogFamily(t, entry.Definition.ResourceFamilies, "group_membership")
	if family.Path != "/api/v1/groups/{group_id}/users" {
		t.Fatalf("group_membership path = %q, want provider path", family.Path)
	}
	if family.Read == nil || len(family.Read.PathParams) != 1 || family.Read.PathParams[0] != "group_id" {
		t.Fatalf("group_membership path params = %#v, want [group_id]", family.Read)
	}
}

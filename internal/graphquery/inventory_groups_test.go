package graphquery

import "testing"

func TestInventoryGroupForEntityType(t *testing.T) {
	cases := []struct {
		entityType string
		group      string
	}{
		{"okta.user", InventoryGroupIdentities},
		{"aws.role", InventoryGroupIdentities},
		{"aws.user", InventoryGroupIdentities},
		{"google_workspace.group", InventoryGroupIdentities},
		{"kubernetes.rbac_binding", InventoryGroupIdentities},
		{"kubernetes.service_account", InventoryGroupIdentities},
		{"cerebro.principal", InventoryGroupIdentities},
		{"aws.ec2.instance", InventoryGroupCloud},
		{"aws.s3.bucket", InventoryGroupCloud},
		{"gcp.compute.instance", InventoryGroupCloud},
		{"kubernetes.cluster", InventoryGroupCloud},
		{"cloud.account", InventoryGroupCloud},
		{"github.code.repository", InventoryGroupCode},
		{"github.org", InventoryGroupCode},
		{"container.registry", InventoryGroupCode},
		{"saas.application", InventoryGroupSaaS},
		{"okta.application", InventoryGroupSaaS},
		{"vendor", InventoryGroupSaaS},
		{"trusted_endpoint.agent", InventoryGroupDevices},
		{"kandji.blueprint", InventoryGroupDevices},
		{"sentinelone.agent", InventoryGroupDevices},
		{"secret", InventoryGroupSecrets},
		{"cerebro.credential", InventoryGroupSecrets},
	}
	for _, testCase := range cases {
		got, label, ok := InventoryGroupForEntityType(testCase.entityType)
		if !ok {
			t.Fatalf("%s: expected a group, got none", testCase.entityType)
		}
		if got != testCase.group {
			t.Fatalf("%s: expected group %q, got %q", testCase.entityType, testCase.group, got)
		}
		if label == "" {
			t.Fatalf("%s: expected a non-empty label", testCase.entityType)
		}
	}
}

// Entity types are built from a provider and a resource type at projection
// time, so these are the pairs where two rules could both match and the
// declaration order decides the winner.
func TestInventoryGroupRuleOrderResolvesOverlaps(t *testing.T) {
	cases := []struct {
		entityType string
		group      string
		losingRule string
	}{
		{"github.user", InventoryGroupIdentities, InventoryGroupCode},
		{"aws.sso.permission.set", InventoryGroupIdentities, InventoryGroupCloud},
		{"gcp.service_account", InventoryGroupIdentities, InventoryGroupCloud},
		{"aws.ecr.container.image", InventoryGroupCode, InventoryGroupCloud},
		{"okta.user", InventoryGroupIdentities, InventoryGroupSaaS},
		{"aws.secret", InventoryGroupSecrets, InventoryGroupCloud},
		{"kolide.device", InventoryGroupDevices, InventoryGroupIdentities},
	}
	for _, testCase := range cases {
		got, _, ok := InventoryGroupForEntityType(testCase.entityType)
		if !ok || got != testCase.group {
			t.Fatalf("%s: expected %q to win over %q, got %q (matched=%t)", testCase.entityType, testCase.group, testCase.losingRule, got, ok)
		}
	}
}

// Types computed as runtime.<resource_type> are the largest family in the
// product and carry no provider prefix, so they must group on the suffix.
func TestInventoryGroupHandlesRuntimeTypes(t *testing.T) {
	cases := map[string]string{
		"runtime.user":        InventoryGroupIdentities,
		"runtime.group":       InventoryGroupIdentities,
		"runtime.repository":  InventoryGroupCode,
		"runtime.secret":      InventoryGroupSecrets,
		"runtime.device":      InventoryGroupDevices,
		"runtime.integration": InventoryGroupSaaS,
	}
	for entityType, want := range cases {
		got, _, ok := InventoryGroupForEntityType(entityType)
		if !ok || got != want {
			t.Fatalf("%s: expected %q, got %q (matched=%t)", entityType, want, got, ok)
		}
	}
}

// Catalog templates and several projectors join the parts of an entity type
// with an underscore where others use a dot, for the same concept.
func TestInventoryGroupMatchesUnderscoreSeparatedTypes(t *testing.T) {
	cases := map[string]string{
		"identity_user":                     InventoryGroupIdentities,
		"identity_group":                    InventoryGroupIdentities,
		"identity_application":              InventoryGroupIdentities,
		"aws.iam_role":                      InventoryGroupIdentities,
		"gcp.service_account":               InventoryGroupIdentities,
		"storage_bucket":                    InventoryGroupCloud,
		"cloud_resource":                    InventoryGroupCloud,
		"endpoint_device":                   InventoryGroupDevices,
		"sentinelone.installed_application": InventoryGroupDevices,
	}
	for entityType, want := range cases {
		got, _, ok := InventoryGroupForEntityType(entityType)
		if !ok || got != want {
			t.Fatalf("%s: expected %q, got %q (matched=%t)", entityType, want, got, ok)
		}
	}
}

func TestInventoryGroupLeavesUnmatchedTypesUngrouped(t *testing.T) {
	for _, entityType := range []string{"policy", "control", "document", "grc.target", "", "   "} {
		if _, _, ok := InventoryGroupForEntityType(entityType); ok {
			t.Fatalf("%q: expected no group", entityType)
		}
	}
}

func TestInventoryGroupForEntityTypesRequiresAgreement(t *testing.T) {
	if id, _ := inventoryGroupForEntityTypes([]string{"okta.user", "google_workspace.user"}); id != InventoryGroupIdentities {
		t.Fatalf("expected agreeing types to report identities, got %q", id)
	}
	if id, _ := inventoryGroupForEntityTypes([]string{"okta.user", "aws.ec2.instance"}); id != "" {
		t.Fatalf("expected disagreeing types to report no group, got %q", id)
	}
	if id, _ := inventoryGroupForEntityTypes([]string{"okta.user", "policy"}); id != "" {
		t.Fatalf("expected an ungrouped type to clear the group, got %q", id)
	}
}

// A group id travels in the same query parameter as a category id, so the two
// namespaces must not collide.
func TestInventoryGroupIDsDoNotCollideWithCategoryIDs(t *testing.T) {
	for _, category := range inventoryCategoryLookup() {
		if IsInventoryGroupID(category.id) {
			t.Fatalf("category id %q collides with an inventory group id", category.id)
		}
	}
	seen := map[string]bool{}
	for _, rule := range inventoryGroupRules() {
		if rule.label == "" {
			t.Fatalf("group %q has no label", rule.id)
		}
		if seen[rule.id] {
			t.Fatalf("duplicate group id %q", rule.id)
		}
		seen[rule.id] = true
	}
	if IsInventoryGroupID("compute-instances") {
		t.Fatal("expected a per-class category id not to be treated as a group")
	}
}

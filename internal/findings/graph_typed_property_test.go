package findings

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// The hot boolean predicates were promoted to typed, indexed node properties
// (projectionmeta.DerivedEntityProperties). Each rule must prefer the typed
// property but retain an `IS NULL` fallback to the legacy attributes_json scan,
// so the result set is identical for entities not yet re-projected since the
// promotion shipped.
func TestGraphRulesPreferTypedPropertyWithJSONFallback(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime", SourceId: "graph", TenantId: "writer"}

	exposure := mustGraphRule(t, newCloudPublicResourceExposureGraphRule()).QueryFor(runtime).Query
	for _, fragment := range []string{
		"resource.internet_exposed = true",
		"resource.internet_exposed IS NULL",
		`coalesce(resource.attributes_json, '') CONTAINS '"internet_exposed":"true"'`,
		`coalesce(resource.attributes_json, '') CONTAINS '"external_exposure":"true"'`,
		`coalesce(resource.attributes_json, '') CONTAINS '"public":"true"'`,
	} {
		if !strings.Contains(exposure, fragment) {
			t.Fatalf("cloud public-exposure query missing %q:\n%s", fragment, exposure)
		}
	}

	identity := mustGraphRule(t, newIdentityPrivilegedNoMFAAccessRule()).QueryFor(runtime).Query
	for _, fragment := range []string{
		"user.is_privileged_identity = true",
		"user.is_privileged_identity IS NULL",
		"user.mfa_disabled = true",
		"user.mfa_disabled IS NULL",
		`user_attrs CONTAINS '"is_admin":"true"'`,
		`user_attrs CONTAINS '"is_delegated_admin":"true"'`,
		`user_attrs CONTAINS '"mfa_enrolled":"false"'`,
		`user_attrs CONTAINS '"is_enforced_in_2sv":"false"'`,
	} {
		if !strings.Contains(identity, fragment) {
			t.Fatalf("identity no-MFA query missing %q:\n%s", fragment, identity)
		}
	}
}

func mustGraphRule(t *testing.T, rule Rule) GraphRule {
	t.Helper()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatalf("%T does not implement GraphRule", rule)
	}
	return graphRule
}

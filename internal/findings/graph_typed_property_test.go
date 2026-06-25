package findings

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// The hot boolean predicates are promoted to typed, indexed node properties
// (projectionmeta.DerivedEntityProperties) and backfilled across every entity,
// so each rule filters on the sargable typed property alone. The legacy
// `IS NULL` attributes_json full-scan fallback was removed once the backfill
// completed; these queries must use the indexed equality and must not
// reintroduce the fallback.
func TestGraphRulesUseSargableTypedProperties(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "runtime", SourceId: "graph", TenantId: "writer"}

	exposure := mustGraphRule(t, newCloudPublicResourceExposureGraphRule()).QueryFor(runtime).Query
	if !strings.Contains(exposure, "resource.internet_exposed = true") {
		t.Fatalf("cloud public-exposure query missing sargable predicate:\n%s", exposure)
	}
	for _, fragment := range []string{
		"resource.internet_exposed IS NULL",
		`coalesce(resource.attributes_json, '') CONTAINS '"internet_exposed":"true"'`,
		`coalesce(resource.attributes_json, '') CONTAINS '"external_exposure":"true"'`,
		`coalesce(resource.attributes_json, '') CONTAINS '"public":"true"'`,
	} {
		if strings.Contains(exposure, fragment) {
			t.Fatalf("cloud public-exposure query must not retain legacy fallback %q:\n%s", fragment, exposure)
		}
	}

	identity := mustGraphRule(t, newIdentityPrivilegedNoMFAAccessRule()).QueryFor(runtime).Query
	for _, fragment := range []string{
		"user.is_privileged_identity = true",
		"user.mfa_disabled = true",
	} {
		if !strings.Contains(identity, fragment) {
			t.Fatalf("identity no-MFA query missing sargable predicate %q:\n%s", fragment, identity)
		}
	}
	for _, fragment := range []string{
		"user.is_privileged_identity IS NULL",
		"user.mfa_disabled IS NULL",
		"user_attrs",
		`CONTAINS '"is_admin":"true"'`,
		`CONTAINS '"mfa_enrolled":"false"'`,
		`CONTAINS '"is_enforced_in_2sv":"false"'`,
	} {
		if strings.Contains(identity, fragment) {
			t.Fatalf("identity no-MFA query must not retain legacy fallback %q:\n%s", fragment, identity)
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

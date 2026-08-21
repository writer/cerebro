package connectorcatalog

import (
	"slices"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestAzureCatalogCompilesExactAuthorizationPolicyExecutionPlan(t *testing.T) {
	entry, found, err := BuiltinEntry("azure")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("azure catalog definition is missing")
	}
	plan, err := connectordefinitions.CompileSourceExecutionPlanV1(entry.Definition, "authorization_policy")
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetProviderKernel() != "azure.authorization_policy" || plan.GetSingletonFallbackId() != "authorizationPolicy" {
		t.Fatalf("unexpected compiled plan: %#v", plan)
	}
	if !slices.Equal(plan.GetRequiredAttributes(), []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"}) || !slices.Equal(plan.GetRequiredPayloadFields(), []string{"id"}) {
		t.Fatalf("unexpected compiled admission contract: %#v", plan)
	}
}

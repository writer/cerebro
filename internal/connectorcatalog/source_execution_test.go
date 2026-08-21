package connectorcatalog

import (
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
}

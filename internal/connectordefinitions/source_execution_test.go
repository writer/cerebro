package connectordefinitions

import (
	"testing"
)

func TestCompileAzureAuthorizationPolicyExecutionPlan(t *testing.T) {
	definition := azureAuthorizationPolicyDefinition()
	plan, err := CompileSourceExecutionPlanV1(definition, "authorization_policy")
	if err != nil {
		t.Fatal(err)
	}
	if plan.GetProviderKernel() != "azure.authorization_policy" || plan.GetOrigin() != "https://graph.microsoft.com" || plan.GetPath() != "/v1.0/policies/authorizationPolicy" {
		t.Fatalf("unexpected provider plan: %#v", plan)
	}
	if plan.GetRecordSelector() != "$" || plan.GetSingletonFallbackId() != "authorizationPolicy" || plan.GetMaxResponseBytes() != 8<<20 {
		t.Fatalf("unexpected singleton plan: %#v", plan)
	}
	if plan.GetEventKind() != "azure.authorization_policy" || plan.GetSchemaRef() != "azure/authorization_policy/v1" {
		t.Fatalf("unexpected event contract: %#v", plan)
	}
	if len(plan.GetPlanDigestSha256()) != 64 {
		t.Fatalf("plan digest = %q", plan.GetPlanDigestSha256())
	}
}

func azureAuthorizationPolicyDefinition() Definition {
	return Definition{
		SourceID: "azure",
		Auth: AuthSpec{
			Model:              "bearer_token",
			RequiresReferences: true,
			CredentialFields:   []Field{{Key: "bearer_token", Required: true, Secret: true, ReferenceOnly: true}},
		},
		Transport: &TransportSpec{BaseURL: "https://graph.microsoft.com"},
		ResourceFamilies: []ResourceFamily{{
			ID: "authorization_policy", Method: "GET", Path: "/v1.0/policies/authorizationPolicy",
			Singleton: true, Pagination: &PaginationSpec{Type: "none"}, RecordSelector: "$",
			ProviderKernel: "azure.authorization_policy", SingletonFallbackID: "authorizationPolicy", IDField: "id",
			Event: EventMappingSpec{
				Kind: "azure.authorization_policy", SchemaRef: "azure/authorization_policy/v1",
				RequiredAttributes: []string{"resource_type", "resource_provider", "resource_name", "resource_id"},
			},
		}},
	}
}

func TestCompileExecutionPlanRejectsCredentialValuesAndWeakEventContract(t *testing.T) {
	definition := azureAuthorizationPolicyDefinition()
	definition.Auth.CredentialFields[0].ReferenceOnly = false
	definition.ResourceFamilies[0].Event.RequiredAttributes = nil
	if _, err := CompileSourceExecutionPlanV1(definition, "authorization_policy"); err == nil {
		t.Fatal("compiler accepted a non-reference credential and weak event contract")
	}
}

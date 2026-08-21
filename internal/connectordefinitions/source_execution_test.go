package connectordefinitions

import (
	"slices"
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
	if got := plan.GetRequiredAttributes(); !slices.Equal(got, []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"}) {
		t.Fatalf("required attributes = %v", got)
	}
	if got := plan.GetRequiredPayloadFields(); !slices.Equal(got, []string{"id"}) {
		t.Fatalf("required payload fields = %v", got)
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
			Read: &ResourceReadSpec{ProviderKernel: "azure.authorization_policy", SingletonFallbackID: "authorizationPolicy"}, IDField: "id",
			Event: EventMappingSpec{
				Kind: "azure.authorization_policy", SchemaRef: "azure/authorization_policy/v1",
				RequiredAttributes:    []string{"resource_type", "resource_provider", "resource_name", "resource_id", "family"},
				RequiredPayloadFields: []string{"id"},
			},
		}},
	}
}

func TestCompileExecutionPlanRejectsUnregisteredKernelAndOrigin(t *testing.T) {
	for name, mutate := range map[string]func(*Definition){
		"kernel": func(definition *Definition) { definition.ResourceFamilies[0].Read.ProviderKernel = "azure.arbitrary" },
		"origin": func(definition *Definition) { definition.Transport.BaseURL = "https://example.com" },
	} {
		t.Run(name, func(t *testing.T) {
			definition := azureAuthorizationPolicyDefinition()
			mutate(&definition)
			if _, err := CompileSourceExecutionPlanV1(definition, "authorization_policy"); err == nil {
				t.Fatal("compiler accepted an unregistered provider binding")
			}
		})
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

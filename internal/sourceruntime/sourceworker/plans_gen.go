package sourceworker

import (
	"crypto/sha256"
	"encoding/hex"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// AzureAuthorizationPolicyPlan returns the generated, credential-free plan for
// the first-party Azure authorization policy family. Runtime code does not read
// the connector catalog YAML.
func AzureAuthorizationPolicyPlan() *cerebrov1.SourceExecutionPlanV1 {
	plan := &cerebrov1.SourceExecutionPlanV1{
		PlanId:              "source-plan-v1:azure:authorization_policy",
		SourceId:            "azure",
		FamilyId:            "authorization_policy",
		ProviderKernel:      "azure.authorization_policy",
		Method:              "GET",
		Origin:              "https://graph.microsoft.com",
		Path:                "/v1.0/policies/authorizationPolicy",
		RecordSelector:      "$",
		IdField:             "id",
		SingletonFallbackId: "authorizationPolicy",
		MaxResponseBytes:    maxResponseBytes,
		EventKind:           "azure.authorization_policy",
		SchemaRef:           "azure/authorization_policy/v1",
		RequiredAttributes:  []string{"resource_id", "resource_name", "resource_provider", "resource_type"},
	}
	plan.PlanDigestSha256 = executionPlanDigest(plan)
	return plan
}

func executionPlanDigest(plan *cerebrov1.SourceExecutionPlanV1) string {
	clone := proto.Clone(plan).(*cerebrov1.SourceExecutionPlanV1)
	clone.PlanDigestSha256 = ""
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		panic("generated source execution plan cannot be encoded: " + err.Error())
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

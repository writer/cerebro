package sourceworker

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestAuthorizationPolicyEventSatisfiesAdmissionContract(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := exactScope(plan, now)
	result, err := (&fakeWorker{responseBody: []byte(exactGoAuthorizationPolicyResponse)}).Decode(context.Background(), &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: plan, StatusCode: 200, ResponseBody: []byte(exactGoAuthorizationPolicyResponse), LogicalPageId: scope.LogicalPageID, RequestIntentDigest: scope.RequestIntentDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := AuthorizationPolicyEvent(plan, scope, result, now)
	if err != nil {
		t.Fatal(err)
	}
	contracts := []sourcecdk.EventContract{{
		Kind: plan.GetEventKind(), SchemaRef: plan.GetSchemaRef(), RequiredAttributes: []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"},
	}}
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, contracts); err != nil {
		t.Fatalf("admission contract: %v", err)
	}
}

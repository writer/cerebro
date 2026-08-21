package sourceworker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/proto"
)

func TestAuthorizationPolicyEventSatisfiesAdmissionContract(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope := exactScope(plan, now)
	receipt := exactReceipt(plan, scope, []byte(exactGoAuthorizationPolicyResponse))
	receiptWire, err := receipt.protobuf()
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&fakeWorker{responseBody: []byte(exactGoAuthorizationPolicyResponse)}).Decode(context.Background(), &cerebrov1.SourceWorkerDecodeRequestV1{
		Plan: plan, StatusCode: 200, ResponseBody: []byte(exactGoAuthorizationPolicyResponse), LogicalPageId: scope.LogicalPageID, RequestIntentDigest: scope.RequestIntentDigest, Receipt: receiptWire,
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := AuthorizationPolicyEvent(plan, scope, receipt, result, now)
	if err != nil {
		t.Fatal(err)
	}
	contracts := []sourcecdk.EventContract{{
		Kind: plan.GetEventKind(), SchemaRef: plan.GetSchemaRef(), RequiredAttributes: plan.GetRequiredAttributes(), RequiredPayloadFields: plan.GetRequiredPayloadFields(),
	}}
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, contracts); err != nil {
		t.Fatalf("admission contract: %v", err)
	}
	missingFamily := proto.Clone(event).(*cerebrov1.EventEnvelope)
	delete(missingFamily.Attributes, "family")
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(missingFamily, contracts); err == nil {
		t.Fatal("admission accepted event without family")
	}
	missingID := proto.Clone(event).(*cerebrov1.EventEnvelope)
	var payload map[string]any
	if err := json.Unmarshal(missingID.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "id")
	missingID.Payload, _ = json.Marshal(payload)
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(missingID, contracts); err == nil {
		t.Fatal("admission accepted event without payload id")
	}
}

package sourceworker

import (
	"encoding/json"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/proto"
)

func TestAuthorizationPolicyEventSatisfiesAdmissionContract(t *testing.T) {
	plan := AzureAuthorizationPolicyPlan()
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy",
		OccurredAtUnixMillis: 1_725_000_000_000,
		Attributes:           map[string]string{"domain": "tenant-1", "family": "authorization_policy", "resource_id": "authorizationPolicy", "resource_name": "authorizationPolicy", "resource_provider": "azure", "resource_type": "authorization_policy"},
		PayloadJson:          []byte(`{"id":"authorizationPolicy","tenant_id":"tenant-1","raw":{"id":"authorizationPolicy"}}`),
	}
	event, err := AuthorizationPolicyEvent(plan, "tenant-1", record)
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

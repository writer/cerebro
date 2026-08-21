package sourceworker

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// AuthorizationPolicyEvent converts one validated worker result into the exact
// tenant-scoped Azure event contract consumed by native admission and projection.
func AuthorizationPolicyEvent(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, result *cerebrov1.SourceWorkerDecodeResultV1, occurredAt time.Time) (*cerebrov1.EventEnvelope, error) {
	if err := validateWorkerResult(plan, scope, result); err != nil {
		return nil, err
	}
	record := result.GetRecords()[0]
	providerID := strings.TrimSpace(record.GetProviderId())
	if providerID == "" {
		providerID = "authorizationPolicy"
	}
	attributes := make(map[string]string, len(record.GetAttributes())+1)
	for key, value := range record.GetAttributes() {
		if value = strings.TrimSpace(value); value != "" {
			attributes[key] = value
		}
	}
	attributes["domain"] = strings.TrimSpace(scope.TenantID)
	for key, want := range map[string]string{
		"family": "authorization_policy", "resource_id": providerID, "resource_name": "authorizationPolicy",
		"resource_provider": "azure", "resource_type": "authorization_policy",
	} {
		if attributes[key] != want {
			return nil, fmt.Errorf("%w: worker record attribute %s is invalid", ErrInvalidExecution, key)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(record.GetPayloadJson(), &payload); err != nil || payload == nil {
		return nil, fmt.Errorf("%w: worker record payload is invalid", ErrInvalidExecution)
	}
	payload["tenant_id"] = strings.TrimSpace(scope.TenantID)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: worker record payload is invalid", ErrInvalidExecution)
	}
	return &cerebrov1.EventEnvelope{
		Id: sanitizeEventID("azure-authorization-policy-" + providerID), TenantId: strings.TrimSpace(scope.TenantID),
		SourceId: "azure", Kind: plan.GetEventKind(), OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef: plan.GetSchemaRef(), Payload: payloadJSON, Attributes: attributes,
	}, nil
}

func sanitizeEventID(value string) string {
	value = strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(value)
	return strings.Trim(value, "-")
}

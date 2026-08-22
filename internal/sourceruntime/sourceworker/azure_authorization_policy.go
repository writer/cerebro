package sourceworker

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// AuthorizationPolicyEvent converts one validated worker result into the exact
// tenant-scoped Azure event contract consumed by native admission and projection.
func AuthorizationPolicyEvent(plan *cerebrov1.SourceExecutionPlanV1, scope CredentialScope, receipt SafeReceipt, result *cerebrov1.SourceWorkerDecodeResultV1, occurredAt time.Time) (*cerebrov1.EventEnvelope, error) {
	executionContext := &cerebrov1.SourceWorkerExecutionContextV1{
		TenantId: scope.TenantID, RuntimeId: scope.RuntimeID, LogicalPageId: scope.LogicalPageID,
		PriorCursor: scope.PriorCursor, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, ObservedAtUnixMillis: receipt.ObservedAtUnixMillis,
	}
	if result.GetTenantId() == "" && len(result.GetRecords()) == 1 && result.GetRecords()[0].GetEventId() == "" {
		if strings.TrimSpace(scope.TenantID) == "" || receipt.PlanDigestSHA256 != plan.GetPlanDigestSha256() || receipt.LogicalPageID != scope.LogicalPageID || receipt.RequestIntentDigest != scope.RequestIntentDigest || receipt.RuntimeGeneration != scope.RuntimeGeneration || receipt.LeaseGeneration != scope.LeaseGeneration {
			return nil, fmt.Errorf("%w: legacy parity result does not match the trusted execution scope", ErrInvalidExecution)
		}
		expected, err := CanonicalResultDigest(result, receipt)
		if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(result.GetResultDigestSha256())) != 1 {
			return nil, fmt.Errorf("%w: legacy worker result digest does not match the safe receipt", ErrWorkerContract)
		}
	} else if err := validateWorkerResult(plan, executionContext, receipt, result); err != nil {
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
	var raw map[string]any
	if err := json.Unmarshal(record.GetPayloadJson(), &raw); err != nil || raw == nil {
		return nil, fmt.Errorf("%w: worker record payload is invalid", ErrInvalidExecution)
	}
	payload := map[string]any{"id": providerID, "tenant_id": strings.TrimSpace(scope.TenantID), "raw": raw}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: worker record payload is invalid", ErrInvalidExecution)
	}
	eventID := strings.TrimSpace(record.GetEventId())
	if eventID == "" {
		eventID = sanitizeEventID("azure-authorization-policy-" + providerID)
	}
	eventTime := occurredAt.UTC()
	if record.GetOccurredAtUnixMillis() > 0 {
		eventTime = time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()
	}
	event := &cerebrov1.EventEnvelope{
		Id: eventID, TenantId: strings.TrimSpace(scope.TenantID),
		SourceId: "azure", Kind: plan.GetEventKind(), OccurredAt: timestamppb.New(eventTime),
		SchemaRef: plan.GetSchemaRef(), Payload: payloadJSON, Attributes: attributes,
	}
	contract := sourcecdk.EventContract{Kind: plan.GetEventKind(), SchemaRef: plan.GetSchemaRef(), RequiredAttributes: plan.GetRequiredAttributes(), RequiredPayloadFields: plan.GetRequiredPayloadFields()}
	if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, []sourcecdk.EventContract{contract}); err != nil {
		return nil, fmt.Errorf("%w: Azure authorization policy admission failed: %w", ErrInvalidExecution, err)
	}
	return event, nil
}

func sanitizeEventID(value string) string {
	value = strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(value)
	return strings.Trim(value, "-")
}

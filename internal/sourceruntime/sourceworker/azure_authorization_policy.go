package sourceworker

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// AuthorizationPolicyEvent performs the temporary mechanical Go envelope
// conversion after Rust has validated and admitted the canonical record.
func AuthorizationPolicyEvent(plan *cerebrov1.SourceExecutionPlanV1, tenantID string, record *cerebrov1.SourceWorkerRecordV1) (*cerebrov1.EventEnvelope, error) {
	if plan == nil || record == nil || strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("%w: Rust-admitted event inputs are incomplete", ErrInvalidExecution)
	}
	return &cerebrov1.EventEnvelope{
		Id: record.GetEventId(), TenantId: strings.TrimSpace(tenantID), SourceId: plan.GetSourceId(),
		Kind: plan.GetEventKind(), SchemaRef: plan.GetSchemaRef(), Payload: record.GetPayloadJson(),
		Attributes: record.GetAttributes(), OccurredAt: timestamppb.New(time.UnixMilli(record.GetOccurredAtUnixMillis()).UTC()),
	}, nil
}

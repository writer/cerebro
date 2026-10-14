package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// SourceProjectionRejectedCategory is the error category used when a rejected
// record carries no usable projector error code.
const SourceProjectionRejectedCategory = "projection_record_rejected"

const maxSourceProjectionCategoryBytes = 64

// SourceProjectionDeadLetter builds the pending recovery record for an event
// that is already in the append log but whose projection was rejected. The ID
// is stable for the same runtime, event, and payload so a retried sync updates
// the existing pending record instead of adding another one.
func SourceProjectionDeadLetter(event *cerebrov1.EventEnvelope, projectionErr error) (ports.AppendLogDeadLetter, error) {
	if event == nil {
		return ports.AppendLogDeadLetter{}, errors.New("event is required")
	}
	payload, hash, err := deterministicEventPayload(event)
	if err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	eventID := strings.TrimSpace(event.GetId())
	if eventID == "" {
		eventID = "sha256:" + hash
	}
	identityHash, err := sourceProjectionIdentityHash(event)
	if err != nil {
		return ports.AppendLogDeadLetter{}, err
	}
	kind := strings.TrimSpace(event.GetKind())
	attrs := event.GetAttributes()
	runtimeID := strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID])
	category := SourceProjectionErrorCategory(projectionErr)
	return ports.AppendLogDeadLetter{
		ID:            sourceProjectionDeadLetterID(runtimeID, eventID, identityHash),
		Status:        ports.AppendLogDeadLetterStatusPending,
		Subject:       ports.AppendLogDeadLetterOperationSourceProjection + "." + kind,
		Operation:     ports.AppendLogDeadLetterOperationSourceProjection,
		EventID:       eventID,
		EventKind:     kind,
		TenantID:      strings.TrimSpace(event.GetTenantId()),
		SourceID:      strings.TrimSpace(event.GetSourceId()),
		RuntimeID:     runtimeID,
		JobID:         strings.TrimSpace(attrs[ports.EventAttributeJobID]),
		ErrorCategory: category,
		// The projector error can echo request fields or response bodies, so only
		// the bounded category is persisted.
		ErrorMessage: fmt.Sprintf("source projection rejected record; category=%s", category),
		RetryCount:   1,
		MaxAttempts:  1,
		PayloadHash:  hash,
		PayloadBytes: len(payload),
		Event:        proto.Clone(event).(*cerebrov1.EventEnvelope),
	}, nil
}

// SourceProjectionErrorCategory returns the projector's error code when it is a
// short machine token, or SourceProjectionRejectedCategory otherwise.
func SourceProjectionErrorCategory(err error) string {
	var coder ports.SourceProjectionErrorCoder
	if !errors.As(err, &coder) || coder == nil {
		return SourceProjectionRejectedCategory
	}
	code := strings.TrimSpace(coder.ProjectionErrorCode())
	if code == "" || len(code) > maxSourceProjectionCategoryBytes {
		return SourceProjectionRejectedCategory
	}
	for _, character := range code {
		switch {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '_', character == '.', character == '-':
		default:
			return SourceProjectionRejectedCategory
		}
	}
	return code
}

// sourceProjectionIdentityHash ignores the per-run collection ID, which changes
// on every sync attempt even when the provider record is identical.
func sourceProjectionIdentityHash(event *cerebrov1.EventEnvelope) (string, error) {
	if _, ok := event.GetAttributes()[ports.EventAttributeSourceCollectionID]; !ok {
		_, hash, err := deterministicEventPayload(event)
		return hash, err
	}
	identity := proto.Clone(event).(*cerebrov1.EventEnvelope)
	delete(identity.Attributes, ports.EventAttributeSourceCollectionID)
	_, hash, err := deterministicEventPayload(identity)
	return hash, err
}

func sourceProjectionDeadLetterID(runtimeID string, eventID string, payloadHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		ports.AppendLogDeadLetterOperationSourceProjection,
		strings.TrimSpace(runtimeID),
		strings.TrimSpace(eventID),
		strings.TrimSpace(payloadHash),
	}, "\x00")))
	return "apdl_" + hex.EncodeToString(sum[:16])
}

package sourcecdk

import (
	"context"
	"strings"
)

type operationContextKey struct{}

// OperationContext carries bounded source operation labels.
type OperationContext struct {
	SourceID  string
	Family    string
	Operation string
}

// AnnotateOperation returns a context carrying bounded source operation labels.
func AnnotateOperation(ctx context.Context, op OperationContext) context.Context {
	return context.WithValue(ctx, operationContextKey{}, normalizeOperationContext(op))
}

// OperationFromContext returns bounded source operation labels from ctx.
func OperationFromContext(ctx context.Context) (OperationContext, bool) {
	op, ok := ctx.Value(operationContextKey{}).(OperationContext)
	return op, ok
}

// PullStats summarizes a source pull without exposing provider identifiers.
type PullStats struct {
	Events               int
	HasCheckpoint        bool
	HasNextCursor        bool
	ShortCircuitReason   PullShortCircuitReason
	ReconciliationReason PullReconciliationReason
}

// PullStatistics returns bounded counts and flags for source observability.
func PullStatistics(pull Pull) PullStats {
	return PullStats{
		Events:               len(pull.Events),
		HasCheckpoint:        pull.Checkpoint != nil,
		HasNextCursor:        pull.NextCursor != nil,
		ShortCircuitReason:   pull.ShortCircuitReason,
		ReconciliationReason: pull.ReconciliationReason,
	}
}

func normalizeOperationContext(op OperationContext) OperationContext {
	return OperationContext{
		SourceID:  strings.TrimSpace(op.SourceID),
		Family:    strings.TrimSpace(op.Family),
		Operation: strings.TrimSpace(op.Operation),
	}
}

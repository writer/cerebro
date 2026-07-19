package ports

import (
	"context"
	"time"
)

const (
	SourceRuntimeQuarantineStateCaptured  = "captured"
	SourceRuntimeQuarantineStatePending   = "pending"
	SourceRuntimeQuarantineStateResolved  = "resolved"
	SourceRuntimeQuarantineStateDiscarded = "discarded"
)

// SourceRuntimeQuarantineRecord is a safe durable view of one rejected event.
// The original event payload remains inside the store.
type SourceRuntimeQuarantineRecord struct {
	ID                       string
	RuntimeID                string
	SourceID                 string
	TenantID                 string
	EventID                  string
	EventKind                string
	EventSHA256              string
	FailureCategory          string
	FailureField             string
	State                    string
	OccurrenceCount          uint64
	FirstObservedAt          time.Time
	LastObservedAt           time.Time
	OccurredAt               time.Time
	AdmissionABIVersion      uint32
	AdmissionContractsSHA256 string
	AdmissionResultSHA256    string
}

// SourceRuntimeQuarantineFilter scopes durable quarantine reads.
type SourceRuntimeQuarantineFilter struct {
	TenantID  string
	RuntimeID string
	State     string
	Limit     uint32
}

// SourceRuntimeQuarantineStore lists durable quarantine records without
// returning stored event payloads.
type SourceRuntimeQuarantineStore interface {
	ListSourceRuntimeQuarantines(context.Context, SourceRuntimeQuarantineFilter) ([]SourceRuntimeQuarantineRecord, error)
}

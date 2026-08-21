// Package sourceworker owns the credential and egress boundary around the
// capability-free Rust source worker.
package sourceworker

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	maxResponseBytes = uint64(8 << 20)
	executionTimeout = 30 * time.Second
	workerOverhead   = int64(64 << 10)
)

var (
	// ErrInvalidExecution means the plan, scope, worker output, or provider
	// response crossed a fail-closed execution boundary.
	ErrInvalidExecution = errors.New("invalid source worker execution")
	// ErrCredentialUnavailable means the trusted host could not redeem the
	// opaque credential reference for this operation.
	ErrCredentialUnavailable = errors.New("source worker credential unavailable")
)

// Worker plans and decodes one bounded request without receiving credentials
// or owning network access.
type Worker interface {
	Plan(context.Context, *cerebrov1.SourceExecutionPlanV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error)
	Decode(context.Context, *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error)
}

// CredentialScope binds one redemption to a runtime lease and logical page.
type CredentialScope struct {
	TenantID            string
	RuntimeID           string
	SourceID            string
	FamilyID            string
	PlanDigestSHA256    string
	LogicalPageID       string
	RequestIntentDigest string
	LeaseOwner          string
	RuntimeGeneration   uint64
	LeaseGeneration     uint64
	LeaseExpiresAt      time.Time
}

// CredentialLease exposes one bearer token to the trusted Go host only.
// BearerToken must return a caller-owned byte slice so the host can clear it.
type CredentialLease interface {
	BearerToken() []byte
	OperationID() string
	ExpiresAt() time.Time
	Close() error
}

// CredentialRedeemer resolves an opaque reference inside the trusted host.
type CredentialRedeemer interface {
	Redeem(context.Context, string, CredentialScope) (CredentialLease, error)
}

// ExecutionInput binds a compiled plan and credential reference to one fenced
// logical page.
type ExecutionInput struct {
	Plan                *cerebrov1.SourceExecutionPlanV1
	CredentialReference string
	Scope               CredentialScope
}

// SafeReceipt contains provider-safe execution evidence and no response body,
// credential, authorization header, or private route.
type SafeReceipt struct {
	PlanDigestSHA256    string
	LogicalPageID       string
	RequestIntentDigest string
	RuntimeGeneration   uint64
	LeaseGeneration     uint64
	CredentialOperation string
	StatusCode          int
	ResponseBytes       int
	ResponseSHA256      string
}

// ExecutionOutput contains the bounded worker result and safe host receipt.
type ExecutionOutput struct {
	Result  *cerebrov1.SourceWorkerDecodeResultV1
	Receipt SafeReceipt
}

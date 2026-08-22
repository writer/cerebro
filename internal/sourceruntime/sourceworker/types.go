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
	ErrCredentialUnavailable     = errors.New("source worker credential unavailable")
	ErrProviderAuthentication    = errors.New("provider authentication failed; refresh the Azure credential reference")
	ErrProviderPermission        = errors.New("provider permission denied; grant the Azure Graph authorization policy permission")
	ErrProviderRateLimited       = errors.New("provider rate limited the request; retry after the provider backoff window")
	ErrProviderTimeout           = errors.New("provider request timed out; retry the bounded operation")
	ErrProviderEgress            = errors.New("provider egress failed; verify public DNS and outbound HTTPS access")
	ErrProviderResponseTooLarge  = errors.New("provider response exceeded the compiled bound; reduce the provider response")
	ErrProviderMalformedResponse = errors.New("provider response was malformed; verify the Azure Graph response contract")
	ErrWorkerContract            = errors.New("source worker contract validation failed; regenerate the compiled plan and worker protocol")
	ErrWorkerUnsupported         = errors.New("source family is not Rust-authoritative")
	ErrWorkerInternal            = errors.New("source worker failed internally; inspect the bounded worker error class")
)

// Worker plans and decodes one bounded request without receiving credentials
// or owning network access.
type Worker interface {
	Compile(context.Context, SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error)
	Context(context.Context, ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error)
	Plan(context.Context, *cerebrov1.SourceWorkerPlanRequestV1) (*cerebrov1.SourceWorkerHTTPRequestV1, error)
	Decode(context.Context, *cerebrov1.SourceWorkerDecodeRequestV1) (*cerebrov1.SourceWorkerDecodeResultV1, error)
	Transition(context.Context, LifecycleRequest) (*LifecycleDecision, error)
}

// SelectionRequest is the private bridge input to Rust's closed registry.
type SelectionRequest struct {
	SourceID string `json:"source_id"`
	FamilyID string `json:"family_id"`
}

// ContextRequest contains trusted identity and generation inputs only.
type ContextRequest struct {
	TenantID             string `json:"tenant_id"`
	RuntimeID            string `json:"runtime_id"`
	PriorCursor          string `json:"prior_cursor"`
	PageNumber           uint32 `json:"page_number"`
	RuntimeGeneration    uint64 `json:"runtime_generation"`
	LeaseGeneration      uint64 `json:"lease_generation"`
	ObservedAtUnixMillis int64  `json:"observed_at_unix_millis"`
}

// Phase is the closed Rust-owned durable page lifecycle.
type Phase uint32

const (
	PhaseDecoded Phase = iota + 1
	PhaseAppended
	PhaseProjected
	PhaseCheckpointed
	PhaseComplete
)

// LifecycleRequest reports one completed side effect to Rust.
type LifecycleRequest struct {
	Plan                   *cerebrov1.SourceExecutionPlanV1
	Context                *cerebrov1.SourceWorkerExecutionContextV1
	Receipt                *cerebrov1.SourceWorkerSafeReceiptV1
	Result                 *cerebrov1.SourceWorkerDecodeResultV1
	CompletedPhase         Phase
	PriorTransitionDigest  string
	CurrentLeaseGeneration uint64
}

// LifecycleDecision is the only authority for the next Go side effect.
type LifecycleDecision struct {
	RequiredPhase                 Phase
	TransitionDigest              string
	AdmittedRecords               []*cerebrov1.SourceWorkerRecordV1
	CheckpointCursor              string
	CheckpointWatermarkUnixMillis int64
}

// CredentialScope binds one redemption to a runtime lease and logical page.
type CredentialScope struct {
	TenantID             string
	RuntimeID            string
	SourceID             string
	FamilyID             string
	PlanDigestSHA256     string
	LogicalPageID        string
	PriorCursor          string
	RequestIntentDigest  string
	LeaseOwner           string
	RuntimeGeneration    uint64
	LeaseGeneration      uint64
	LeaseExpiresAt       time.Time
	ObservedAtUnixMillis int64
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
	SourceID            string
	FamilyID            string
	CredentialReference string
	Scope               CredentialScope
	PageNumber          uint32
}

// ExecutionOutput contains the bounded worker result and safe host receipt.
type ExecutionOutput struct {
	Plan     *cerebrov1.SourceExecutionPlanV1
	Context  *cerebrov1.SourceWorkerExecutionContextV1
	Receipt  *cerebrov1.SourceWorkerSafeReceiptV1
	Result   *cerebrov1.SourceWorkerDecodeResultV1
	Decision *LifecycleDecision
}

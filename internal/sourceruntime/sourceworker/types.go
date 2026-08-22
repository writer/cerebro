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

	ErrSourceConfiguration        = errors.New("source configuration is incomplete; repair the public source configuration")
	ErrCredentialReferenceMissing = errors.New("source credential reference is missing; repair the credential binding")

	// ErrCredentialUnavailable means the trusted host could not redeem the
	// opaque credential reference for this operation.
	ErrCredentialUnavailable     = errors.New("source credential is unavailable; repair the credential binding or provider access")
	ErrProviderAuthentication    = errors.New("provider authentication failed; repair the provider credential binding")
	ErrProviderPermission        = errors.New("provider permission denied; grant the required provider scope")
	ErrProviderRateLimited       = errors.New("provider rate limited the request; retry after the provider backoff window")
	ErrProviderTimeout           = errors.New("provider request timed out; retry the bounded operation")
	ErrProviderEgress            = errors.New("provider egress failed; verify public DNS and outbound HTTPS access")
	ErrProviderResponseTooLarge  = errors.New("provider response exceeded the compiled bound; reduce the provider response")
	ErrProviderUnexpectedStatus  = errors.New("provider returned an unexpected status; inspect the bounded provider response")
	ErrProviderMalformedResponse = errors.New("provider response was malformed; verify the provider response contract")
	ErrWorkerResultTooLarge      = errors.New("source worker result exceeded the shared bound; reduce the normalized result")
	ErrWorkerAppend              = errors.New("source append failed; retry after restoring durable append availability")
	ErrWorkerProjection          = errors.New("source projection failed; retry after restoring projection availability")
	ErrWorkerLeaseLost           = errors.New("source worker lease was lost; restart collection under the current lease")
	ErrWorkerStaleAuthority      = errors.New("source writer authority changed; restart collection under the current authority")
	ErrWorkerContract            = errors.New("source worker contract validation failed; regenerate the compiled plan and worker protocol")
	ErrWorkerUnsupported         = errors.New("source family is not Rust-authoritative")
	ErrWorkerInternal            = errors.New("source worker failed internally; inspect the bounded worker error class")
)

// Worker plans and decodes one bounded request without receiving credentials
// or owning network access.
type Worker interface {
	Compile(context.Context, SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error)
	Context(context.Context, ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error)
	PlanV2(context.Context, *cerebrov1.SourceWorkerPlanEnvelopeV2) (*cerebrov1.SourceWorkerHTTPExecutionV2, error)
	DecodeV2(context.Context, *cerebrov1.SourceWorkerDecodeEnvelopeV2) (*cerebrov1.SourceWorkerDecodeOutputV2, error)
	SealPage(context.Context, PageProgramRequest) (*PageProgram, error)
}

// SelectionRequest is the private bridge input to Rust's closed registry.
type SelectionRequest struct {
	SourceID string `json:"source_id"`
	FamilyID string `json:"family_id"`
}

// ContextRequest contains trusted identity and generation inputs only.
type ContextRequest struct {
	TenantID                         string            `json:"tenant_id"`
	RuntimeID                        string            `json:"runtime_id"`
	PriorCursor                      string            `json:"prior_cursor"`
	PageNumber                       uint32            `json:"page_number"`
	RuntimeGeneration                uint64            `json:"runtime_generation"`
	LeaseGeneration                  uint64            `json:"lease_generation"`
	ObservedAtUnixMillis             int64             `json:"observed_at_unix_millis"`
	PublicConfig                     map[string]string `json:"public_config,omitempty"`
	PriorTerminalWatermarkUnixMillis int64             `json:"prior_terminal_watermark_unix_millis,omitempty"`
	PriorCheckpoint                  string            `json:"prior_checkpoint,omitempty"`
}

type PageProgramRequest struct {
	Plan                   *cerebrov1.SourceExecutionPlanV1
	Context                *cerebrov1.SourceWorkerExecutionContextV1
	Receipt                *cerebrov1.SourceWorkerSafeReceiptV1
	Result                 *cerebrov1.SourceWorkerDecodeResultV1
	CurrentLeaseGeneration uint64
	Metadata               *cerebrov1.SourceWorkerRuntimeMetadataV2
}

type PageProgram struct {
	TransitionDigest              string
	AdmittedRecords               []*cerebrov1.SourceWorkerRecordV1
	CheckpointCursor              string
	CheckpointWatermarkUnixMillis int64
}

// CredentialScope binds one redemption to a runtime lease and logical page.
type CredentialScope struct {
	TenantID                         string
	RuntimeID                        string
	SourceID                         string
	FamilyID                         string
	PlanDigestSHA256                 string
	LogicalPageID                    string
	PriorCursor                      string
	PublicConfig                     map[string]string
	PriorTerminalWatermarkUnixMillis int64
	PriorCheckpoint                  string
	LeaseOwner                       string
	RuntimeGeneration                uint64
	LeaseGeneration                  uint64
	LeaseExpiresAt                   time.Time
	ObservedAtUnixMillis             int64
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
	Plan    *cerebrov1.SourceExecutionPlanV1
	Context *cerebrov1.SourceWorkerExecutionContextV1
	Receipt *cerebrov1.SourceWorkerSafeReceiptV1
	Result  *cerebrov1.SourceWorkerDecodeResultV1
	Program *PageProgram
}

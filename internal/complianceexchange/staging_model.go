package complianceexchange

import (
	"context"
	"errors"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	StagingStatusStaged              = "staged"
	StagingStatusValid               = "valid"
	StagingStatusInvalid             = "invalid"
	StagingStatusCommitEventAppended = "commit_event_appended"

	CommitIntentAwaitingAuthorization = "awaiting_authorization"
	CommitIntentEventAppended         = "event_appended"

	ComplianceExchangeCommitScope = "cerebro.compliance.exchange.commit"
)

var (
	ErrStagingInvalid       = errors.New("invalid compliance exchange staging request")
	ErrStagingNotFound      = errors.New("compliance exchange staging record not found")
	ErrStagingExpired       = errors.New("compliance exchange staging record expired")
	ErrStagingVersion       = errors.New("compliance exchange staging version conflict")
	ErrStagingDigest        = errors.New("compliance exchange staging digest conflict")
	ErrValidationNotFound   = errors.New("compliance exchange validation replay not found")
	ErrCommitIntentNotFound = errors.New("compliance exchange commit intent not found")
	ErrCommitAuthorization  = errors.New("compliance exchange commit authorization required")
	ErrAppendBoundary       = errors.New("compliance exchange append boundary required")
)

// StagingLimits bound bytes retained in Postgres and the maximum lifetime of a
// staged import. These are intentionally independent from archive validation
// limits.
type StagingLimits struct {
	MaxStagedBytes int64
	MaxTTL         time.Duration
}

func DefaultStagingLimits() StagingLimits {
	return StagingLimits{MaxStagedBytes: 64 << 20, MaxTTL: 24 * time.Hour}
}

type StagePackageRequest struct {
	TenantID       string
	IdempotencyKey string
	Package        Package
	ExpiresAt      time.Time
	Limits         StagingLimits
}

// StagedPackage is tenant-scoped import state. Files remain staging data in
// Postgres and are never projected into canonical domain tables by this API.
type StagedPackage struct {
	ID                            string
	TenantID                      string
	PackageID                     string
	ManifestDigest                string
	PackageDigest                 string
	IdempotencyKey                string
	ManifestBytes                 []byte
	Signature                     string
	Files                         []File
	FileCount                     int
	TotalBytes                    int64
	StagedBytes                   int64
	Status                        string
	Version                       uint64
	LatestValidationRequestDigest string
	ChangePlanDigest              string
	SignerKeyID                   string
	Algorithm                     string
	ExpiresAt                     time.Time
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
	ValidatedAt                   time.Time
}

type ValidateStagedRequest struct {
	TenantID               string
	StagingID              string
	ExpectedStagingVersion uint64
	PolicyVersion          string
	Limits                 Limits
	Trust                  TrustResolver
}

type SignatureReceipt struct {
	ManifestDigest  string    `json:"manifest_digest"`
	SignatureDigest string    `json:"signature_digest"`
	SignerKeyID     string    `json:"signer_key_id"`
	Algorithm       string    `json:"algorithm"`
	VerifiedAt      time.Time `json:"verified_at"`
}

type StagedValidation struct {
	TenantID         string
	StagingID        string
	RequestDigest    string
	StagingVersion   uint64
	Status           string
	Result           ValidationResult
	Signature        *SignatureReceipt
	ChangePlanDigest string
	ValidatedAt      time.Time
	Replayed         bool
}

type CreateCommitIntentRequest struct {
	TenantID               string
	StagingID              string
	ExpectedStagingVersion uint64
	IdempotencyKey         string
	RequestedBy            string
}

type CommitIntent struct {
	ID                      string
	TenantID                string
	StagingID               string
	ExpectedStagingVersion  uint64
	ChangePlanDigest        string
	IntentDigest            string
	IdempotencyKey          string
	RequiredScope           string
	Status                  string
	Version                 uint64
	RequestedBy             string
	AuthorizedBy            string
	AuthorizationDecisionID string
	AuthorizedAt            time.Time
	EventID                 string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type AuthorizationReceipt struct {
	ActorID    string
	DecisionID string
	Scope      string
	GrantedAt  time.Time
}

type AppendCommitIntentRequest struct {
	TenantID               string
	IntentID               string
	ExpectedIntentVersion  uint64
	ExpectedStagingVersion uint64
	Authorization          AuthorizationReceipt
}

// StagingStore owns only import staging state. It exposes no canonical domain
// mutation method, so validation cannot write programs, assessments, or work.
type StagingStore interface {
	PutStagedPackage(context.Context, StagedPackage) (StagedPackage, bool, error)
	GetStagedPackage(context.Context, string, string) (StagedPackage, error)
	GetStagedValidation(context.Context, string, string, string) (StagedValidation, error)
	PutStagedValidation(context.Context, StagedValidation, uint64) (StagedValidation, bool, error)
	PutCommitIntent(context.Context, CommitIntent) (CommitIntent, bool, error)
	GetCommitIntent(context.Context, string, string) (CommitIntent, error)
	MarkCommitIntentEventAppended(context.Context, CommitIntent, AuthorizationReceipt, string) (CommitIntent, error)
}

// StagingService coordinates validation and the append-only commit boundary.
// Canonical state changes are left to a later event projector.
type StagingService struct {
	store     StagingStore
	appendLog ports.AppendLog
	now       func() time.Time
}

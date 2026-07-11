// Package complianceread serves exact, tenant-scoped compliance revisions.
package complianceread

import (
	"context"
	"errors"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var (
	ErrNotFound       = errors.New("compliance revision not found")
	ErrInvalidRequest = errors.New("invalid compliance read request")
	ErrInvalidCursor  = errors.New("invalid compliance read cursor")
)

const (
	DefaultPageSize uint32 = 50
	MaxPageSize     uint32 = 200
)

// Keyset identifies the last immutable revision in a page. The transport
// encodes it as an opaque cursor; repositories receive only validated fields.
type Keyset struct {
	LastModified time.Time
	ID           string
	RevisionID   string
}

type Page struct {
	After *Keyset
	Limit uint32
}

// TenantRecord keeps tenant ownership next to the generated response message
// so the handler can fail closed if a repository returns a foreign record.
type TenantRecord[T any] struct {
	TenantID string
	Value    T
}

type PageResult[T any] struct {
	Records []TenantRecord[T]
	Next    *Keyset
}

// Repository is the current-state read capability required to register the
// generated ComplianceReadService. Implementations must apply the supplied
// tenant and keyset in their storage query; the handler verifies ownership
// again before returning records.
type Repository interface {
	ListCompliancePrograms(context.Context, string, *cerebrov1.ListComplianceProgramsRequest, Page) (PageResult[*cerebrov1.ComplianceProgram], error)
	GetComplianceProgram(context.Context, string, string, string) (TenantRecord[*cerebrov1.ComplianceProgram], error)
	ListControlImplementations(context.Context, string, *cerebrov1.ListControlImplementationsRequest, Page) (PageResult[*cerebrov1.ControlImplementation], error)
	GetControlImplementation(context.Context, string, string, string) (TenantRecord[*cerebrov1.ControlImplementation], error)
	ListEvidenceArtifactMetadata(context.Context, string, *cerebrov1.ListEvidenceArtifactMetadataRequest, Page) (PageResult[*cerebrov1.EvidenceArtifactMetadata], error)
	GetEvidenceArtifactMetadata(context.Context, string, string, string) (TenantRecord[*cerebrov1.EvidenceArtifactMetadata], error)
	ListAssessmentPlans(context.Context, string, *cerebrov1.ListAssessmentPlansRequest, Page) (PageResult[*cerebrov1.AssessmentPlan], error)
	GetAssessmentPlan(context.Context, string, string, string) (TenantRecord[*cerebrov1.AssessmentPlan], error)
	ListAssessmentRuns(context.Context, string, *cerebrov1.ListAssessmentRunsRequest, Page) (PageResult[*cerebrov1.AssessmentRun], error)
	GetAssessmentRun(context.Context, string, string, string) (TenantRecord[*cerebrov1.AssessmentRun], error)
	ListAssessmentResults(context.Context, string, *cerebrov1.ListAssessmentResultsRequest, Page) (PageResult[*cerebrov1.AssessmentResult], error)
	GetAssessmentResult(context.Context, string, string, string) (TenantRecord[*cerebrov1.AssessmentResult], error)
	ListAssessmentReviews(context.Context, string, *cerebrov1.ListAssessmentReviewsRequest, Page) (PageResult[*cerebrov1.AssessmentReview], error)
	GetAssessmentReview(context.Context, string, string, string) (TenantRecord[*cerebrov1.AssessmentReview], error)
	ListComplianceWorkItems(context.Context, string, *cerebrov1.ListComplianceWorkItemsRequest, Page) (PageResult[*cerebrov1.ComplianceWorkItem], error)
	GetComplianceWorkItem(context.Context, string, string, string) (TenantRecord[*cerebrov1.ComplianceWorkItem], error)
}

// StateStore is the minimum composition-root capability used for optional
// repository discovery.
type StateStore interface {
	Ping(context.Context) error
}

// RepositoryFrom returns the optional compliance read capability exposed by a
// composed state store.
func RepositoryFrom(value StateStore) Repository {
	repository, _ := value.(Repository)
	return repository
}

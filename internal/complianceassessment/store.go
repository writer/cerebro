package complianceassessment

import "context"

type Store interface {
	ApplyPlan(context.Context, string, AssessmentPlanRevision, uint64) error
	GetPlan(context.Context, string, string) (AssessmentPlanRevision, error)
	ApplyRun(context.Context, string, AssessmentRun, uint64) error
	GetRun(context.Context, string, string) (AssessmentRun, error)
	FindRunByIdempotency(context.Context, string, string) (AssessmentRun, error)
	ListUnboundRuns(context.Context, uint32) ([]AssessmentRun, error)
	ApplyResultChunk(context.Context, string, string, ResultChunk) error
	ListResultChunks(context.Context, string, string) ([]ResultChunk, error)
}

// NonterminalRunStore lists persisted runs whose bound job may need
// reconciliation after an interrupted or failed worker attempt.
type NonterminalRunStore interface {
	ListNonterminalRuns(context.Context, uint32) ([]AssessmentRun, error)
}

type Collector interface {
	Collect(context.Context, AssessmentRun) (InputManifest, []ObjectiveResult, error)
}

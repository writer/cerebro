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

// AssuranceDecisionStore is the durable read projection for immutable
// evidence-backed decisions. It remains a separate capability so assessment
// collection stores cannot silently claim decision persistence support.
type AssuranceDecisionStore interface {
	ApplyAssuranceDecision(context.Context, string, AssuranceDecision) error
	GetAssuranceDecision(context.Context, string, string) (AssuranceDecision, error)
	FindAssuranceDecisionByIdempotency(context.Context, string, string) (AssuranceDecision, error)
}

// AssessmentSnapshotStore projects immutable snapshot commitments and exposes
// the decision set needed to verify governed views at the recorded cutoff.
type AssessmentSnapshotStore interface {
	ApplyAssessmentSnapshot(context.Context, string, AssessmentSnapshot) error
	GetAssessmentSnapshot(context.Context, string, string) (AssessmentSnapshot, error)
	FindAssessmentSnapshotByIdempotency(context.Context, string, string) (AssessmentSnapshot, error)
	ListAssuranceDecisionsByRun(context.Context, string, string) ([]AssuranceDecision, error)
}

package ports

import "context"

// GRCDashboardAggregateRequest scopes aggregate counts needed by the GRC dashboard.
type GRCDashboardAggregateRequest struct {
	FindingRequest  ListFindingsRequest
	EvidenceRequest ListFindingEvidenceRequest
}

// GRCDashboardAggregate contains dashboard summary counts fetched without row payloads.
type GRCDashboardAggregate struct {
	FindingSummary            FindingSummary
	EvidenceCount             int
	EvidenceCountsByFindingID map[string]int
}

// GRCDashboardAggregateStore provides a purpose-built aggregate path for the GRC dashboard.
type GRCDashboardAggregateStore interface {
	StateStore
	SummarizeGRCDashboard(context.Context, GRCDashboardAggregateRequest) (GRCDashboardAggregate, error)
}

package ports

import (
	"context"
	"time"
)

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

// GRCFindingTrendsRequest scopes the time-bucketed finding trend aggregation.
// Trends are derived from current-state finding timestamps: findings are
// bucketed as opened by first_observed_at and as closed by status_updated_at
// for non-open rows. Interval must be one of "day", "week", or "month".
type GRCFindingTrendsRequest struct {
	FindingRequest ListFindingsRequest
	Start          time.Time
	End            time.Time
	Interval       string
}

// GRCFindingTrendPoint holds one bucket of finding flow counts.
type GRCFindingTrendPoint struct {
	BucketStart    time.Time
	Opened         int
	OpenedCritical int
	OpenedHigh     int
	Closed         int
}

// GRCFindingTrends is the bucketed trend series plus the open backlog at the
// window start, which lets callers reconstruct a running open total.
type GRCFindingTrends struct {
	Points      []GRCFindingTrendPoint
	OpenAtStart int
}

// GRCFindingTrendsStore provides a purpose-built time-bucketed trend aggregation.
type GRCFindingTrendsStore interface {
	StateStore
	SummarizeGRCFindingTrends(context.Context, GRCFindingTrendsRequest) (GRCFindingTrends, error)
}

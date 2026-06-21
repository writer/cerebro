package ports

import (
	"context"
	"time"
)

// Finding triage dispositions overlay operator decisions on projected findings.
const (
	GRCFindingDispositionOpen          = "open"
	GRCFindingDispositionInTriage      = "in_triage"
	GRCFindingDispositionRiskAccepted  = "risk_accepted"
	GRCFindingDispositionFalsePositive = "false_positive"
	GRCFindingDispositionResolved      = "resolved"
)

// IsGRCFindingDisposition reports whether value is a known finding disposition.
func IsGRCFindingDisposition(value string) bool {
	switch value {
	case GRCFindingDispositionOpen,
		GRCFindingDispositionInTriage,
		GRCFindingDispositionRiskAccepted,
		GRCFindingDispositionFalsePositive,
		GRCFindingDispositionResolved:
		return true
	default:
		return false
	}
}

// GRCFindingDispositionRecord is an operator-set triage disposition for a finding.
type GRCFindingDispositionRecord struct {
	TenantID    string    `json:"tenant_id"`
	FindingID   string    `json:"finding_id"`
	Disposition string    `json:"disposition"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GRCFindingDispositionBulkUpdate applies one disposition to many findings in a tenant.
type GRCFindingDispositionBulkUpdate struct {
	TenantID    string
	FindingIDs  []string
	Disposition string
	UpdatedBy   string
}

// GRCFindingDispositionStore persists operator triage dispositions for findings.
type GRCFindingDispositionStore interface {
	StateStore
	UpsertGRCFindingDispositions(context.Context, GRCFindingDispositionBulkUpdate) ([]*GRCFindingDispositionRecord, error)
	ListGRCFindingDispositions(ctx context.Context, tenantID string, findingIDs []string) ([]*GRCFindingDispositionRecord, error)
}

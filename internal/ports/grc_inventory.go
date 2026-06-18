package ports

import (
	"context"
	"errors"
	"strings"
	"time"
)

const (
	GRCInventoryScopeStateIn  = "in_scope"
	GRCInventoryScopeStateOut = "out_of_scope"

	GRCInventoryAssetReportStatusSubmitted = "submitted"
	GRCInventoryAssetReportStatusInTriage  = "in_triage"
	GRCInventoryAssetReportStatusAccepted  = "accepted"
	GRCInventoryAssetReportStatusRejected  = "rejected"
	GRCInventoryAssetReportStatusResolved  = "resolved"
)

var ErrGRCInventoryAssetReportNotFound = errors.New("grc inventory asset report not found")

type GRCInventoryScopeRecord struct {
	TenantID   string            `json:"tenant_id"`
	AssetURN   string            `json:"asset_urn"`
	SourceID   string            `json:"source_id,omitempty"`
	ScopeState string            `json:"scope_state"`
	Reason     string            `json:"reason,omitempty"`
	UpdatedBy  string            `json:"updated_by,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type GRCInventoryScopeFilter struct {
	TenantID   string
	AssetURNs  []string
	SourceID   string
	ScopeState string
	Limit      uint32
}

type GRCInventoryAccountabilityUpdate struct {
	TenantID        string
	AssetURN        string
	SourceID        string
	UpdatedBy       string
	SetAttributes   map[string]string
	ClearAttributes []string
}

type GRCInventoryScopeStore interface {
	StateStore
	UpsertGRCInventoryScope(context.Context, GRCInventoryScopeRecord) (*GRCInventoryScopeRecord, error)
	UpdateGRCInventoryAccountability(context.Context, GRCInventoryAccountabilityUpdate) (*GRCInventoryScopeRecord, error)
	ListGRCInventoryScopes(context.Context, GRCInventoryScopeFilter) ([]*GRCInventoryScopeRecord, error)
}

type GRCInventoryAssetReportRecord struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	AssetURN     string            `json:"asset_urn"`
	SourceID     string            `json:"source_id,omitempty"`
	Reason       string            `json:"reason"`
	Reporter     string            `json:"reporter,omitempty"`
	TriageStatus string            `json:"triage_status"`
	TriageReason string            `json:"triage_reason,omitempty"`
	TriagedBy    string            `json:"triaged_by,omitempty"`
	TriagedAt    *time.Time        `json:"triaged_at,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

type GRCInventoryAssetReportFilter struct {
	TenantID     string
	AssetURNs    []string
	SourceID     string
	TriageStatus string
	Limit        uint32
}

type GRCInventoryAssetReportTriageUpdate struct {
	ID           string
	TenantID     string
	TriageStatus string
	TriageReason string
	TriagedBy    string
}

type GRCInventoryAssetReportSummary struct {
	AssetURN     string
	ReportCount  int
	TriageStatus string
	Reason       string
	UpdatedAt    time.Time
}

type GRCInventoryAssetReportStore interface {
	StateStore
	CreateGRCInventoryAssetReport(context.Context, GRCInventoryAssetReportRecord) (*GRCInventoryAssetReportRecord, error)
	GetGRCInventoryAssetReport(context.Context, string, string) (*GRCInventoryAssetReportRecord, error)
	ListGRCInventoryAssetReports(context.Context, GRCInventoryAssetReportFilter) ([]*GRCInventoryAssetReportRecord, error)
	SummarizeGRCInventoryAssetReports(context.Context, GRCInventoryAssetReportFilter) ([]*GRCInventoryAssetReportSummary, error)
	UpdateGRCInventoryAssetReportTriage(context.Context, GRCInventoryAssetReportTriageUpdate) (*GRCInventoryAssetReportRecord, error)
}

func IsGRCInventoryAssetReportStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case GRCInventoryAssetReportStatusSubmitted,
		GRCInventoryAssetReportStatusInTriage,
		GRCInventoryAssetReportStatusAccepted,
		GRCInventoryAssetReportStatusRejected,
		GRCInventoryAssetReportStatusResolved:
		return true
	default:
		return false
	}
}

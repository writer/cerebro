package ports

import "context"

type VendorDiscoveryFilter struct {
	TenantID     string
	SourceID     string
	RuntimeIDs   []string
	Query        string
	SourceStatus string
	Limit        int
}

type VendorDiscoveryRow struct {
	URN               string                  `json:"urn"`
	DiscoveryID       string                  `json:"discovery_id,omitempty"`
	Name              string                  `json:"name"`
	NormalizedName    string                  `json:"normalized_name,omitempty"`
	SourceID          string                  `json:"source_id,omitempty"`
	RuntimeID         string                  `json:"runtime_id,omitempty"`
	Provider          string                  `json:"provider,omitempty"`
	SourceStatus      string                  `json:"source_status"`
	DecisionState     string                  `json:"decision_state"`
	Category          string                  `json:"category,omitempty"`
	WebsiteURL        string                  `json:"website_url,omitempty"`
	LinkedVendorURN   string                  `json:"linked_vendor_urn,omitempty"`
	DecisionReason    string                  `json:"decision_reason,omitempty"`
	DecisionUpdatedBy string                  `json:"decision_updated_by,omitempty"`
	DecisionUpdatedAt string                  `json:"decision_updated_at,omitempty"`
	Attributes        map[string]string       `json:"attributes,omitempty"`
	SourceIDs         []string                `json:"source_ids,omitempty"`
	ConfidenceScore   float64                 `json:"confidence_score,omitempty"`
	DiscoveryReason   string                  `json:"discovery_reason,omitempty"`
	FirstObservedAt   string                  `json:"first_observed_at,omitempty"`
	LastObservedAt    string                  `json:"last_observed_at,omitempty"`
	Signals           []VendorDiscoverySignal `json:"signals,omitempty"`
}

type VendorDiscoverySignal struct {
	ID              string            `json:"id"`
	Label           string            `json:"label"`
	SourceID        string            `json:"source_id,omitempty"`
	RuntimeID       string            `json:"runtime_id,omitempty"`
	EntityType      string            `json:"entity_type,omitempty"`
	EntityURN       string            `json:"entity_urn,omitempty"`
	ConfidenceScore float64           `json:"confidence_score,omitempty"`
	ObservedAt      string            `json:"observed_at,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

type VendorDiscoverySummary struct {
	TotalDiscoveries uint64 `json:"total_discoveries"`
	Discovered       uint64 `json:"discovered"`
	Approved         uint64 `json:"approved"`
	Rejected         uint64 `json:"rejected"`
	Ignored          uint64 `json:"ignored"`
	Linked           uint64 `json:"linked"`
	SourceCount      uint64 `json:"source_count"`
	EvidenceSignals  uint64 `json:"evidence_signals"`
}

type VendorDiscoverySourceSummary struct {
	SourceID       string `json:"source_id"`
	Provider       string `json:"provider,omitempty"`
	RuntimeID      string `json:"runtime_id,omitempty"`
	Status         string `json:"status,omitempty"`
	Freshness      string `json:"freshness,omitempty"`
	Total          uint64 `json:"total"`
	Discovered     uint64 `json:"discovered"`
	Approved       uint64 `json:"approved,omitempty"`
	Rejected       uint64 `json:"rejected,omitempty"`
	Ignored        uint64 `json:"ignored,omitempty"`
	Linked         uint64 `json:"linked,omitempty"`
	Failed         uint64 `json:"failed,omitempty"`
	Stale          uint64 `json:"stale,omitempty"`
	CursorPending  uint64 `json:"cursor_pending,omitempty"`
	SyncLagSeconds uint64 `json:"sync_lag_seconds,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	LastSyncedAt   string `json:"last_synced_at,omitempty"`
}

type VendorDiscoveryPage struct {
	TenantID        string                         `json:"-"`
	GraphRevision   uint64                         `json:"graph_revision"`
	DataAuthority   string                         `json:"data_authority"`
	GeneratedAt     string                         `json:"generated_at"`
	Discoveries     []VendorDiscoveryRow           `json:"discoveries"`
	Summary         VendorDiscoverySummary         `json:"summary"`
	SourceSummaries []VendorDiscoverySourceSummary `json:"source_summaries"`
}

type VendorDiscoveryRegisterStore interface {
	ListVendorDiscoveries(context.Context, VendorDiscoveryFilter) (*VendorDiscoveryPage, error)
}

package ports

import "context"

type VendorRegisterFilter struct {
	TenantID       string
	SourceID       string
	RuntimeIDs     []string
	Query          string
	RiskLevel      string
	ReviewState    string
	OwnerState     string
	LifecycleState string
	QueueOnly      bool
	Limit          int
}

type VendorRegisterAction struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type VendorRegisterIdentity struct {
	URN              string `json:"urn"`
	VendorID         string `json:"vendor_id,omitempty"`
	Name             string `json:"name"`
	SourceID         string `json:"source_id,omitempty"`
	RuntimeID        string `json:"runtime_id,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Status           string `json:"status,omitempty"`
	Category         string `json:"category,omitempty"`
	WebsiteURL       string `json:"website_url,omitempty"`
	ServicesProvided string `json:"services_provided,omitempty"`
	LifecycleState   string `json:"lifecycle_state"`
	Owner            string `json:"owner,omitempty"`
	OwnerState       string `json:"owner_state"`
}

type VendorRegisterAssessment struct {
	RiskLevel              string `json:"risk_level"`
	RiskScore              int32  `json:"risk_score,omitempty"`
	RiskScoreLevel         string `json:"risk_score_level,omitempty"`
	ReviewState            string `json:"review_state"`
	ReviewDueAt            string `json:"review_due_at,omitempty"`
	EvidenceFreshnessState string `json:"evidence_freshness_state"`
	PacketState            string `json:"packet_state,omitempty"`
}

type VendorRegisterSignals struct {
	ContractCount          uint64                 `json:"contract_count"`
	SecurityReviewCount    uint64                 `json:"security_review_count"`
	QuestionnaireCount     uint64                 `json:"questionnaire_count"`
	AssuranceDocumentCount uint64                 `json:"assurance_document_count"`
	OpenFindings           uint64                 `json:"open_findings"`
	CriticalFindings       uint64                 `json:"critical_findings"`
	HighFindings           uint64                 `json:"high_findings"`
	EvidenceItems          uint64                 `json:"evidence_items"`
	RiskQueueRank          int32                  `json:"risk_queue_rank,omitempty"`
	QueueReasons           []string               `json:"queue_reasons,omitempty"`
	NextActions            []VendorRegisterAction `json:"next_actions,omitempty"`
}

type VendorRegisterRow struct {
	VendorRegisterIdentity
	VendorRegisterAssessment
	VendorRegisterSignals
	Attributes map[string]string `json:"attributes,omitempty"`
}

type VendorRegisterSummary struct {
	TotalVendors         uint64 `json:"total_vendors"`
	ActiveVendors        uint64 `json:"active_vendors"`
	HighRiskVendors      uint64 `json:"high_risk_vendors"`
	OwnerMissingVendors  uint64 `json:"owner_missing_vendors"`
	ReviewOverdueVendors uint64 `json:"review_overdue_vendors"`
	ReviewDueSoonVendors uint64 `json:"review_due_soon_vendors"`
	ReviewNotScheduled   uint64 `json:"review_not_scheduled"`
	RiskQueueVendors     uint64 `json:"risk_queue_vendors"`
	StaleEvidenceVendors uint64 `json:"stale_evidence_vendors"`
	OpenFindings         uint64 `json:"open_findings"`
	CriticalFindings     uint64 `json:"critical_findings"`
	HighFindings         uint64 `json:"high_findings"`
	EvidenceItems        uint64 `json:"evidence_items"`
}

type VendorRegisterPage struct {
	TenantID      string                `json:"-"`
	GraphRevision uint64                `json:"graph_revision"`
	DataAuthority string                `json:"data_authority"`
	GeneratedAt   string                `json:"generated_at"`
	Vendors       []VendorRegisterRow   `json:"vendors"`
	Summary       VendorRegisterSummary `json:"summary"`
}

type VendorRegisterStore interface {
	ListVendorRegister(context.Context, VendorRegisterFilter) (*VendorRegisterPage, error)
}

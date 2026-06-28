package grcvendor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultVendorLimit = 100
	maxVendorLimit     = 500
	relatedLimit       = 50
	dueSoonDays        = 30

	OwnerStateAssigned = "assigned"
	OwnerStateMissing  = "missing"

	ReviewStateCurrent      = "current"
	ReviewStateDueSoon      = "due_soon"
	ReviewStateOverdue      = "overdue"
	ReviewStateNotScheduled = "not_scheduled"

	LifecycleStateDiscovered            = "discovered"
	LifecycleStateCandidate             = "candidate"
	LifecycleStateActive                = "active"
	LifecycleStateInReview              = "in_review"
	LifecycleStateApproved              = "approved"
	LifecycleStateConditionallyApproved = "conditionally_approved"
	LifecycleStateRestricted            = "restricted"
	LifecycleStateOffboarding           = "offboarding"
	LifecycleStateRetired               = "retired"
	LifecycleStateRejected              = "rejected"
	LifecycleStateIgnored               = "ignored"
	LifecycleStateUnknown               = "unknown"

	FreshnessStateCurrent = "current"
	FreshnessStateStale   = "stale"
	FreshnessStateExpired = "expired"
	FreshnessStateUnknown = "unknown"
	FreshnessStateMissing = "missing"

	DiscoveryStateDiscovered = "discovered"
	DiscoveryStateApproved   = ports.GRCVendorDiscoveryDecisionApproved
	DiscoveryStateRejected   = ports.GRCVendorDiscoveryDecisionRejected
	DiscoveryStateIgnored    = ports.GRCVendorDiscoveryDecisionIgnored
	DiscoveryStateLinked     = ports.GRCVendorDiscoveryDecisionLinked
)

var (
	ErrRuntimeUnavailable = errors.New("vendor risk runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid vendor risk request")
)

// Service reads the vendor GRC graph projection without owning a separate
// source, source-provider writer, or normalization path.
type Service struct {
	store ports.GraphQueryStore
	now   func() time.Time
}

type ListVendorsRequest struct {
	TenantID    string
	RuntimeID   string
	RuntimeIDs  []string
	SourceID    string
	Query       string
	RiskLevel   string
	ReviewState string
	OwnerState  string
	Lifecycle   string
	QueueOnly   bool
	DeferLimit  bool
	Limit       uint32
}

type VendorDetailRequest struct {
	URN        string
	VendorID   string
	TenantID   string
	RuntimeID  string
	RuntimeIDs []string
	SourceID   string
	Limit      uint32
}

type ListDiscoveriesRequest struct {
	TenantID      string
	RuntimeID     string
	RuntimeIDs    []string
	SourceID      string
	Query         string
	Status        string
	DecisionState string
	Limit         uint32
}

// Vendor is the canonical vendor row. Rows are anchored on
// Entity.entity_type='vendor'; vendor.discovery nodes, aliases, host IDs, and
// category tags are only supporting signals unless a source has already emitted
// them as vendor attributes. Field precedence is:
//   - vendor_id: vendor_id, external_id, URN tail
//   - name: graph label, name attribute, vendor_id, URN tail
//   - provider: source_system, provider, source_id
//   - website: website_url, website, url, domain
//   - owner: security_owner_user_id, business_owner_user_id
//   - risk_level: residual_risk_level, inherent_risk_level, risk_level, unknown
//
// Evidence freshness is not inferred here. Source runtime freshness, artifact
// age, review completion, document expiry, and control evidence recency must be
// modeled as explicit source attributes or finding/evidence filters.
type Vendor struct {
	VendorIdentity
	VendorLifecycle
	VendorOwnership
	VendorRiskPosture
	VendorRiskInputs
	VendorRiskScoring
	VendorControlPosture
	VendorReviewPosture
	VendorAssessmentPosture
	VendorFreshnessPosture
	VendorMonitoringPosture
	VendorCommercialPosture
	VendorOperationalPosture
	VendorContractDates
	VendorRecordCounts
	VendorFindingCounts
	VendorQueuePosture
	Attributes map[string]string `json:"attributes,omitempty"`
}

type VendorIdentity struct {
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
}

type VendorLifecycle struct {
	SourceStatus    string `json:"source_status,omitempty"`
	LifecycleState  string `json:"lifecycle_state"`
	LifecycleReason string `json:"lifecycle_reason,omitempty"`
}

type VendorOwnership struct {
	SecurityOwnerUserID string `json:"security_owner_user_id,omitempty"`
	BusinessOwnerUserID string `json:"business_owner_user_id,omitempty"`
	Owner               string `json:"owner,omitempty"`
	OwnerState          string `json:"owner_state"`
}

type VendorRiskPosture struct {
	InherentRiskLevel string `json:"inherent_risk_level,omitempty"`
	ResidualRiskLevel string `json:"residual_risk_level,omitempty"`
	RiskLevel         string `json:"risk_level"`
}

type VendorRiskInputs struct {
	DataSensitivity  string   `json:"data_sensitivity,omitempty"`
	AccessLevel      string   `json:"access_level,omitempty"`
	Criticality      string   `json:"criticality,omitempty"`
	Subprocessor     string   `json:"subprocessor,omitempty"`
	Geography        string   `json:"geography,omitempty"`
	SystemDependency string   `json:"system_dependency,omitempty"`
	RiskDrivers      []string `json:"risk_drivers,omitempty"`
}

type VendorRiskScoring struct {
	RiskScore         int               `json:"risk_score,omitempty"`
	RiskScoreLevel    string            `json:"risk_score_level,omitempty"`
	RiskScoreSource   string            `json:"risk_score_source,omitempty"`
	RiskTier          string            `json:"risk_tier,omitempty"`
	ReviewCadenceDays int               `json:"review_cadence_days,omitempty"`
	ScoreFactors      []RiskScoreFactor `json:"score_factors,omitempty"`
}

type RiskScoreFactor struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Score  int    `json:"score"`
	Weight int    `json:"weight"`
	Reason string `json:"reason,omitempty"`
}

type VendorControlPosture struct {
	DPAStatus            string `json:"dpa_status,omitempty"`
	BAAStatus            string `json:"baa_status,omitempty"`
	SOC2Status           string `json:"soc2_status,omitempty"`
	ISO27001Status       string `json:"iso27001_status,omitempty"`
	SecurityReviewStatus string `json:"security_review_status,omitempty"`
	PrivacyReviewStatus  string `json:"privacy_review_status,omitempty"`
	DocumentStatus       string `json:"document_status,omitempty"`
}

type VendorReviewPosture struct {
	ReviewState           string     `json:"review_state"`
	ReviewDueAt           *time.Time `json:"review_due_at,omitempty"`
	LastReviewCompletedAt *time.Time `json:"last_review_completed_at,omitempty"`
}

type VendorAssessmentPosture struct {
	AssessmentState       string     `json:"assessment_state,omitempty"`
	AssessmentProgress    int        `json:"assessment_progress,omitempty"`
	OpenAssessments       int        `json:"open_assessments,omitempty"`
	CompletedAssessments  int        `json:"completed_assessments,omitempty"`
	AssessmentTypes       []string   `json:"assessment_types,omitempty"`
	QuestionnaireState    string     `json:"questionnaire_state,omitempty"`
	QuestionnaireProgress int        `json:"questionnaire_progress,omitempty"`
	LastAssessmentAt      *time.Time `json:"last_assessment_at,omitempty"`
	NextAssessmentAt      *time.Time `json:"next_assessment_at,omitempty"`
}

type VendorFreshnessPosture struct {
	EvidenceFreshnessState string           `json:"evidence_freshness_state"`
	EvidenceFreshness      []FreshnessClock `json:"evidence_freshness,omitempty"`
}

type VendorMonitoringPosture struct {
	MonitoringState         string                   `json:"monitoring_state,omitempty"`
	MonitoringSignals       []VendorMonitoringSignal `json:"monitoring_signals,omitempty"`
	ExternalRating          string                   `json:"external_rating,omitempty"`
	ExternalRatingUpdatedAt *time.Time               `json:"external_rating_updated_at,omitempty"`
	LastMaterialChangeAt    *time.Time               `json:"last_material_change_at,omitempty"`
}

type VendorMonitoringSignal struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Severity   string     `json:"severity"`
	Source     string     `json:"source,omitempty"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

type VendorCommercialPosture struct {
	SpendAmount      string     `json:"spend_amount,omitempty"`
	SpendCurrency    string     `json:"spend_currency,omitempty"`
	ContractValue    string     `json:"contract_value,omitempty"`
	ContractCurrency string     `json:"contract_currency,omitempty"`
	RenewalNoticeAt  *time.Time `json:"renewal_notice_at,omitempty"`
	RenewalState     string     `json:"renewal_state,omitempty"`
	PrimaryContact   string     `json:"primary_contact,omitempty"`
	BusinessUnit     string     `json:"business_unit,omitempty"`
	CostCenter       string     `json:"cost_center,omitempty"`
}

type VendorOperationalPosture struct {
	ExposureLevel           string     `json:"exposure_level,omitempty"`
	ExposureReasons         []string   `json:"exposure_reasons,omitempty"`
	PacketState             string     `json:"packet_state,omitempty"`
	PacketReadyItems        []string   `json:"packet_ready_items,omitempty"`
	PacketMissingItems      []string   `json:"packet_missing_items,omitempty"`
	RemediationState        string     `json:"remediation_state,omitempty"`
	RemediationDueAt        *time.Time `json:"remediation_due_at,omitempty"`
	OpenRemediationItems    int        `json:"open_remediation_items,omitempty"`
	OverdueRemediationItems int        `json:"overdue_remediation_items,omitempty"`
	OffboardingState        string     `json:"offboarding_state,omitempty"`
	OffboardingDueAt        *time.Time `json:"offboarding_due_at,omitempty"`
	DataDeletionState       string     `json:"data_deletion_state,omitempty"`
}

type FreshnessClock struct {
	ID             string     `json:"id"`
	Label          string     `json:"label"`
	Source         string     `json:"source"`
	Status         string     `json:"status"`
	ObservedAt     *time.Time `json:"observed_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	AgeDays        int        `json:"age_days,omitempty"`
	StaleAfterDays int        `json:"stale_after_days,omitempty"`
	Reason         string     `json:"reason,omitempty"`
}

type VendorContractDates struct {
	ContractStartAt       *time.Time `json:"contract_start_at,omitempty"`
	ContractRenewalAt     *time.Time `json:"contract_renewal_at,omitempty"`
	ContractTerminationAt *time.Time `json:"contract_termination_at,omitempty"`
}

type VendorRecordCounts struct {
	ContractCount          int `json:"contract_count"`
	SecurityReviewCount    int `json:"security_review_count"`
	QuestionnaireCount     int `json:"questionnaire_count"`
	AssuranceDocumentCount int `json:"assurance_document_count"`
}

type VendorFindingCounts struct {
	OpenFindings     int `json:"open_findings,omitempty"`
	CriticalFindings int `json:"critical_findings,omitempty"`
	HighFindings     int `json:"high_findings,omitempty"`
	EvidenceItems    int `json:"evidence_items,omitempty"`
}

type VendorQueuePosture struct {
	RiskQueueRank int                 `json:"risk_queue_rank,omitempty"`
	QueueReasons  []string            `json:"queue_reasons,omitempty"`
	NextActions   []VendorAction      `json:"next_actions,omitempty"`
	CloseActions  []VendorCloseAction `json:"close_actions,omitempty"`
}

type VendorAction struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Reason      string `json:"reason,omitempty"`
	ActionType  string `json:"action_type,omitempty"`
	TargetState string `json:"target_state,omitempty"`
	Priority    int    `json:"priority,omitempty"`
}

type VendorCloseAction struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	ClosesWhen string `json:"closes_when"`
	FindingKey string `json:"finding_key,omitempty"`
}

type VendorDiscovery struct {
	URN               string            `json:"urn"`
	DiscoveryID       string            `json:"discovery_id,omitempty"`
	Name              string            `json:"name"`
	NormalizedName    string            `json:"normalized_name,omitempty"`
	SourceID          string            `json:"source_id,omitempty"`
	RuntimeID         string            `json:"runtime_id,omitempty"`
	Provider          string            `json:"provider,omitempty"`
	SourceStatus      string            `json:"source_status"`
	DecisionState     string            `json:"decision_state"`
	Category          string            `json:"category,omitempty"`
	WebsiteURL        string            `json:"website_url,omitempty"`
	LinkedVendorURN   string            `json:"linked_vendor_urn,omitempty"`
	DecisionReason    string            `json:"decision_reason,omitempty"`
	DecisionUpdatedBy string            `json:"decision_updated_by,omitempty"`
	DecisionUpdatedAt *time.Time        `json:"decision_updated_at,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

type Summary struct {
	TotalVendors           int `json:"total_vendors"`
	ActiveVendors          int `json:"active_vendors"`
	HighRiskVendors        int `json:"high_risk_vendors"`
	OwnerMissingVendors    int `json:"owner_missing_vendors"`
	ReviewOverdueVendors   int `json:"review_overdue_vendors"`
	ReviewDueSoonVendors   int `json:"review_due_soon_vendors"`
	ReviewNotScheduled     int `json:"review_not_scheduled"`
	RiskQueueVendors       int `json:"risk_queue_vendors"`
	StaleEvidenceVendors   int `json:"stale_evidence_vendors"`
	RestrictedVendors      int `json:"restricted_vendors"`
	CriticalTierVendors    int `json:"critical_tier_vendors"`
	AssessmentDueVendors   int `json:"assessment_due_vendors"`
	MonitoringAlertVendors int `json:"monitoring_alert_vendors"`
	RenewalDueVendors      int `json:"renewal_due_vendors"`
	PacketBlockedVendors   int `json:"packet_blocked_vendors"`
	HighExposureVendors    int `json:"high_exposure_vendors"`
	RemediationDueVendors  int `json:"remediation_due_vendors"`
	OffboardingDueVendors  int `json:"offboarding_due_vendors"`
	OpenFindings           int `json:"open_findings"`
	CriticalFindings       int `json:"critical_findings"`
	HighFindings           int `json:"high_findings"`
	EvidenceItems          int `json:"evidence_items"`
}

type DiscoverySummary struct {
	TotalDiscoveries int `json:"total_discoveries"`
	Discovered       int `json:"discovered"`
	Approved         int `json:"approved"`
	Rejected         int `json:"rejected"`
	Ignored          int `json:"ignored"`
	Linked           int `json:"linked"`
}

type VendorDetail struct {
	Vendor        Vendor                    `json:"vendor"`
	Relationships VendorRelationships       `json:"relationships"`
	Packet        VendorPacket              `json:"packet"`
	Graph         *ports.EntityNeighborhood `json:"graph,omitempty"`
}

type VendorRelationships struct {
	Contracts              []RelatedRecord `json:"contracts,omitempty"`
	SecurityReviews        []RelatedRecord `json:"security_reviews,omitempty"`
	SecurityQuestionnaires []RelatedRecord `json:"security_questionnaires,omitempty"`
	AssuranceDocuments     []RelatedRecord `json:"assurance_documents,omitempty"`
	Assessments            []RelatedRecord `json:"assessments,omitempty"`
	Owners                 []RelatedRecord `json:"owners,omitempty"`
	Hosts                  []RelatedRecord `json:"hosts,omitempty"`
	Aliases                []RelatedRecord `json:"aliases,omitempty"`
	Contacts               []RelatedRecord `json:"contacts,omitempty"`
	FourthParties          []RelatedRecord `json:"fourth_parties,omitempty"`
}

type VendorPacket struct {
	Version           string                   `json:"version"`
	VendorURN         string                   `json:"vendor_urn"`
	Lifecycle         VendorLifecycle          `json:"lifecycle"`
	Risk              VendorPacketRisk         `json:"risk"`
	RiskScore         VendorRiskScoring        `json:"risk_score"`
	Controls          VendorControlPosture     `json:"controls"`
	Assessments       VendorAssessmentPosture  `json:"assessments"`
	Monitoring        VendorMonitoringPosture  `json:"monitoring"`
	Commercial        VendorCommercialPosture  `json:"commercial"`
	Operations        VendorOperationalPosture `json:"operations"`
	EvidenceFreshness []FreshnessClock         `json:"evidence_freshness,omitempty"`
	ReviewHistory     []RelatedRecord          `json:"review_history,omitempty"`
	Obligations       []VendorObligation       `json:"obligations,omitempty"`
	Owners            []RelatedRecord          `json:"owners,omitempty"`
	Contacts          []RelatedRecord          `json:"contacts,omitempty"`
	Identifiers       []RelatedRecord          `json:"identifiers,omitempty"`
	FourthParties     []RelatedRecord          `json:"fourth_parties,omitempty"`
	FindingCounts     VendorFindingCounts      `json:"finding_counts"`
	NextActions       []VendorAction           `json:"next_actions,omitempty"`
	CloseActions      []VendorCloseAction      `json:"close_actions,omitempty"`
}

type VendorPacketRisk struct {
	InherentRiskLevel string   `json:"inherent_risk_level,omitempty"`
	ResidualRiskLevel string   `json:"residual_risk_level,omitempty"`
	RiskLevel         string   `json:"risk_level"`
	DataSensitivity   string   `json:"data_sensitivity,omitempty"`
	AccessLevel       string   `json:"access_level,omitempty"`
	Criticality       string   `json:"criticality,omitempty"`
	Subprocessor      string   `json:"subprocessor,omitempty"`
	Geography         string   `json:"geography,omitempty"`
	SystemDependency  string   `json:"system_dependency,omitempty"`
	Drivers           []string `json:"drivers,omitempty"`
}

type VendorObligation struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Status    string     `json:"status"`
	Source    string     `json:"source,omitempty"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

type RelatedRecord struct {
	URN        string            `json:"urn"`
	EntityType string            `json:"entity_type"`
	Label      string            `json:"label"`
	SourceID   string            `json:"source_id,omitempty"`
	RuntimeID  string            `json:"runtime_id,omitempty"`
	Relation   string            `json:"relation,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func New(store ports.GraphQueryStore) *Service {
	return &Service{store: store, now: time.Now}
}

func (s *Service) ListVendors(ctx context.Context, request ListVendorsRequest) ([]Vendor, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	limit := normalizeVendorLimit(request.Limit)
	queryLimit := limit
	if hasDerivedFilter(request) {
		queryLimit = maxVendorLimit
	}
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: vendorListQuery,
		Params: map[string]any{
			"tenant_id":   strings.TrimSpace(request.TenantID),
			"runtime_id":  strings.TrimSpace(request.RuntimeID),
			"runtime_ids": nonEmptyStrings(request.RuntimeIDs),
			"source_id":   strings.TrimSpace(request.SourceID),
			"q":           strings.ToLower(strings.TrimSpace(request.Query)),
			"limit":       queryLimit,
		},
		RowLimit: queryLimit,
	})
	if err != nil {
		return nil, err
	}
	vendors := make([]Vendor, 0, len(rows))
	for _, row := range rows {
		vendor := s.vendorFromRow(row)
		if vendor.URN == "" {
			continue
		}
		if !matchesVendorFilter(vendor, request) {
			continue
		}
		vendors = append(vendors, vendor)
	}
	sortVendors(vendors)
	if !request.DeferLimit && len(vendors) > limit {
		vendors = vendors[:limit]
	}
	return vendors, nil
}

func (s *Service) ListDiscoveries(ctx context.Context, request ListDiscoveriesRequest) ([]VendorDiscovery, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	limit := normalizeVendorLimit(request.Limit)
	queryLimit := limit
	if hasDiscoveryDerivedFilter(request) {
		queryLimit = maxVendorLimit
	}
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: discoveryListQuery,
		Params: map[string]any{
			"tenant_id":   strings.TrimSpace(request.TenantID),
			"runtime_id":  strings.TrimSpace(request.RuntimeID),
			"runtime_ids": nonEmptyStrings(request.RuntimeIDs),
			"source_id":   strings.TrimSpace(request.SourceID),
			"q":           strings.ToLower(strings.TrimSpace(request.Query)),
			"limit":       queryLimit,
		},
		RowLimit: queryLimit,
	})
	if err != nil {
		return nil, err
	}
	discoveries := make([]VendorDiscovery, 0, len(rows))
	for _, row := range rows {
		discovery := discoveryFromRow(row)
		if discovery.URN == "" {
			continue
		}
		if !matchesDiscoveryFilter(discovery, request) {
			continue
		}
		discoveries = append(discoveries, discovery)
	}
	sortDiscoveries(discoveries)
	if len(discoveries) > limit {
		discoveries = discoveries[:limit]
	}
	return discoveries, nil
}

func (s *Service) GetVendor(ctx context.Context, request VendorDetailRequest) (*VendorDetail, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	urn := strings.TrimSpace(request.URN)
	vendorID := strings.TrimSpace(request.VendorID)
	if urn == "" && looksLikeCerebroURN(vendorID) {
		urn = vendorID
		vendorID = ""
	}
	if urn == "" && vendorID == "" {
		return nil, fmt.Errorf("%w: vendor_id is required", ErrInvalidRequest)
	}
	if urn != "" {
		if err := validateCerebroURN(urn); err != nil {
			return nil, err
		}
	}
	if vendorID != "" && strings.Contains(vendorID, "/") {
		return nil, fmt.Errorf("%w: vendor_id must not contain path separators", ErrInvalidRequest)
	}
	if err := validateVendorDetailScope(urn, vendorID); err != nil {
		return nil, err
	}
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    vendorDetailQuery,
		Params:   vendorDetailParams(request, urn, vendorID),
		RowLimit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ports.ErrGraphEntityNotFound
	}
	vendor := s.vendorFromRow(rows[0])
	if vendor.URN == "" {
		return nil, ports.ErrGraphEntityNotFound
	}
	urn = vendor.URN
	limit := normalizeRelatedLimit(request.Limit)
	relatedRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    vendorRelationshipsQuery,
		Params:   map[string]any{"urn": urn, "limit": limit},
		RowLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	relationships := relationshipsFromRows(relatedRows)
	graph, err := s.store.GetEntityNeighborhood(ctx, urn, normalizeNeighborhoodLimit(request.Limit))
	if err != nil {
		return nil, err
	}
	return &VendorDetail{
		Vendor:        vendor,
		Relationships: relationships,
		Packet:        BuildVendorPacket(vendor, relationships),
		Graph:         graph,
	}, nil
}

func Summarize(vendors []Vendor) Summary {
	var summary Summary
	summary.TotalVendors = len(vendors)
	for _, vendor := range vendors {
		if vendorLifecycleIsActive(vendor) {
			summary.ActiveVendors++
		}
		if vendor.RiskLevel == "high" || vendor.RiskLevel == "critical" {
			summary.HighRiskVendors++
		}
		if vendor.OwnerState == OwnerStateMissing {
			summary.OwnerMissingVendors++
		}
		switch vendor.ReviewState {
		case ReviewStateOverdue:
			summary.ReviewOverdueVendors++
		case ReviewStateDueSoon:
			summary.ReviewDueSoonVendors++
		case ReviewStateNotScheduled:
			summary.ReviewNotScheduled++
		}
		if len(vendor.QueueReasons) > 0 {
			summary.RiskQueueVendors++
		}
		if vendor.EvidenceFreshnessState == FreshnessStateStale || vendor.EvidenceFreshnessState == FreshnessStateExpired {
			summary.StaleEvidenceVendors++
		}
		if vendor.LifecycleState == LifecycleStateRestricted || vendor.LifecycleState == LifecycleStateConditionallyApproved {
			summary.RestrictedVendors++
		}
		if vendor.RiskTier == "tier_1" || vendor.RiskTier == "critical" {
			summary.CriticalTierVendors++
		}
		if vendor.AssessmentState == ReviewStateOverdue || vendor.AssessmentState == ReviewStateDueSoon || vendor.AssessmentState == "in_progress" {
			summary.AssessmentDueVendors++
		}
		if vendor.MonitoringState == "alert" || vendor.MonitoringState == "critical" {
			summary.MonitoringAlertVendors++
		}
		if vendor.RenewalState == ReviewStateOverdue || vendor.RenewalState == ReviewStateDueSoon {
			summary.RenewalDueVendors++
		}
		if vendor.PacketState == "blocked" || vendor.PacketState == "needs_work" {
			summary.PacketBlockedVendors++
		}
		if vendor.ExposureLevel == "critical" || vendor.ExposureLevel == "high" {
			summary.HighExposureVendors++
		}
		if vendor.RemediationState == ReviewStateOverdue || vendor.RemediationState == ReviewStateDueSoon {
			summary.RemediationDueVendors++
		}
		if vendor.OffboardingState == ReviewStateOverdue || vendor.OffboardingState == ReviewStateDueSoon {
			summary.OffboardingDueVendors++
		}
		summary.OpenFindings += vendor.OpenFindings
		summary.CriticalFindings += vendor.CriticalFindings
		summary.HighFindings += vendor.HighFindings
		summary.EvidenceItems += vendor.EvidenceItems
	}
	return summary
}

func SummarizeDiscoveries(discoveries []VendorDiscovery) DiscoverySummary {
	var summary DiscoverySummary
	summary.TotalDiscoveries = len(discoveries)
	for _, discovery := range discoveries {
		switch normalizeDiscoveryState(discovery.DecisionState) {
		case DiscoveryStateApproved:
			summary.Approved++
		case DiscoveryStateRejected:
			summary.Rejected++
		case DiscoveryStateIgnored:
			summary.Ignored++
		case DiscoveryStateLinked:
			summary.Linked++
		default:
			summary.Discovered++
		}
	}
	return summary
}

func ApplyDiscoveryDecisions(discoveries []VendorDiscovery, records []*ports.GRCVendorDiscoveryDecisionRecord) []VendorDiscovery {
	if len(discoveries) == 0 || len(records) == 0 {
		return discoveries
	}
	byURN := make(map[string]*ports.GRCVendorDiscoveryDecisionRecord, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		urn := strings.TrimSpace(record.DiscoveryURN)
		if urn == "" {
			continue
		}
		byURN[urn] = record
	}
	for index := range discoveries {
		record := byURN[discoveries[index].URN]
		if record == nil {
			continue
		}
		if decision := normalizeDiscoveryState(record.Decision); decision != "" {
			discoveries[index].DecisionState = decision
		}
		discoveries[index].LinkedVendorURN = strings.TrimSpace(record.LinkedVendorURN)
		discoveries[index].DecisionReason = strings.TrimSpace(record.Reason)
		discoveries[index].DecisionUpdatedBy = strings.TrimSpace(record.UpdatedBy)
		if !record.UpdatedAt.IsZero() {
			updatedAt := record.UpdatedAt.UTC()
			discoveries[index].DecisionUpdatedAt = &updatedAt
		}
	}
	return discoveries
}

func FilterDiscoveriesByDecisionState(discoveries []VendorDiscovery, decisionState string) []VendorDiscovery {
	decisionState = normalizeDiscoveryFilter(decisionState)
	if decisionState == "" || decisionState == "all" {
		return discoveries
	}
	filtered := discoveries[:0]
	for _, discovery := range discoveries {
		if normalizeDiscoveryState(discovery.DecisionState) == decisionState {
			filtered = append(filtered, discovery)
		}
	}
	return filtered
}

func (s *Service) vendorFromRow(row ports.CypherRow) Vendor {
	attrs := parseAttributes(rowString(row, "attributes_json"))
	owner := firstNonEmpty(attrs["security_owner_user_id"], attrs["business_owner_user_id"])
	ownerState := OwnerStateAssigned
	if owner == "" {
		ownerState = OwnerStateMissing
	}
	reviewDueAt := parseDateAttribute(attrs, "next_security_review_due_date")
	lastReviewCompletedAt := parseDateAttribute(attrs, "last_security_review_completion_date")
	inherentRisk := normalizeRiskLevel(attrs["inherent_risk_level"])
	residualRisk := normalizeRiskLevel(attrs["residual_risk_level"])
	riskLevel := firstNonEmpty(residualRisk, inherentRisk, normalizeRiskLevel(attrs["risk_level"]), "unknown")
	urn := rowString(row, "urn")
	now := s.now()
	vendor := Vendor{
		VendorIdentity: VendorIdentity{
			URN:              urn,
			VendorID:         firstNonEmpty(attrs["vendor_id"], attrs["external_id"], urnTail(urn)),
			Name:             firstNonEmpty(rowString(row, "label"), attrs["name"], attrs["vendor_id"], urnTail(urn)),
			SourceID:         rowString(row, "source_id"),
			RuntimeID:        rowString(row, "runtime_id"),
			Provider:         firstNonEmpty(attrs["source_system"], attrs["provider"], rowString(row, "source_id")),
			Status:           firstNonEmpty(attrs["status"], attrs["vendor_status"]),
			Category:         attrs["category"],
			WebsiteURL:       firstNonEmpty(attrs["website_url"], attrs["website"], attrs["url"], attrs["domain"]),
			ServicesProvided: attrs["services_provided"],
		},
		VendorLifecycle: VendorLifecycle{
			SourceStatus:    firstNonEmpty(attrs["source_status"], attrs["status"], attrs["vendor_status"]),
			LifecycleState:  normalizeVendorLifecycleState(firstNonEmpty(attrs["lifecycle_state"], attrs["vendor_lifecycle_state"], attrs["status"], attrs["vendor_status"])),
			LifecycleReason: firstNonEmpty(attrs["lifecycle_reason"], attrs["status_reason"], attrs["vendor_status_reason"]),
		},
		VendorOwnership: VendorOwnership{
			SecurityOwnerUserID: attrs["security_owner_user_id"],
			BusinessOwnerUserID: attrs["business_owner_user_id"],
			Owner:               owner,
			OwnerState:          ownerState,
		},
		VendorRiskPosture: VendorRiskPosture{
			InherentRiskLevel: inherentRisk,
			ResidualRiskLevel: residualRisk,
			RiskLevel:         riskLevel,
		},
		VendorRiskInputs: VendorRiskInputs{
			DataSensitivity:  normalizeRiskInput(firstNonEmpty(attrs["data_sensitivity"], attrs["data_classification"], attrs["data_access_level"])),
			AccessLevel:      normalizeRiskInput(firstNonEmpty(attrs["access_level"], attrs["access_type"], attrs["system_access"])),
			Criticality:      normalizeRiskInput(firstNonEmpty(attrs["criticality"], attrs["business_criticality"], attrs["service_criticality"])),
			Subprocessor:     normalizeBooleanish(firstNonEmpty(attrs["subprocessor"], attrs["is_subprocessor"], attrs["processor"])),
			Geography:        firstNonEmpty(attrs["geography"], attrs["processing_region"], attrs["country"], attrs["region"]),
			SystemDependency: normalizeRiskInput(firstNonEmpty(attrs["system_dependency"], attrs["dependency_level"], attrs["service_dependency"])),
			RiskDrivers:      vendorRiskDrivers(attrs),
		},
		VendorControlPosture: VendorControlPosture{
			DPAStatus:            normalizeDocumentStatus(attrs, now, "dpa", "data_processing_agreement"),
			BAAStatus:            normalizeDocumentStatus(attrs, now, "baa", "business_associate_agreement"),
			SOC2Status:           normalizeDocumentStatus(attrs, now, "soc2", "soc_2"),
			ISO27001Status:       normalizeDocumentStatus(attrs, now, "iso27001", "iso_27001"),
			SecurityReviewStatus: normalizeReviewPosture(firstNonEmpty(attrs["security_review_status"], attrs["review_status"]), reviewDueAt, lastReviewCompletedAt, now),
			PrivacyReviewStatus:  normalizeReviewPosture(firstNonEmpty(attrs["privacy_review_status"], attrs["privacy_review_state"]), parseDateAttribute(attrs, "next_privacy_review_due_date"), parseDateAttribute(attrs, "last_privacy_review_completion_date"), now),
			DocumentStatus:       normalizeDocumentStatus(attrs, now, "assurance_document", "document"),
		},
		VendorReviewPosture: VendorReviewPosture{
			ReviewState:           reviewState(reviewDueAt, now),
			ReviewDueAt:           reviewDueAt,
			LastReviewCompletedAt: lastReviewCompletedAt,
		},
		VendorFreshnessPosture: vendorFreshnessPosture(attrs, now),
		VendorContractDates: VendorContractDates{
			ContractStartAt:       parseDateAttribute(attrs, "contract_start_date"),
			ContractRenewalAt:     parseDateAttribute(attrs, "contract_renewal_date"),
			ContractTerminationAt: parseDateAttribute(attrs, "contract_termination_date"),
		},
		VendorRecordCounts: VendorRecordCounts{
			ContractCount:          rowInt(row, "contract_count"),
			SecurityReviewCount:    rowInt(row, "security_review_count"),
			QuestionnaireCount:     rowInt(row, "questionnaire_count"),
			AssuranceDocumentCount: rowInt(row, "assurance_document_count"),
		},
		Attributes: attrs,
	}
	if vendor.LifecycleState == "" {
		vendor.LifecycleState = LifecycleStateUnknown
	}
	vendor.VendorAssessmentPosture = vendorAssessmentPosture(vendor, now)
	vendor.VendorCommercialPosture = vendorCommercialPosture(attrs, now)
	return RefreshVendorQueuePosture(vendor, now)
}

func discoveryFromRow(row ports.CypherRow) VendorDiscovery {
	attrs := parseAttributes(rowString(row, "attributes_json"))
	sourceStatus := normalizeDiscoveryState(firstNonEmpty(attrs["status"], DiscoveryStateDiscovered))
	if sourceStatus == "" {
		sourceStatus = DiscoveryStateDiscovered
	}
	return VendorDiscovery{
		URN:            rowString(row, "urn"),
		DiscoveryID:    firstNonEmpty(attrs["discovered_vendor_id"], attrs["vendor_id"], attrs["external_id"], urnTail(rowString(row, "urn"))),
		Name:           firstNonEmpty(rowString(row, "label"), attrs["name"], attrs["display_name"], attrs["normalized_name"], urnTail(rowString(row, "urn"))),
		NormalizedName: firstNonEmpty(attrs["normalized_name"], strings.ToLower(attrs["name"])),
		SourceID:       rowString(row, "source_id"),
		RuntimeID:      rowString(row, "runtime_id"),
		Provider:       firstNonEmpty(attrs["source_system"], attrs["provider"], rowString(row, "source_id")),
		SourceStatus:   sourceStatus,
		DecisionState:  sourceStatus,
		Category:       attrs["category"],
		WebsiteURL:     firstNonEmpty(attrs["website_url"], attrs["website"], attrs["url"], attrs["domain"]),
		Attributes:     attrs,
	}
}

func hasDerivedFilter(request ListVendorsRequest) bool {
	return strings.TrimSpace(request.RiskLevel) != "" ||
		strings.TrimSpace(request.ReviewState) != "" ||
		strings.TrimSpace(request.OwnerState) != "" ||
		strings.TrimSpace(request.Lifecycle) != "" ||
		request.QueueOnly
}

func hasDiscoveryDerivedFilter(request ListDiscoveriesRequest) bool {
	return strings.TrimSpace(request.Status) != "" ||
		strings.TrimSpace(request.DecisionState) != ""
}

func matchesVendorFilter(vendor Vendor, request ListVendorsRequest) bool {
	riskLevel := strings.ToLower(strings.TrimSpace(request.RiskLevel))
	if riskLevel != "" && riskLevel != "all" && vendor.RiskLevel != riskLevel {
		return false
	}
	reviewState := strings.ToLower(strings.TrimSpace(request.ReviewState))
	if reviewState != "" && reviewState != "all" && vendor.ReviewState != reviewState {
		return false
	}
	ownerState := strings.ToLower(strings.TrimSpace(request.OwnerState))
	if ownerState != "" && ownerState != "all" && vendor.OwnerState != ownerState {
		return false
	}
	lifecycle := normalizeVendorLifecycleState(request.Lifecycle)
	if lifecycle != "" && lifecycle != "all" && vendor.LifecycleState != lifecycle {
		return false
	}
	return true
}

func matchesDiscoveryFilter(discovery VendorDiscovery, request ListDiscoveriesRequest) bool {
	status := normalizeDiscoveryFilter(request.Status)
	if status != "" && status != "all" && normalizeDiscoveryState(discovery.SourceStatus) != status {
		return false
	}
	return true
}

func sortVendors(vendors []Vendor) {
	sort.Slice(vendors, func(i, j int) bool {
		if vendors[i].RiskQueueRank != vendors[j].RiskQueueRank {
			return vendors[i].RiskQueueRank > vendors[j].RiskQueueRank
		}
		if riskRank(vendors[i].RiskLevel) != riskRank(vendors[j].RiskLevel) {
			return riskRank(vendors[i].RiskLevel) > riskRank(vendors[j].RiskLevel)
		}
		if reviewRank(vendors[i].ReviewState) != reviewRank(vendors[j].ReviewState) {
			return reviewRank(vendors[i].ReviewState) > reviewRank(vendors[j].ReviewState)
		}
		leftDue := timeValue(vendors[i].ReviewDueAt)
		rightDue := timeValue(vendors[j].ReviewDueAt)
		if !leftDue.Equal(rightDue) {
			if leftDue.IsZero() {
				return false
			}
			if rightDue.IsZero() {
				return true
			}
			return leftDue.Before(rightDue)
		}
		return strings.ToLower(vendors[i].Name) < strings.ToLower(vendors[j].Name)
	})
}

func sortDiscoveries(discoveries []VendorDiscovery) {
	sort.Slice(discoveries, func(i, j int) bool {
		if discoveryRank(discoveries[i].DecisionState) != discoveryRank(discoveries[j].DecisionState) {
			return discoveryRank(discoveries[i].DecisionState) > discoveryRank(discoveries[j].DecisionState)
		}
		return strings.ToLower(discoveries[i].Name) < strings.ToLower(discoveries[j].Name)
	})
}

func BuildVendorPacket(vendor Vendor, relationships VendorRelationships) VendorPacket {
	reviewHistory := append([]RelatedRecord{}, relationships.SecurityReviews...)
	reviewHistory = append(reviewHistory, relationships.SecurityQuestionnaires...)
	reviewHistory = append(reviewHistory, relationships.AssuranceDocuments...)
	reviewHistory = append(reviewHistory, relationships.Assessments...)
	return VendorPacket{
		Version:           "2026-06-28",
		VendorURN:         vendor.URN,
		Lifecycle:         vendor.VendorLifecycle,
		Risk:              vendorPacketRisk(vendor),
		RiskScore:         vendor.VendorRiskScoring,
		Controls:          vendor.VendorControlPosture,
		Assessments:       vendor.VendorAssessmentPosture,
		Monitoring:        vendor.VendorMonitoringPosture,
		Commercial:        vendor.VendorCommercialPosture,
		Operations:        vendor.VendorOperationalPosture,
		EvidenceFreshness: vendor.EvidenceFreshness,
		ReviewHistory:     reviewHistory,
		Obligations:       vendorObligations(vendor),
		Owners:            append([]RelatedRecord{}, relationships.Owners...),
		Contacts:          append([]RelatedRecord{}, relationships.Contacts...),
		Identifiers:       append(append([]RelatedRecord{}, relationships.Hosts...), relationships.Aliases...),
		FourthParties:     append([]RelatedRecord{}, relationships.FourthParties...),
		FindingCounts:     vendor.VendorFindingCounts,
		NextActions:       append([]VendorAction{}, vendor.NextActions...),
		CloseActions:      append([]VendorCloseAction{}, vendor.CloseActions...),
	}
}

func RefreshVendorQueuePosture(vendor Vendor, at ...time.Time) Vendor {
	now := time.Now().UTC()
	if len(at) > 0 && !at[0].IsZero() {
		now = at[0].UTC()
	}
	vendor.VendorRiskScoring = vendorRiskScoring(vendor)
	vendor.VendorMonitoringPosture = vendorMonitoringPosture(vendor)
	vendor.VendorOperationalPosture = vendorOperationalPosture(vendor, now)
	vendor.VendorQueuePosture = vendorQueuePosture(vendor)
	return vendor
}

func SortAndLimitVendors(vendors []Vendor, limit uint32) []Vendor {
	sortVendors(vendors)
	normalized := normalizeVendorLimit(limit)
	if len(vendors) > normalized {
		return vendors[:normalized]
	}
	return vendors
}

func FilterVendorsByQueue(vendors []Vendor) []Vendor {
	filtered := vendors[:0]
	for _, vendor := range vendors {
		vendor = RefreshVendorQueuePosture(vendor)
		if len(vendor.QueueReasons) != 0 {
			filtered = append(filtered, vendor)
		}
	}
	return filtered
}

func vendorPacketRisk(vendor Vendor) VendorPacketRisk {
	return VendorPacketRisk{
		InherentRiskLevel: vendor.InherentRiskLevel,
		ResidualRiskLevel: vendor.ResidualRiskLevel,
		RiskLevel:         vendor.RiskLevel,
		DataSensitivity:   vendor.DataSensitivity,
		AccessLevel:       vendor.AccessLevel,
		Criticality:       vendor.Criticality,
		Subprocessor:      vendor.Subprocessor,
		Geography:         vendor.Geography,
		SystemDependency:  vendor.SystemDependency,
		Drivers:           append([]string{}, vendor.RiskDrivers...),
	}
}

func vendorObligations(vendor Vendor) []VendorObligation {
	obligations := []VendorObligation{
		vendorObligation("security_review", "Security review", vendor.SecurityReviewStatus, "review", vendor.ReviewDueAt, nil),
		vendorObligation("dpa", "DPA", vendor.DPAStatus, "contract", nil, firstDate(vendor.Attributes, "dpa_expiry_date", "data_processing_agreement_expiry_date")),
		vendorObligation("soc2", "SOC 2", vendor.SOC2Status, "assurance", nil, firstDate(vendor.Attributes, "soc2_expiry_date", "soc_2_expiry_date", "soc2_report_end_date")),
		vendorObligation("iso27001", "ISO 27001", vendor.ISO27001Status, "assurance", nil, firstDate(vendor.Attributes, "iso27001_expiry_date", "iso_27001_expiry_date")),
	}
	if status := strings.TrimSpace(vendor.BAAStatus); status != "" && status != FreshnessStateUnknown {
		obligations = append(obligations, vendorObligation("baa", "BAA", status, "contract", nil, firstDate(vendor.Attributes, "baa_expiry_date", "business_associate_agreement_expiry_date")))
	}
	return obligations
}

func vendorObligation(id string, label string, status string, source string, dueAt *time.Time, expiresAt *time.Time) VendorObligation {
	normalized := strings.TrimSpace(status)
	if normalized == "" {
		normalized = FreshnessStateUnknown
	}
	obligation := VendorObligation{
		ID:        id,
		Label:     label,
		Status:    normalized,
		Source:    source,
		DueAt:     dueAt,
		ExpiresAt: expiresAt,
	}
	switch normalized {
	case FreshnessStateMissing:
		obligation.Reason = label + " is not attached"
	case FreshnessStateExpired:
		obligation.Reason = label + " is expired"
	case ReviewStateOverdue:
		obligation.Reason = label + " is overdue"
	}
	return obligation
}

func relationshipsFromRows(rows []ports.CypherRow) VendorRelationships {
	var result VendorRelationships
	for _, row := range rows {
		record := relatedRecordFromRow(row)
		if record.URN == "" {
			continue
		}
		switch record.EntityType {
		case "contract":
			result.Contracts = append(result.Contracts, record)
		case "security.review":
			result.SecurityReviews = append(result.SecurityReviews, record)
		case "security.questionnaire":
			result.SecurityQuestionnaires = append(result.SecurityQuestionnaires, record)
		case "assurance.document":
			result.AssuranceDocuments = append(result.AssuranceDocuments, record)
		case "vendor.assessment", "privacy.assessment", "security.assessment", "risk.assessment", "legal.assessment":
			result.Assessments = append(result.Assessments, record)
		case "grc.user", "user":
			result.Owners = append(result.Owners, record)
		case "internet.host":
			result.Hosts = append(result.Hosts, record)
		case "vendor.alias":
			result.Aliases = append(result.Aliases, record)
		case "vendor.contact", "contact":
			result.Contacts = append(result.Contacts, record)
		case "vendor.fourth_party", "fourth_party.vendor", "subprocessor":
			result.FourthParties = append(result.FourthParties, record)
		}
	}
	return result
}

func relatedRecordFromRow(row ports.CypherRow) RelatedRecord {
	return RelatedRecord{
		URN:        rowString(row, "urn"),
		EntityType: rowString(row, "entity_type"),
		Label:      firstNonEmpty(rowString(row, "label"), rowString(row, "urn")),
		SourceID:   rowString(row, "source_id"),
		RuntimeID:  rowString(row, "runtime_id"),
		Relation:   rowString(row, "relation"),
		Attributes: parseAttributes(rowString(row, "attributes_json")),
	}
}

func vendorRiskScoring(vendor Vendor) VendorRiskScoring {
	factors := []RiskScoreFactor{
		riskScoreFactor("risk_level", "Risk level", scoreForRiskLevel(vendor.RiskLevel), 16, firstNonEmpty(vendor.ResidualRiskLevel, vendor.InherentRiskLevel, vendor.RiskLevel)),
		riskScoreFactor("data", "Data access", scoreForRiskInput(vendor.DataSensitivity), 14, vendor.DataSensitivity),
		riskScoreFactor("access", "System access", scoreForRiskInput(vendor.AccessLevel), 12, vendor.AccessLevel),
		riskScoreFactor("criticality", "Business criticality", maxInt(scoreForRiskInput(vendor.Criticality), scoreForRiskInput(vendor.SystemDependency)), 14, firstNonEmpty(vendor.Criticality, vendor.SystemDependency)),
		riskScoreFactor("subprocessor", "Subprocessor", scoreForBooleanish(vendor.Subprocessor), 6, vendor.Subprocessor),
		riskScoreFactor("controls", "Control gaps", scoreForControlPosture(vendor), 12, vendorControlRiskReason(vendor)),
		riskScoreFactor("findings", "Open findings", scoreForFindings(vendor), 14, vendorFindingRiskReason(vendor)),
		riskScoreFactor("freshness", "Evidence freshness", scoreForFreshness(vendor.EvidenceFreshnessState), 8, vendor.EvidenceFreshnessState),
		riskScoreFactor("lifecycle", "Lifecycle", scoreForLifecycle(vendor.LifecycleState), 4, vendor.LifecycleState),
	}
	score := weightedRiskScore(factors)
	source := "derived"
	if explicit := intAttribute(vendor.Attributes, "risk_score", "vendor_risk_score", "current_risk_score"); explicit >= 0 {
		score = clampPercent(explicit)
		source = "attribute"
	}
	level := firstNonEmpty(normalizeRiskLevel(scoreLevel(score)), vendor.RiskLevel, "unknown")
	tier := vendorRiskTier(score, vendor)
	return VendorRiskScoring{
		RiskScore:         score,
		RiskScoreLevel:    level,
		RiskScoreSource:   source,
		RiskTier:          tier,
		ReviewCadenceDays: reviewCadenceDays(tier, score),
		ScoreFactors:      factors,
	}
}

func riskScoreFactor(id string, label string, score int, weight int, reason string) RiskScoreFactor {
	return RiskScoreFactor{ID: id, Label: label, Score: clampPercent(score), Weight: weight, Reason: strings.TrimSpace(reason)}
}

func weightedRiskScore(factors []RiskScoreFactor) int {
	totalWeight := 0
	total := 0
	for _, factor := range factors {
		if factor.Weight <= 0 {
			continue
		}
		totalWeight += factor.Weight
		total += clampPercent(factor.Score) * factor.Weight
	}
	if totalWeight == 0 {
		return 0
	}
	return clampPercent((total + (totalWeight / 2)) / totalWeight)
}

func scoreForRiskLevel(level string) int {
	switch normalizeRiskLevel(level) {
	case "critical":
		return 95
	case "high":
		return 78
	case "medium":
		return 52
	case "low":
		return 22
	default:
		return 38
	}
}

func scoreForRiskInput(value string) int {
	normalized := normalizeRiskInput(value)
	switch normalized {
	case "critical", "tier_1", "tier_0", "mission_critical", "admin", "privileged", "restricted", "sensitive", "confidential", "phi", "pii", "pci", "production", "write":
		return 90
	case "high", "tier_2", "important", "internal", "personal_data", "read_write", "sso":
		return 72
	case "medium", "moderate", "tier_3", "business":
		return 50
	case "low", "minimal", "public", "none", "read_only", "false":
		return 18
	case "":
		return 35
	default:
		if strings.Contains(normalized, "sensitive") || strings.Contains(normalized, "critical") || strings.Contains(normalized, "admin") {
			return 84
		}
		return 45
	}
}

func scoreForBooleanish(value string) int {
	switch normalizeBooleanish(value) {
	case "true":
		return 68
	case "false":
		return 10
	case "":
		return 30
	default:
		return scoreForRiskInput(value)
	}
}

func scoreForControlPosture(vendor Vendor) int {
	score := 0
	for _, status := range []string{vendor.DPAStatus, vendor.SOC2Status, vendor.ISO27001Status, vendor.SecurityReviewStatus, vendor.PrivacyReviewStatus} {
		switch status {
		case FreshnessStateExpired, ReviewStateOverdue:
			score = maxInt(score, 86)
		case FreshnessStateMissing, ReviewStateNotScheduled:
			score = maxInt(score, 72)
		case FreshnessStateStale, ReviewStateDueSoon:
			score = maxInt(score, 52)
		}
	}
	return score
}

func vendorControlRiskReason(vendor Vendor) string {
	reasons := []string{}
	for _, item := range []struct {
		label  string
		status string
	}{
		{"DPA", vendor.DPAStatus},
		{"SOC 2", vendor.SOC2Status},
		{"ISO 27001", vendor.ISO27001Status},
		{"Security review", vendor.SecurityReviewStatus},
		{"Privacy review", vendor.PrivacyReviewStatus},
	} {
		if item.status == FreshnessStateMissing || item.status == FreshnessStateExpired || item.status == ReviewStateOverdue {
			reasons = append(reasons, item.label+" "+item.status)
		}
	}
	return strings.Join(reasons, ", ")
}

func scoreForFindings(vendor Vendor) int {
	switch {
	case vendor.CriticalFindings > 0:
		return 100
	case vendor.HighFindings > 0:
		return 82
	case vendor.OpenFindings > 0:
		return 55
	default:
		return 0
	}
}

func vendorFindingRiskReason(vendor Vendor) string {
	switch {
	case vendor.CriticalFindings > 0:
		return fmt.Sprintf("%d critical open", vendor.CriticalFindings)
	case vendor.HighFindings > 0:
		return fmt.Sprintf("%d high open", vendor.HighFindings)
	case vendor.OpenFindings > 0:
		return fmt.Sprintf("%d open", vendor.OpenFindings)
	default:
		return "no open findings"
	}
}

func scoreForFreshness(state string) int {
	switch state {
	case FreshnessStateExpired:
		return 80
	case FreshnessStateStale:
		return 62
	case FreshnessStateMissing:
		return 40
	case FreshnessStateCurrent:
		return 8
	default:
		return 32
	}
}

func scoreForLifecycle(state string) int {
	switch state {
	case LifecycleStateRestricted:
		return 72
	case LifecycleStateConditionallyApproved:
		return 55
	case LifecycleStateCandidate, LifecycleStateDiscovered, LifecycleStateInReview:
		return 42
	case LifecycleStateApproved, LifecycleStateActive:
		return 10
	case LifecycleStateRetired, LifecycleStateRejected, LifecycleStateIgnored:
		return 0
	default:
		return 30
	}
}

func scoreLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func vendorRiskTier(score int, vendor Vendor) string {
	if explicit := normalizeRiskInput(firstNonEmpty(vendor.Attributes["risk_tier"], vendor.Attributes["vendor_tier"], vendor.Attributes["tier"])); explicit != "" {
		return explicit
	}
	if score >= 80 || scoreForRiskInput(vendor.Criticality) >= 90 || scoreForRiskInput(vendor.SystemDependency) >= 90 {
		return "tier_1"
	}
	if score >= 60 || scoreForRiskInput(vendor.DataSensitivity) >= 72 || scoreForRiskInput(vendor.AccessLevel) >= 72 {
		return "tier_2"
	}
	if score >= 35 {
		return "tier_3"
	}
	return "tier_4"
}

func reviewCadenceDays(tier string, score int) int {
	switch normalizeRiskInput(tier) {
	case "tier_1", "critical":
		return 180
	case "tier_2", "high":
		return 365
	case "tier_3", "medium":
		return 730
	case "tier_4", "low":
		return 1095
	default:
		if score >= 80 {
			return 180
		}
		if score >= 60 {
			return 365
		}
		if score >= 35 {
			return 730
		}
		return 1095
	}
}

func vendorAssessmentPosture(vendor Vendor, now time.Time) VendorAssessmentPosture {
	attrs := vendor.Attributes
	openAssessments := maxInt(intAttribute(attrs, "open_assessment_count", "open_assessments"), 0)
	completedAssessments := maxInt(intAttribute(attrs, "completed_assessment_count", "completed_assessments"), 0)
	if vendor.SecurityReviewCount > completedAssessments {
		completedAssessments = vendor.SecurityReviewCount
	}
	if vendor.QuestionnaireCount > 0 && completedAssessments == 0 {
		completedAssessments = vendor.QuestionnaireCount
	}
	state := normalizeAssessmentState(firstNonEmpty(attrs["assessment_state"], attrs["assessment_status"], attrs["vendor_assessment_status"]))
	if state == "" {
		state = vendor.ReviewState
		if openAssessments > 0 {
			state = "in_progress"
		}
		if state == ReviewStateCurrent && completedAssessments == 0 && vendor.QuestionnaireCount == 0 {
			state = FreshnessStateMissing
		}
	}
	progress := intAttribute(attrs, "assessment_progress", "assessment_progress_pct", "assessment_progress_percent")
	if progress < 0 {
		progress = inferredProgressForState(state)
	}
	questionnaireState := normalizeAssessmentState(firstNonEmpty(attrs["questionnaire_state"], attrs["questionnaire_status"]))
	if questionnaireState == "" && vendor.QuestionnaireCount > 0 {
		questionnaireState = FreshnessStateCurrent
	}
	questionnaireProgress := intAttribute(attrs, "questionnaire_progress", "questionnaire_progress_pct", "questionnaire_progress_percent")
	if questionnaireProgress < 0 {
		questionnaireProgress = inferredProgressForState(questionnaireState)
	}
	nextAssessmentAt := firstDate(attrs, "next_assessment_due_date", "assessment_due_date", "next_vendor_review_due_date")
	if nextAssessmentAt == nil {
		nextAssessmentAt = vendor.ReviewDueAt
	}
	if state == ReviewStateCurrent && nextAssessmentAt != nil {
		state = dateState(nextAssessmentAt, now, dueSoonDays)
	}
	return VendorAssessmentPosture{
		AssessmentState:       state,
		AssessmentProgress:    clampPercent(progress),
		OpenAssessments:       openAssessments,
		CompletedAssessments:  completedAssessments,
		AssessmentTypes:       dedupeStrings(splitAttribute(firstNonEmpty(attrs["assessment_types"], attrs["assessment_type"], attrs["review_types"]))),
		QuestionnaireState:    questionnaireState,
		QuestionnaireProgress: clampPercent(questionnaireProgress),
		LastAssessmentAt:      firstDate(attrs, "last_assessment_completed_at", "last_assessment_date", "last_security_review_completion_date"),
		NextAssessmentAt:      nextAssessmentAt,
	}
}

func normalizeAssessmentState(value string) string {
	normalized := normalizeDocumentStatusValue(value)
	switch normalized {
	case "open", "pending", "started", "in_review", "review":
		return "in_progress"
	case "passed", "approved", "complete", "completed":
		return FreshnessStateCurrent
	default:
		return normalized
	}
}

func inferredProgressForState(state string) int {
	switch state {
	case FreshnessStateCurrent:
		return 100
	case "in_progress":
		return 50
	case ReviewStateDueSoon:
		return 25
	case ReviewStateOverdue, FreshnessStateMissing, "":
		return 0
	default:
		return 0
	}
}

func vendorCommercialPosture(attrs map[string]string, now time.Time) VendorCommercialPosture {
	renewalNoticeAt := firstDate(attrs, "renewal_notice_date", "contract_notice_date", "renewal_notice_at")
	return VendorCommercialPosture{
		SpendAmount:      firstNonEmpty(attrs["annual_spend"], attrs["spend_amount"], attrs["vendor_spend"]),
		SpendCurrency:    firstNonEmpty(attrs["spend_currency"], attrs["currency"]),
		ContractValue:    firstNonEmpty(attrs["contract_value"], attrs["annual_contract_value"]),
		ContractCurrency: firstNonEmpty(attrs["contract_currency"], attrs["currency"]),
		RenewalNoticeAt:  renewalNoticeAt,
		RenewalState:     dateState(renewalNoticeAt, now, 90),
		PrimaryContact:   firstNonEmpty(attrs["primary_contact"], attrs["vendor_contact"], attrs["account_manager"], attrs["contact_email"]),
		BusinessUnit:     firstNonEmpty(attrs["business_unit"], attrs["department"]),
		CostCenter:       attrs["cost_center"],
	}
}

func vendorMonitoringPosture(vendor Vendor) VendorMonitoringPosture {
	attrs := vendor.Attributes
	signals := []VendorMonitoringSignal{}
	add := func(signal VendorMonitoringSignal) {
		if strings.TrimSpace(signal.ID) == "" || strings.TrimSpace(signal.Label) == "" {
			return
		}
		if strings.TrimSpace(signal.Severity) == "" {
			signal.Severity = "medium"
		}
		signals = append(signals, signal)
	}
	if vendor.CriticalFindings > 0 {
		add(vendorMonitoringSignal("critical_findings", "Critical findings open", "critical", "findings", nil, fmt.Sprintf("%d critical findings", vendor.CriticalFindings)))
	} else if vendor.HighFindings > 0 {
		add(vendorMonitoringSignal("high_findings", "High findings open", "high", "findings", nil, fmt.Sprintf("%d high findings", vendor.HighFindings)))
	}
	if vendor.EvidenceFreshnessState == FreshnessStateExpired || vendor.EvidenceFreshnessState == FreshnessStateStale {
		add(vendorMonitoringSignal("freshness", "Evidence "+vendor.EvidenceFreshnessState, "medium", "evidence", nil, "Freshness clock requires review"))
	}
	if vendor.LifecycleState == LifecycleStateRestricted || vendor.LifecycleState == LifecycleStateConditionallyApproved {
		add(vendorMonitoringSignal("lifecycle", "Vendor "+strings.ReplaceAll(vendor.LifecycleState, "_", " "), "medium", "lifecycle", nil, "Lifecycle condition requires review"))
	}
	externalRating := firstNonEmpty(attrs["external_security_rating"], attrs["security_rating"], attrs["external_rating"])
	if badExternalRating(externalRating) {
		add(vendorMonitoringSignal("external_rating", "External rating "+externalRating, "high", "external_rating", firstDate(attrs, "external_rating_updated_at", "security_rating_updated_at"), "External monitoring rating requires review"))
	}
	if count := intAttribute(attrs, "breached_credential_count", "leaked_credential_count"); count > 0 {
		add(vendorMonitoringSignal("breached_credentials", "Breached credentials", "high", "external_intel", firstDate(attrs, "breached_credentials_observed_at"), fmt.Sprintf("%d exposed credentials", count)))
	}
	if count := intAttribute(attrs, "security_incident_count", "public_incident_count"); count > 0 {
		add(vendorMonitoringSignal("public_incidents", "Public incidents", "high", "external_intel", firstDate(attrs, "last_security_incident_at", "last_public_incident_at"), fmt.Sprintf("%d incidents", count)))
	}
	if materialChangeAt := firstDate(attrs, "last_material_change_at", "last_vendor_change_at", "material_change_at"); materialChangeAt != nil {
		add(vendorMonitoringSignal("material_change", "Material change", "medium", "source", materialChangeAt, "Vendor profile changed"))
	}
	state := "clear"
	for _, signal := range signals {
		switch signal.Severity {
		case "critical":
			state = "critical"
		case "high":
			if state != "critical" {
				state = "alert"
			}
		case "medium":
			if state == "clear" {
				state = "watch"
			}
		}
	}
	if override := normalizeRiskInput(attrs["monitoring_state"]); override != "" {
		state = override
	}
	return VendorMonitoringPosture{
		MonitoringState:         state,
		MonitoringSignals:       signals,
		ExternalRating:          externalRating,
		ExternalRatingUpdatedAt: firstDate(attrs, "external_rating_updated_at", "security_rating_updated_at"),
		LastMaterialChangeAt:    firstDate(attrs, "last_material_change_at", "last_vendor_change_at", "material_change_at"),
	}
}

func vendorMonitoringSignal(id string, label string, severity string, source string, observedAt *time.Time, reason string) VendorMonitoringSignal {
	return VendorMonitoringSignal{ID: id, Label: label, Severity: severity, Source: source, ObservedAt: observedAt, Reason: reason}
}

func vendorOperationalPosture(vendor Vendor, now time.Time) VendorOperationalPosture {
	exposureLevel, exposureReasons := vendorExposurePosture(vendor)
	packetReadyItems, packetMissingItems := vendorPacketReadiness(vendor)
	remediationDueAt := firstDate(vendor.Attributes, "next_remediation_due_date", "remediation_due_date", "risk_treatment_due_date", "finding_sla_due_date")
	openRemediationItems := maxInt(intAttribute(vendor.Attributes, "open_remediation_count", "open_remediation_items", "open_risk_treatment_count"), 0)
	if openRemediationItems == 0 {
		openRemediationItems = vendor.OpenFindings
	}
	overdueRemediationItems := maxInt(intAttribute(vendor.Attributes, "overdue_remediation_count", "overdue_remediation_items", "overdue_risk_treatment_count"), 0)
	remediationState := normalizeOperationalState(firstNonEmpty(vendor.Attributes["remediation_state"], vendor.Attributes["risk_treatment_state"], vendor.Attributes["remediation_status"]))
	if remediationState == "" {
		remediationState = remediationStateFromCounts(openRemediationItems, remediationDueAt, now)
	}
	if remediationState == ReviewStateOverdue && overdueRemediationItems == 0 && openRemediationItems > 0 {
		overdueRemediationItems = openRemediationItems
	}
	offboardingDueAt := firstDate(vendor.Attributes, "offboarding_due_date", "termination_due_date", "vendor_offboarding_due_date", "data_deletion_due_date")
	dataDeletionState := normalizeOperationalState(firstNonEmpty(vendor.Attributes["data_deletion_state"], vendor.Attributes["data_deletion_status"], vendor.Attributes["data_return_status"]))
	if dataDeletionState == "" {
		dataDeletionState = FreshnessStateUnknown
	}
	offboardingState := normalizeOperationalState(firstNonEmpty(vendor.Attributes["offboarding_state"], vendor.Attributes["offboarding_status"]))
	if offboardingState == "" {
		offboardingState = offboardingStateFromLifecycle(vendor, offboardingDueAt, now)
	}
	return VendorOperationalPosture{
		ExposureLevel:           exposureLevel,
		ExposureReasons:         exposureReasons,
		PacketState:             vendorPacketState(vendor, packetMissingItems),
		PacketReadyItems:        packetReadyItems,
		PacketMissingItems:      packetMissingItems,
		RemediationState:        remediationState,
		RemediationDueAt:        remediationDueAt,
		OpenRemediationItems:    openRemediationItems,
		OverdueRemediationItems: overdueRemediationItems,
		OffboardingState:        offboardingState,
		OffboardingDueAt:        offboardingDueAt,
		DataDeletionState:       dataDeletionState,
	}
}

func vendorExposurePosture(vendor Vendor) (string, []string) {
	score := 0
	reasons := []string{}
	add := func(reason string, value int) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, reason)
		}
		score = maxInt(score, value)
	}
	if value := scoreForRiskInput(vendor.DataSensitivity); value >= 72 {
		add("Sensitive data", value)
	}
	if value := scoreForRiskInput(vendor.AccessLevel); value >= 72 {
		add("Privileged access", value)
	}
	if value := maxInt(scoreForRiskInput(vendor.Criticality), scoreForRiskInput(vendor.SystemDependency)); value >= 72 {
		add("Business-critical service", value)
	}
	if normalizeBooleanish(vendor.Subprocessor) == "true" {
		add("Fourth-party dependency", 68)
	}
	for _, item := range []struct {
		key    string
		label  string
		weight int
	}{
		{"internet_exposed", "Internet-facing service", 72},
		{"customer_data", "Customer data", 72},
		{"regulated_data", "Regulated data", 86},
		{"payment_data", "Payment data", 86},
		{"health_data", "Health data", 86},
		{"employee_data", "Employee data", 64},
		{"ai_data_use", "AI data use", 58},
	} {
		if normalizeBooleanish(vendor.Attributes[item.key]) == "true" {
			add(item.label, item.weight)
		}
	}
	if explicit := normalizeRiskLevel(firstNonEmpty(vendor.Attributes["exposure_level"], vendor.Attributes["vendor_exposure_level"])); explicit != "" {
		return explicit, dedupeStrings(reasons)
	}
	score = maxInt(score, vendor.RiskScore)
	switch {
	case score >= 85:
		return "critical", dedupeStrings(reasons)
	case score >= 65:
		return "high", dedupeStrings(reasons)
	case score >= 35:
		return "medium", dedupeStrings(reasons)
	default:
		return "low", dedupeStrings(reasons)
	}
}

func vendorPacketReadiness(vendor Vendor) ([]string, []string) {
	ready := []string{}
	missing := []string{}
	add := func(label string, ok bool) {
		if ok {
			ready = append(ready, label)
			return
		}
		missing = append(missing, label)
	}
	add("Owner", vendor.OwnerState == OwnerStateAssigned)
	add("Security review", vendor.ReviewState == ReviewStateCurrent || vendor.ReviewState == ReviewStateDueSoon)
	add("DPA", vendor.DPAStatus == FreshnessStateCurrent || vendor.DPAStatus == "not_applicable")
	add("Fresh evidence", vendor.EvidenceFreshnessState == FreshnessStateCurrent)
	if vendor.RiskTier == "tier_1" || vendor.RiskTier == "tier_2" {
		add("Assessment", vendor.AssessmentState == FreshnessStateCurrent || vendor.AssessmentState == ReviewStateDueSoon)
		add("Vendor contact", strings.TrimSpace(vendor.PrimaryContact) != "")
	}
	add("Monitoring", vendor.MonitoringState == "clear" || vendor.MonitoringState == "watch" || vendor.MonitoringState == "")
	add("Critical findings", vendor.CriticalFindings == 0)
	return dedupeStrings(ready), dedupeStrings(missing)
}

func vendorPacketState(vendor Vendor, missing []string) string {
	if len(missing) == 0 {
		return "ready"
	}
	blocking := map[string]struct{}{
		"Owner":             {},
		"Security review":   {},
		"DPA":               {},
		"Critical findings": {},
	}
	if vendor.EvidenceFreshnessState == FreshnessStateExpired || vendor.MonitoringState == "critical" {
		return "blocked"
	}
	for _, item := range missing {
		if _, ok := blocking[item]; ok {
			return "blocked"
		}
	}
	return "needs_work"
}

func remediationStateFromCounts(openRemediationItems int, remediationDueAt *time.Time, now time.Time) string {
	if openRemediationItems == 0 {
		return FreshnessStateCurrent
	}
	if remediationDueAt == nil {
		return "in_progress"
	}
	state := dateState(remediationDueAt, now, 14)
	if state == ReviewStateCurrent {
		return "in_progress"
	}
	return state
}

func offboardingStateFromLifecycle(vendor Vendor, offboardingDueAt *time.Time, now time.Time) string {
	switch vendor.LifecycleState {
	case LifecycleStateRetired:
		return FreshnessStateCurrent
	case LifecycleStateOffboarding:
		state := dateState(offboardingDueAt, now, 14)
		if state == "" || state == ReviewStateCurrent {
			state = "in_progress"
		}
		return state
	default:
		return ""
	}
}

func normalizeOperationalState(value string) string {
	normalized := normalizeDocumentStatusValue(value)
	switch normalized {
	case "open", "pending", "started", "review", "in_review":
		return "in_progress"
	case "resolved", "closed", "complete", "completed":
		return FreshnessStateCurrent
	default:
		return normalized
	}
}

func badExternalRating(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "f", "d", "poor", "bad", "low", "critical", "high", "at_risk", "watch":
		return true
	default:
		return false
	}
}

func vendorFreshnessPosture(attrs map[string]string, now time.Time) VendorFreshnessPosture {
	clocks := []FreshnessClock{
		observedFreshnessClock("source_runtime", "Source runtime", "runtime", firstDate(attrs, "source_runtime_fresh_at", "last_source_sync_at", "last_synced_at", "source_last_seen_at", "last_observed_at"), daysAttribute(attrs, 2, "source_runtime_stale_after_days", "source_stale_after_days"), now),
		observedFreshnessClock("artifact_age", "Artifact age", "artifact", firstDate(attrs, "artifact_created_at", "assurance_document_created_at", "document_created_at", "evidence_created_at"), daysAttribute(attrs, 365, "artifact_stale_after_days", "document_stale_after_days"), now),
		observedFreshnessClock("review_completion", "Review completion", "review", firstDate(attrs, "last_security_review_completion_date", "last_review_completed_at", "review_completed_at"), daysAttribute(attrs, 365, "review_stale_after_days", "security_review_stale_after_days"), now),
		expiryFreshnessClock("document_expiry", "Document expiry", "document", firstDate(attrs, "document_expiry_date", "assurance_document_expiry_date", "dpa_expiry_date", "soc2_expiry_date", "certificate_expiry_date"), now),
		observedFreshnessClock("control_evidence", "Control evidence", "control", firstDate(attrs, "last_control_evidence_at", "control_evidence_updated_at", "last_evidence_at"), daysAttribute(attrs, 90, "control_evidence_stale_after_days", "evidence_stale_after_days"), now),
	}
	return VendorFreshnessPosture{
		EvidenceFreshnessState: overallFreshnessState(clocks),
		EvidenceFreshness:      clocks,
	}
}

func observedFreshnessClock(id string, label string, source string, observedAt *time.Time, staleAfterDays int, now time.Time) FreshnessClock {
	clock := FreshnessClock{
		ID:             id,
		Label:          label,
		Source:         source,
		Status:         FreshnessStateMissing,
		ObservedAt:     observedAt,
		StaleAfterDays: staleAfterDays,
	}
	if observedAt == nil {
		clock.Reason = label + " timestamp is missing"
		return clock
	}
	clock.AgeDays = ageDays(*observedAt, now)
	clock.Status = FreshnessStateCurrent
	clock.Reason = label + " is within freshness window"
	if staleAfterDays > 0 && clock.AgeDays > staleAfterDays {
		clock.Status = FreshnessStateStale
		clock.Reason = fmt.Sprintf("%s is %d days old", label, clock.AgeDays)
	}
	return clock
}

func expiryFreshnessClock(id string, label string, source string, expiresAt *time.Time, now time.Time) FreshnessClock {
	clock := FreshnessClock{
		ID:        id,
		Label:     label,
		Source:    source,
		Status:    FreshnessStateMissing,
		ExpiresAt: expiresAt,
	}
	if expiresAt == nil {
		clock.Reason = label + " date is missing"
		return clock
	}
	clock.Status = FreshnessStateCurrent
	clock.Reason = label + " is current"
	if dateBefore(*expiresAt, now) {
		clock.Status = FreshnessStateExpired
		clock.Reason = label + " is expired"
	}
	return clock
}

func overallFreshnessState(clocks []FreshnessClock) string {
	hasStale := false
	hasMissing := false
	hasCurrent := false
	for _, clock := range clocks {
		switch clock.Status {
		case FreshnessStateExpired:
			return FreshnessStateExpired
		case FreshnessStateStale:
			hasStale = true
		case FreshnessStateMissing:
			hasMissing = true
		case FreshnessStateCurrent:
			hasCurrent = true
		}
	}
	switch {
	case hasStale:
		return FreshnessStateStale
	case hasMissing:
		return FreshnessStateMissing
	case hasCurrent:
		return FreshnessStateCurrent
	default:
		return FreshnessStateUnknown
	}
}

func vendorQueuePosture(vendor Vendor) VendorQueuePosture {
	var posture VendorQueuePosture
	if !vendorLifecycleIsQueueable(vendor) {
		return posture
	}
	addQueueItem := func(rank int, reason string, action VendorAction, closeAction VendorCloseAction) {
		if strings.TrimSpace(reason) == "" {
			return
		}
		if rank > posture.RiskQueueRank {
			posture.RiskQueueRank = rank
		}
		posture.QueueReasons = append(posture.QueueReasons, reason)
		if action.ID != "" {
			posture.NextActions = append(posture.NextActions, action)
		}
		if closeAction.ID != "" {
			posture.CloseActions = append(posture.CloseActions, closeAction)
		}
	}
	if vendor.OwnerState == OwnerStateMissing {
		addQueueItem(80, "owner missing", vendorAction("assign_owner", "Assign owner", "Owner missing", "owner", OwnerStateAssigned, 80), vendorCloseAction("owner_restored", "Owner restored", "Set security_owner_user_id or business_owner_user_id", "grc-vendor-review-overdue"))
	}
	switch vendor.ReviewState {
	case ReviewStateOverdue:
		addQueueItem(75, "review overdue", vendorAction("complete_review", "Complete review", "Security review overdue", "review", ReviewStateCurrent, 75), vendorCloseAction("review_current", "Review current", "Complete review or move next_security_review_due_date forward", "grc-vendor-review-overdue"))
	case ReviewStateDueSoon:
		addQueueItem(45, "review due soon", vendorAction("schedule_review", "Schedule review", "Security review due soon", "review", ReviewStateCurrent, 45), VendorCloseAction{})
	case ReviewStateNotScheduled:
		addQueueItem(35, "review not scheduled", vendorAction("set_review_due_date", "Set review date", "No review due date", "review", ReviewStateCurrent, 35), VendorCloseAction{})
	}
	if vendor.DPAStatus == FreshnessStateMissing || vendor.DPAStatus == FreshnessStateExpired {
		addQueueItem(65, "DPA "+vendor.DPAStatus, vendorAction("attach_dpa", "Attach DPA", "DPA "+vendor.DPAStatus, "document", FreshnessStateCurrent, 65), vendorCloseAction("dpa_attached", "DPA attached", "Attach a current DPA or mark DPA not applicable", "vendor-dpa"))
	}
	if vendor.EvidenceFreshnessState == FreshnessStateStale || vendor.EvidenceFreshnessState == FreshnessStateExpired {
		addQueueItem(60, "evidence "+vendor.EvidenceFreshnessState, vendorAction("refresh_evidence", "Refresh evidence", "Evidence "+vendor.EvidenceFreshnessState, "evidence", FreshnessStateCurrent, 60), vendorCloseAction("evidence_refreshed", "Evidence refreshed", "Attach fresh evidence or update source freshness timestamps", "vendor-evidence"))
	}
	if vendor.CriticalFindings > 0 {
		addQueueItem(90, "critical findings open", vendorAction("resolve_critical_findings", "Resolve critical findings", "Critical findings open", "finding", "resolved", 90), vendorCloseAction("critical_findings_resolved", "Critical findings resolved", "Resolve or risk-accept all linked critical findings", "vendor-findings"))
	} else if vendor.HighFindings > 0 {
		addQueueItem(70, "high findings open", vendorAction("resolve_high_findings", "Resolve high findings", "High findings open", "finding", "resolved", 70), vendorCloseAction("high_findings_resolved", "High findings resolved", "Resolve or risk-accept all linked high findings", "vendor-findings"))
	}
	if vendor.LifecycleState == LifecycleStateRestricted || vendor.LifecycleState == LifecycleStateConditionallyApproved {
		addQueueItem(55, vendor.LifecycleState, vendorAction("clear_vendor_condition", "Clear condition", "Vendor "+strings.ReplaceAll(vendor.LifecycleState, "_", " "), "lifecycle", LifecycleStateApproved, 55), vendorCloseAction("condition_cleared", "Condition cleared", "Move vendor to approved, offboarding, retired, or accepted restricted state", "vendor-lifecycle"))
	}
	switch vendor.AssessmentState {
	case ReviewStateOverdue:
		addQueueItem(72, "assessment overdue", vendorAction("complete_assessment", "Complete assessment", "Assessment overdue", "assessment", FreshnessStateCurrent, 72), vendorCloseAction("assessment_current", "Assessment current", "Complete the assessment or move next_assessment_due_date forward", "vendor-assessment"))
	case "in_progress":
		addQueueItem(50, "assessment in progress", vendorAction("finish_assessment", "Finish assessment", "Assessment in progress", "assessment", FreshnessStateCurrent, 50), vendorCloseAction("assessment_completed", "Assessment completed", "Complete the open assessment", "vendor-assessment"))
	case FreshnessStateMissing:
		addQueueItem(48, "assessment missing", vendorAction("start_assessment", "Start assessment", "Assessment missing", "assessment", "in_progress", 48), vendorCloseAction("assessment_started", "Assessment started", "Start or attach a vendor assessment", "vendor-assessment"))
	}
	if vendor.MonitoringState == "critical" || vendor.MonitoringState == "alert" {
		addQueueItem(85, "monitoring alert", vendorAction("review_monitoring", "Review monitoring", "Monitoring alert", "monitoring", "clear", 85), vendorCloseAction("monitoring_clear", "Monitoring clear", "Resolve or accept active monitoring signals", "vendor-monitoring"))
	}
	switch vendor.PacketState {
	case "blocked":
		addQueueItem(82, "packet blocked", vendorAction("complete_vendor_packet", "Complete packet", "Vendor packet blocked", "packet", "ready", 82), vendorCloseAction("packet_ready", "Packet ready", "Clear missing packet items", "vendor-packet"))
	case "needs_work":
		addQueueItem(44, "packet needs work", vendorAction("finish_vendor_packet", "Finish packet", "Vendor packet needs work", "packet", "ready", 44), vendorCloseAction("packet_ready", "Packet ready", "Clear missing packet items", "vendor-packet"))
	}
	switch vendor.RemediationState {
	case ReviewStateOverdue:
		addQueueItem(88, "remediation overdue", vendorAction("complete_remediation", "Complete remediation", "Remediation overdue", "remediation", FreshnessStateCurrent, 88), vendorCloseAction("remediation_current", "Remediation current", "Resolve, accept, or move remediation due date forward", "vendor-remediation"))
	case ReviewStateDueSoon:
		addQueueItem(58, "remediation due soon", vendorAction("review_remediation", "Review remediation", "Remediation due soon", "remediation", FreshnessStateCurrent, 58), VendorCloseAction{})
	}
	if vendor.RenewalState == ReviewStateOverdue || vendor.RenewalState == ReviewStateDueSoon {
		addQueueItem(42, "renewal "+vendor.RenewalState, vendorAction("review_renewal", "Review renewal", "Renewal "+vendor.RenewalState, "contract", ReviewStateCurrent, 42), VendorCloseAction{})
	}
	if vendor.OffboardingState == ReviewStateOverdue || vendor.OffboardingState == ReviewStateDueSoon || (vendor.LifecycleState == LifecycleStateOffboarding && vendor.DataDeletionState != FreshnessStateCurrent && vendor.DataDeletionState != "not_applicable") {
		addQueueItem(62, "offboarding incomplete", vendorAction("complete_offboarding", "Complete offboarding", "Offboarding incomplete", "offboarding", FreshnessStateCurrent, 62), vendorCloseAction("offboarding_complete", "Offboarding complete", "Revoke access and complete data deletion or return", "vendor-offboarding"))
	}
	if vendor.PrimaryContact == "" && (vendor.RiskTier == "tier_1" || vendor.RiskTier == "tier_2") {
		addQueueItem(38, "vendor contact missing", vendorAction("set_vendor_contact", "Set vendor contact", "Vendor contact missing", "contact", "assigned", 38), VendorCloseAction{})
	}
	return posture
}

func vendorAction(id string, label string, reason string, actionType string, targetState string, priority int) VendorAction {
	return VendorAction{ID: id, Label: label, Reason: reason, ActionType: actionType, TargetState: targetState, Priority: priority}
}

func vendorCloseAction(id string, label string, closesWhen string, findingKey string) VendorCloseAction {
	return VendorCloseAction{ID: id, Label: label, ClosesWhen: closesWhen, FindingKey: findingKey}
}

func normalizeVendorLifecycleState(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "":
		return ""
	case "all":
		return "all"
	case "new", "discovered", "shadow", "unreviewed":
		return LifecycleStateDiscovered
	case "candidate", "pending", "pending_review", "needs_review":
		return LifecycleStateCandidate
	case "active", "enabled", "current", "monitored":
		return LifecycleStateActive
	case "in_review", "review", "under_review":
		return LifecycleStateInReview
	case "approved", "complete", "completed":
		return LifecycleStateApproved
	case "conditionally_approved", "conditional", "approved_with_conditions":
		return LifecycleStateConditionallyApproved
	case "restricted", "limited":
		return LifecycleStateRestricted
	case "offboarding", "terminating", "decommissioning":
		return LifecycleStateOffboarding
	case "retired", "terminated", "offboarded", "inactive", "archived", "deleted", "disabled":
		return LifecycleStateRetired
	case "rejected", "denied":
		return LifecycleStateRejected
	case "ignored":
		return LifecycleStateIgnored
	default:
		return normalized
	}
}

func normalizeRiskInput(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	return strings.ReplaceAll(normalized, " ", "_")
}

func normalizeBooleanish(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "true", "1", "yes", "y":
		return "true"
	case "false", "0", "no", "n":
		return "false"
	default:
		return normalizeRiskInput(value)
	}
}

func vendorRiskDrivers(attrs map[string]string) []string {
	drivers := splitAttribute(firstNonEmpty(attrs["risk_drivers"], attrs["risk_reason"], attrs["risk_reasons"]))
	for _, key := range []string{"data_sensitivity", "access_level", "criticality", "subprocessor", "geography", "system_dependency"} {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			drivers = append(drivers, key+":"+normalizeRiskInput(value))
		}
	}
	return dedupeStrings(drivers)
}

func normalizeDocumentStatus(attrs map[string]string, now time.Time, keys ...string) string {
	for _, key := range keys {
		if status := normalizeDocumentStatusValue(firstNonEmpty(attrs[key+"_status"], attrs[key+"_state"])); status != "" {
			return status
		}
		if expiresAt := firstDate(attrs, key+"_expiry_date", key+"_expires_at", key+"_expiration_date"); expiresAt != nil && dateBefore(*expiresAt, now) {
			return FreshnessStateExpired
		}
		if value := strings.ToLower(strings.TrimSpace(firstNonEmpty(attrs[key+"_attached"], attrs[key+"_signed"], attrs[key+"_available"], attrs[key]))); value != "" {
			switch value {
			case "true", "1", "yes", "signed", "attached", "available", "current", "complete", "completed":
				return FreshnessStateCurrent
			case "false", "0", "no", "missing", "not_found", "none":
				return FreshnessStateMissing
			case "not_applicable", "not applicable", "n/a", "na":
				return "not_applicable"
			}
			return normalizeDocumentStatusValue(value)
		}
	}
	return FreshnessStateUnknown
}

func normalizeDocumentStatusValue(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "":
		return ""
	case "attached", "signed", "available", "complete", "completed", "current", "valid":
		return FreshnessStateCurrent
	case "missing", "not_found", "none", "required":
		return FreshnessStateMissing
	case "expired":
		return FreshnessStateExpired
	case "stale":
		return FreshnessStateStale
	case "not_applicable", "not applicable", "n/a", "na":
		return "not_applicable"
	default:
		return normalized
	}
}

func normalizeReviewPosture(value string, dueAt *time.Time, completedAt *time.Time, now time.Time) string {
	if status := normalizeDocumentStatusValue(value); status != "" {
		return status
	}
	if dueAt != nil {
		return reviewState(dueAt, now)
	}
	if completedAt != nil {
		return FreshnessStateCurrent
	}
	return FreshnessStateMissing
}

func reviewState(dueAt *time.Time, now time.Time) string {
	if dueAt == nil {
		return ReviewStateNotScheduled
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	dueDay := time.Date(dueAt.UTC().Year(), dueAt.UTC().Month(), dueAt.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if dueDay.Before(today) {
		return ReviewStateOverdue
	}
	if !dueDay.After(today.AddDate(0, 0, dueSoonDays)) {
		return ReviewStateDueSoon
	}
	return ReviewStateCurrent
}

func riskRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func reviewRank(state string) int {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case ReviewStateOverdue:
		return 3
	case ReviewStateDueSoon:
		return 2
	case ReviewStateNotScheduled:
		return 1
	default:
		return 0
	}
}

func discoveryRank(state string) int {
	switch normalizeDiscoveryState(state) {
	case DiscoveryStateDiscovered:
		return 4
	case DiscoveryStateApproved:
		return 3
	case DiscoveryStateLinked:
		return 2
	case DiscoveryStateRejected, DiscoveryStateIgnored:
		return 1
	default:
		return 0
	}
}

func vendorIsActive(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "active", "approved", "current", "in_progress", "monitored":
		return true
	case "archived", "deleted", "disabled", "ignored", "inactive", "rejected", "terminated":
		return false
	default:
		return true
	}
}

func vendorLifecycleIsActive(vendor Vendor) bool {
	switch strings.ToLower(strings.TrimSpace(vendor.LifecycleState)) {
	case LifecycleStateDiscovered, LifecycleStateCandidate, LifecycleStateActive, LifecycleStateInReview, LifecycleStateApproved, LifecycleStateConditionallyApproved, LifecycleStateRestricted, LifecycleStateUnknown:
		return true
	case LifecycleStateOffboarding, LifecycleStateRetired, LifecycleStateRejected, LifecycleStateIgnored:
		return false
	case "":
		return vendorIsActive(vendor.Status)
	default:
		return vendorIsActive(firstNonEmpty(vendor.Status, vendor.LifecycleState))
	}
}

func vendorLifecycleIsQueueable(vendor Vendor) bool {
	switch strings.ToLower(strings.TrimSpace(vendor.LifecycleState)) {
	case LifecycleStateRetired, LifecycleStateRejected, LifecycleStateIgnored:
		return false
	case LifecycleStateOffboarding:
		return true
	default:
		return vendorLifecycleIsActive(vendor)
	}
}

func normalizeDiscoveryState(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "", "new", "pending", "needs_review":
		return DiscoveryStateDiscovered
	case "approve", "approved":
		return DiscoveryStateApproved
	case "reject", "rejected":
		return DiscoveryStateRejected
	case "ignore", "ignored":
		return DiscoveryStateIgnored
	case "link", "linked":
		return DiscoveryStateLinked
	default:
		return normalized
	}
}

func normalizeDiscoveryFilter(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return normalizeDiscoveryState(value)
}

func normalizeRiskLevel(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	switch {
	case strings.Contains(normalized, "critical"):
		return "critical"
	case strings.Contains(normalized, "high"):
		return "high"
	case strings.Contains(normalized, "medium"), strings.Contains(normalized, "moderate"):
		return "medium"
	case strings.Contains(normalized, "low"), strings.Contains(normalized, "minimal"):
		return "low"
	case normalized == "none" || normalized == "no risk":
		return "low"
	default:
		return normalized
	}
}

func vendorDetailParams(request VendorDetailRequest, urn string, vendorID string) map[string]any {
	vendorID = strings.TrimSpace(vendorID)
	vendorIDLower := strings.ToLower(vendorID)
	return map[string]any{
		"urn":             strings.TrimSpace(urn),
		"vendor_id":       vendorID,
		"vendor_id_lc":    vendorIDLower,
		"vendor_id_probe": jsonAttributeProbe("vendor_id", vendorIDLower),
		"external_probe":  jsonAttributeProbe("external_id", vendorIDLower),
		"tenant_id":       strings.TrimSpace(request.TenantID),
		"runtime_id":      strings.TrimSpace(request.RuntimeID),
		"runtime_ids":     nonEmptyStrings(request.RuntimeIDs),
		"source_id":       strings.TrimSpace(request.SourceID),
	}
}

func jsonAttributeProbe(key string, value string) string {
	key = strings.TrimSpace(key)
	value = strings.ToLower(strings.TrimSpace(value))
	if key == "" || value == "" {
		return "\x00"
	}
	return fmt.Sprintf("%q:%q", key, value)
}

func validateVendorDetailScope(urn string, vendorID string) error {
	if urn == "" && vendorID == "" {
		return fmt.Errorf("%w: vendor_id is required", ErrInvalidRequest)
	}
	return nil
}

func looksLikeCerebroURN(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "urn:cerebro:")
}

func parseDateAttribute(attrs map[string]string, key string) *time.Time {
	if attrs == nil {
		return nil
	}
	value := strings.TrimSpace(attrs[key])
	if value == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		utc := parsed.UTC()
		return &utc
	}
	return nil
}

func firstDate(attrs map[string]string, keys ...string) *time.Time {
	for _, key := range keys {
		if parsed := parseDateAttribute(attrs, key); parsed != nil {
			return parsed
		}
	}
	return nil
}

func daysAttribute(attrs map[string]string, fallback int, keys ...string) int {
	for _, key := range keys {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		var parsed int
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil && parsed > 0 {
			return parsed
		}
	}
	return fallback
}

func intAttribute(attrs map[string]string, keys ...string) int {
	for _, key := range keys {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		var parsed int
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
			return parsed
		}
	}
	return -1
}

func dateState(value *time.Time, now time.Time, dueSoonWindowDays int) string {
	if value == nil {
		return ""
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	valueDay := time.Date(value.UTC().Year(), value.UTC().Month(), value.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if valueDay.Before(today) {
		return ReviewStateOverdue
	}
	if dueSoonWindowDays > 0 && !valueDay.After(today.AddDate(0, 0, dueSoonWindowDays)) {
		return ReviewStateDueSoon
	}
	return ReviewStateCurrent
}

func ageDays(observedAt time.Time, now time.Time) int {
	if now.IsZero() || observedAt.IsZero() || observedAt.After(now) {
		return 0
	}
	return int(now.Sub(observedAt).Hours() / 24)
}

func dateBefore(left time.Time, right time.Time) bool {
	if left.IsZero() || right.IsZero() {
		return false
	}
	leftDay := time.Date(left.UTC().Year(), left.UTC().Month(), left.UTC().Day(), 0, 0, 0, 0, time.UTC)
	rightDay := time.Date(right.UTC().Year(), right.UTC().Month(), right.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return leftDay.Before(rightDay)
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func splitAttribute(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func dedupeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func normalizeVendorLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultVendorLimit
	case limit > maxVendorLimit:
		return maxVendorLimit
	default:
		return int(limit)
	}
}

func normalizeRelatedLimit(limit uint32) int {
	value := normalizeVendorLimit(limit)
	if value > relatedLimit {
		return relatedLimit
	}
	return value
}

func normalizeNeighborhoodLimit(limit uint32) int {
	value := normalizeRelatedLimit(limit)
	if value <= 0 {
		return 10
	}
	return value
}

func validateCerebroURN(urn string) error {
	parts := strings.Split(urn, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return fmt.Errorf("%w: urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
	}
	if parts[len(parts)-1] == "" {
		return fmt.Errorf("%w: urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
	}
	for index, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (index < 3 && part == "") {
			return fmt.Errorf("%w: urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", ErrInvalidRequest)
		}
	}
	return nil
}

func parseAttributes(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return nil
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	attrs := map[string]string{}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				attrs[key] = strings.TrimSpace(typed)
			}
		case float64, bool:
			attrs[key] = fmt.Sprint(typed)
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func rowString(row ports.CypherRow, key string) string {
	value := row.Values[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func rowInt(row ports.CypherRow, key string) int {
	value := row.Values[key]
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		var parsed int
		_, _ = fmt.Sscanf(fmt.Sprint(value), "%d", &parsed)
		return parsed
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func urnTail(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func timeValue(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return *value
}

const vendorListQuery = `MATCH (v:Entity)
WHERE v.entity_type = 'vendor'
  AND ($tenant_id = '' OR v.tenant_id = $tenant_id)
  AND ($runtime_id = '' OR v.runtime_id = $runtime_id)
  AND (size($runtime_ids) = 0 OR v.runtime_id IN $runtime_ids)
  AND ($source_id = '' OR v.source_id = $source_id)
  AND ($q = '' OR toLower(coalesce(v.label, '')) CONTAINS $q OR toLower(v.urn) CONTAINS $q OR toLower(coalesce(v.attributes_json, '')) CONTAINS $q)
OPTIONAL MATCH (v)<-[contract_rel:RELATION]-(contract:Entity)
WHERE contract_rel.relation = 'associated_with' AND contract.entity_type = 'contract'
OPTIONAL MATCH (v)<-[review_rel:RELATION]-(security_review:Entity)
WHERE review_rel.relation = 'associated_with' AND security_review.entity_type = 'security.review'
OPTIONAL MATCH (v)<-[questionnaire_rel:RELATION]-(questionnaire:Entity)
WHERE questionnaire_rel.relation = 'associated_with' AND questionnaire.entity_type = 'security.questionnaire'
OPTIONAL MATCH (v)<-[document_rel:RELATION]-(assurance_document:Entity)
WHERE document_rel.relation = 'associated_with' AND assurance_document.entity_type = 'assurance.document'
RETURN v.urn AS urn,
       v.label AS label,
       v.source_id AS source_id,
       v.runtime_id AS runtime_id,
       coalesce(v.attributes_json, '{}') AS attributes_json,
       count(DISTINCT contract) AS contract_count,
       count(DISTINCT security_review) AS security_review_count,
       count(DISTINCT questionnaire) AS questionnaire_count,
       count(DISTINCT assurance_document) AS assurance_document_count
ORDER BY v.label ASC, v.urn ASC
LIMIT $limit`

const vendorDetailQuery = `MATCH (v:Entity)
WHERE v.entity_type = 'vendor'
  AND ($tenant_id = '' OR v.tenant_id = $tenant_id)
  AND ($runtime_id = '' OR v.runtime_id = $runtime_id)
  AND (size($runtime_ids) = 0 OR v.runtime_id IN $runtime_ids)
  AND ($source_id = '' OR v.source_id = $source_id)
  AND (
    ($urn <> '' AND v.urn = $urn)
    OR
    ($vendor_id <> '' AND (
      v.urn = $vendor_id
      OR v.urn ENDS WITH ':' + $vendor_id
      OR toLower(coalesce(v.label, '')) = $vendor_id_lc
      OR toLower(coalesce(v.attributes_json, '')) CONTAINS $vendor_id_probe
      OR toLower(coalesce(v.attributes_json, '')) CONTAINS $external_probe
    ))
  )
OPTIONAL MATCH (v)<-[contract_rel:RELATION]-(contract:Entity)
WHERE contract_rel.relation = 'associated_with' AND contract.entity_type = 'contract'
OPTIONAL MATCH (v)<-[review_rel:RELATION]-(security_review:Entity)
WHERE review_rel.relation = 'associated_with' AND security_review.entity_type = 'security.review'
OPTIONAL MATCH (v)<-[questionnaire_rel:RELATION]-(questionnaire:Entity)
WHERE questionnaire_rel.relation = 'associated_with' AND questionnaire.entity_type = 'security.questionnaire'
OPTIONAL MATCH (v)<-[document_rel:RELATION]-(assurance_document:Entity)
WHERE document_rel.relation = 'associated_with' AND assurance_document.entity_type = 'assurance.document'
RETURN v.urn AS urn,
       v.label AS label,
       v.source_id AS source_id,
       v.runtime_id AS runtime_id,
       coalesce(v.attributes_json, '{}') AS attributes_json,
       count(DISTINCT contract) AS contract_count,
       count(DISTINCT security_review) AS security_review_count,
       count(DISTINCT questionnaire) AS questionnaire_count,
       count(DISTINCT assurance_document) AS assurance_document_count
LIMIT 1`

const vendorRelationshipsQuery = `MATCH (v:Entity {urn: $urn})<-[rel:RELATION]-(e:Entity)
WHERE rel.relation = 'associated_with'
  AND e.entity_type IN ['contract', 'security.review', 'security.questionnaire', 'assurance.document', 'vendor.assessment', 'privacy.assessment', 'security.assessment', 'risk.assessment', 'legal.assessment']
RETURN e.urn AS urn,
       e.entity_type AS entity_type,
       e.label AS label,
       e.source_id AS source_id,
       e.runtime_id AS runtime_id,
       rel.relation AS relation,
       coalesce(e.attributes_json, '{}') AS attributes_json
UNION
MATCH (v:Entity {urn: $urn})-[rel:RELATION]->(e:Entity)
WHERE rel.relation IN ['owned_by', 'has_identifier', 'has_contact', 'uses_subprocessor', 'depends_on']
  AND e.entity_type IN ['grc.user', 'user', 'internet.host', 'vendor.alias', 'vendor.contact', 'contact', 'vendor.fourth_party', 'fourth_party.vendor', 'subprocessor']
RETURN e.urn AS urn,
       e.entity_type AS entity_type,
       e.label AS label,
       e.source_id AS source_id,
       e.runtime_id AS runtime_id,
       rel.relation AS relation,
       coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY entity_type ASC, label ASC, urn ASC
LIMIT $limit`

const discoveryListQuery = `MATCH (d:Entity)
WHERE d.entity_type = 'vendor.discovery'
  AND ($tenant_id = '' OR d.tenant_id = $tenant_id)
  AND ($runtime_id = '' OR d.runtime_id = $runtime_id)
  AND (size($runtime_ids) = 0 OR d.runtime_id IN $runtime_ids)
  AND ($source_id = '' OR d.source_id = $source_id)
  AND ($q = '' OR toLower(coalesce(d.label, '')) CONTAINS $q OR toLower(d.urn) CONTAINS $q OR toLower(coalesce(d.attributes_json, '')) CONTAINS $q)
RETURN d.urn AS urn,
       d.label AS label,
       d.source_id AS source_id,
       d.runtime_id AS runtime_id,
       coalesce(d.attributes_json, '{}') AS attributes_json
ORDER BY d.label ASC, d.urn ASC
LIMIT $limit`

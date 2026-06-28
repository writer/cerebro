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
	VendorOwnership
	VendorRiskPosture
	VendorReviewPosture
	VendorContractDates
	VendorRecordCounts
	VendorFindingCounts
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

type VendorReviewPosture struct {
	ReviewState           string     `json:"review_state"`
	ReviewDueAt           *time.Time `json:"review_due_at,omitempty"`
	LastReviewCompletedAt *time.Time `json:"last_review_completed_at,omitempty"`
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
	TotalVendors         int `json:"total_vendors"`
	ActiveVendors        int `json:"active_vendors"`
	HighRiskVendors      int `json:"high_risk_vendors"`
	OwnerMissingVendors  int `json:"owner_missing_vendors"`
	ReviewOverdueVendors int `json:"review_overdue_vendors"`
	ReviewDueSoonVendors int `json:"review_due_soon_vendors"`
	ReviewNotScheduled   int `json:"review_not_scheduled"`
	OpenFindings         int `json:"open_findings"`
	CriticalFindings     int `json:"critical_findings"`
	HighFindings         int `json:"high_findings"`
	EvidenceItems        int `json:"evidence_items"`
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
	Graph         *ports.EntityNeighborhood `json:"graph,omitempty"`
}

type VendorRelationships struct {
	Contracts              []RelatedRecord `json:"contracts,omitempty"`
	SecurityReviews        []RelatedRecord `json:"security_reviews,omitempty"`
	SecurityQuestionnaires []RelatedRecord `json:"security_questionnaires,omitempty"`
	AssuranceDocuments     []RelatedRecord `json:"assurance_documents,omitempty"`
	Owners                 []RelatedRecord `json:"owners,omitempty"`
	Hosts                  []RelatedRecord `json:"hosts,omitempty"`
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
	if len(vendors) > limit {
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
	graph, err := s.store.GetEntityNeighborhood(ctx, urn, normalizeNeighborhoodLimit(request.Limit))
	if err != nil {
		return nil, err
	}
	return &VendorDetail{
		Vendor:        vendor,
		Relationships: relationshipsFromRows(relatedRows),
		Graph:         graph,
	}, nil
}

func Summarize(vendors []Vendor) Summary {
	var summary Summary
	summary.TotalVendors = len(vendors)
	for _, vendor := range vendors {
		if vendorIsActive(vendor.Status) {
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
	return Vendor{
		VendorIdentity: VendorIdentity{
			URN:              urn,
			VendorID:         firstNonEmpty(attrs["vendor_id"], attrs["external_id"], urnTail(urn)),
			Name:             firstNonEmpty(rowString(row, "label"), attrs["name"], attrs["vendor_id"], urnTail(urn)),
			SourceID:         rowString(row, "source_id"),
			RuntimeID:        rowString(row, "runtime_id"),
			Provider:         firstNonEmpty(attrs["source_system"], attrs["provider"], rowString(row, "source_id")),
			Status:           attrs["status"],
			Category:         attrs["category"],
			WebsiteURL:       firstNonEmpty(attrs["website_url"], attrs["website"], attrs["url"], attrs["domain"]),
			ServicesProvided: attrs["services_provided"],
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
		VendorReviewPosture: VendorReviewPosture{
			ReviewState:           reviewState(reviewDueAt, s.now()),
			ReviewDueAt:           reviewDueAt,
			LastReviewCompletedAt: lastReviewCompletedAt,
		},
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
		strings.TrimSpace(request.OwnerState) != ""
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
		case "grc.user", "user":
			result.Owners = append(result.Owners, record)
		case "internet.host":
			result.Hosts = append(result.Hosts, record)
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
  AND e.entity_type IN ['contract', 'security.review', 'security.questionnaire', 'assurance.document']
RETURN e.urn AS urn,
       e.entity_type AS entity_type,
       e.label AS label,
       e.source_id AS source_id,
       e.runtime_id AS runtime_id,
       rel.relation AS relation,
       coalesce(e.attributes_json, '{}') AS attributes_json
UNION
MATCH (v:Entity {urn: $urn})-[rel:RELATION]->(e:Entity)
WHERE rel.relation IN ['owned_by', 'has_identifier']
  AND e.entity_type IN ['grc.user', 'user', 'internet.host']
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

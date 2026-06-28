package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grcvendor"
	"github.com/writer/cerebro/internal/ports"
)

const maxGRCVendorDiscoveryDecisionBodyBytes = 32 << 10

type grcVendorsResponse struct {
	Summary     grcvendor.Summary  `json:"summary"`
	Vendors     []grcvendor.Vendor `json:"vendors"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type grcVendorDetailResponse struct {
	Vendor        grcvendor.Vendor              `json:"vendor"`
	Relationships grcvendor.VendorRelationships `json:"relationships"`
	Graph         any                           `json:"graph,omitempty"`
	Findings      []grcFindingItem              `json:"findings"`
	Evidence      []grcEvidenceItem             `json:"evidence"`
	GeneratedAt   time.Time                     `json:"generated_at"`
}

type grcVendorDiscoveriesResponse struct {
	Summary     grcvendor.DiscoverySummary                `json:"summary"`
	Discoveries []grcvendor.VendorDiscovery               `json:"discoveries"`
	Decisions   []*ports.GRCVendorDiscoveryDecisionRecord `json:"decisions,omitempty"`
	GeneratedAt time.Time                                 `json:"generated_at"`
}

type grcVendorDiscoveryDecisionRequest struct {
	TenantID        string            `json:"tenant_id,omitempty"`
	DiscoveryURN    string            `json:"discovery_urn,omitempty"`
	SourceID        string            `json:"source_id,omitempty"`
	Decision        string            `json:"decision"`
	Reason          string            `json:"reason,omitempty"`
	LinkedVendorURN string            `json:"linked_vendor_urn,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
}

type grcVendorDiscoveryDecisionResponse struct {
	Decision    *ports.GRCVendorDiscoveryDecisionRecord `json:"decision"`
	GeneratedAt time.Time                               `json:"generated_at"`
}

type grcVendorFindingMetrics struct {
	OpenFindings     int
	CriticalFindings int
	HighFindings     int
	EvidenceItems    int
}

func (a *App) handleGRCVendors(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	vendors, err := grcvendor.New(graphQueryStore(a.deps.GraphStore)).ListVendors(r.Context(), grcvendor.ListVendorsRequest{
		TenantID:    scope.TenantID,
		RuntimeID:   scope.RuntimeID,
		RuntimeIDs:  scope.RuntimeIDs,
		SourceID:    scope.SourceID,
		Query:       strings.TrimSpace(r.URL.Query().Get("q")),
		RiskLevel:   strings.TrimSpace(r.URL.Query().Get("risk_level")),
		ReviewState: strings.TrimSpace(r.URL.Query().Get("review_state")),
		OwnerState:  strings.TrimSpace(r.URL.Query().Get("owner_state")),
		Limit:       scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	vendors, err = a.enrichGRCVendors(r, scope, vendors)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcVendorsResponse{
		Summary:     grcvendor.Summarize(vendors),
		Vendors:     vendors,
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleGRCVendorDetail(w http.ResponseWriter, r *http.Request) {
	response, err := a.grcVendorDetailResponse(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGRCVendorPacket(w http.ResponseWriter, r *http.Request) {
	response, err := a.grcVendorDetailResponse(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) grcVendorDetailResponse(r *http.Request) (grcVendorDetailResponse, error) {
	vendorID := strings.TrimSpace(r.PathValue("vendorID"))
	if vendorID == "" {
		vendorID = strings.TrimSpace(r.URL.Query().Get("vendor_id"))
	}
	urn := strings.TrimSpace(r.URL.Query().Get("urn"))
	if urn == "" && strings.HasPrefix(vendorID, "urn:cerebro:") {
		urn = vendorID
		vendorID = ""
	}
	if urn != "" {
		if err := authorizeCerebroURNTenant(r.Context(), urn); err != nil {
			return grcVendorDetailResponse{}, err
		}
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	detail, err := grcvendor.New(graphQueryStore(a.deps.GraphStore)).GetVendor(r.Context(), grcvendor.VendorDetailRequest{
		URN:        urn,
		VendorID:   vendorID,
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	})
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	urn = detail.Vendor.URN
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{ResourceURN: urn, Status: "open", Limit: scope.Limit})
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	evidenceCounts, counted, err := a.grcEvidenceCountsByFindingID(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings)})
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), GraphRootURN: urn, Limit: scope.Limit})
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	if !counted {
		evidenceCounts = grcEvidenceCounts(evidence)
	}
	findingItems := grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), evidenceCounts)
	evidenceItems := grcEvidenceItems(evidence, grcFindingTitleMap(findings))
	metrics := vendorFindingMetrics(findingItems)
	detail.Vendor.OpenFindings = metrics[urn].OpenFindings
	detail.Vendor.CriticalFindings = metrics[urn].CriticalFindings
	detail.Vendor.HighFindings = metrics[urn].HighFindings
	detail.Vendor.EvidenceItems = metrics[urn].EvidenceItems
	return grcVendorDetailResponse{
		Vendor:        detail.Vendor,
		Relationships: detail.Relationships,
		Graph:         detail.Graph,
		Findings:      findingItems,
		Evidence:      evidenceItems,
		GeneratedAt:   time.Now().UTC(),
	}, nil
}

func (a *App) handleGRCVendorRiskVendors(w http.ResponseWriter, r *http.Request) {
	a.handleGRCVendors(w, r)
}

func (a *App) handleGRCVendorRiskVendorDetail(w http.ResponseWriter, r *http.Request) {
	a.handleGRCVendorDetail(w, r)
}

func (a *App) handleGRCVendorDiscoveries(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	decisionState := strings.TrimSpace(r.URL.Query().Get("decision_state"))
	discoveries, err := grcvendor.New(graphQueryStore(a.deps.GraphStore)).ListDiscoveries(r.Context(), grcvendor.ListDiscoveriesRequest{
		TenantID:      scope.TenantID,
		RuntimeID:     scope.RuntimeID,
		RuntimeIDs:    scope.RuntimeIDs,
		SourceID:      scope.SourceID,
		Query:         strings.TrimSpace(r.URL.Query().Get("q")),
		Status:        strings.TrimSpace(r.URL.Query().Get("status")),
		DecisionState: decisionState,
		Limit:         scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	decisions, err := a.listGRCVendorDiscoveryDecisions(r, scope, grcDiscoveryURNs(discoveries))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	discoveries = grcvendor.ApplyDiscoveryDecisions(discoveries, decisions)
	discoveries = grcvendor.FilterDiscoveriesByDecisionState(discoveries, decisionState)
	writeJSON(w, http.StatusOK, grcVendorDiscoveriesResponse{
		Summary:     grcvendor.SummarizeDiscoveries(discoveries),
		Discoveries: discoveries,
		Decisions:   decisions,
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleUpdateGRCVendorDiscoveryDecision(w http.ResponseWriter, r *http.Request) {
	var request grcVendorDiscoveryDecisionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCVendorDiscoveryDecisionBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode vendor discovery decision request: %w", errInvalidHTTPRequest, err))
		return
	}
	request.DiscoveryURN = strings.TrimSpace(request.DiscoveryURN)
	if request.DiscoveryURN == "" {
		request.DiscoveryURN = strings.TrimSpace(r.PathValue("discoveryID"))
	}
	if request.DiscoveryURN == "" {
		writeGRCError(w, fmt.Errorf("%w: discovery_urn is required", errInvalidHTTPRequest))
		return
	}
	if err := validateGRCVendorDiscoveryURN(request.DiscoveryURN); err != nil {
		writeGRCError(w, err)
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), request.DiscoveryURN); err != nil {
		writeGRCError(w, err)
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = tenantIDFromCerebroURN(request.DiscoveryURN)
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	request.Decision = strings.TrimSpace(request.Decision)
	if !ports.IsGRCVendorDiscoveryDecision(request.Decision) {
		writeGRCError(w, fmt.Errorf("%w: decision must be approved, rejected, ignored, or linked", errInvalidHTTPRequest))
		return
	}
	request.LinkedVendorURN = strings.TrimSpace(request.LinkedVendorURN)
	if request.LinkedVendorURN != "" {
		if err := validateGRCVendorURN(request.LinkedVendorURN); err != nil {
			writeGRCError(w, err)
			return
		}
		if err := authorizeCerebroURNTenant(r.Context(), request.LinkedVendorURN); err != nil {
			writeGRCError(w, err)
			return
		}
	}
	if request.Decision == ports.GRCVendorDiscoveryDecisionLinked && request.LinkedVendorURN == "" {
		writeGRCError(w, fmt.Errorf("%w: linked_vendor_urn is required for linked decisions", errInvalidHTTPRequest))
		return
	}
	store := grcVendorDiscoveryDecisionStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	record, err := store.UpsertGRCVendorDiscoveryDecision(r.Context(), ports.GRCVendorDiscoveryDecisionRecord{
		TenantID:        tenantID,
		DiscoveryURN:    request.DiscoveryURN,
		SourceID:        strings.TrimSpace(request.SourceID),
		Decision:        request.Decision,
		Reason:          strings.TrimSpace(request.Reason),
		LinkedVendorURN: request.LinkedVendorURN,
		UpdatedBy:       grcInventoryUpdatedBy(r),
		Attributes:      request.Attributes,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeInventory)
	writeJSON(w, http.StatusOK, grcVendorDiscoveryDecisionResponse{Decision: record, GeneratedAt: time.Now().UTC()})
}

func (a *App) enrichGRCVendors(r *http.Request, scope grcScope, vendors []grcvendor.Vendor) ([]grcvendor.Vendor, error) {
	if len(vendors) == 0 || findingStore(a.deps.StateStore) == nil {
		return vendors, nil
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		return nil, err
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{
		ResourceURNs: grcVendorURNs(vendors),
		Status:       "open",
		Limit:        grcVendorFindingLimit(len(vendors), scope.Limit),
	})
	if err != nil {
		return nil, err
	}
	evidenceCounts := map[string]int{}
	if findingEvidenceStore(a.deps.StateStore) != nil {
		var counted bool
		evidenceCounts, counted, err = a.grcEvidenceCountsByFindingID(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings)})
		if err != nil {
			return nil, err
		}
		if !counted {
			evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), Limit: grcVendorFindingLimit(len(vendors), scope.Limit)})
			if err != nil {
				return nil, err
			}
			evidenceCounts = grcEvidenceCounts(evidence)
		}
	}
	findingItems := grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), evidenceCounts)
	metrics := vendorFindingMetrics(findingItems)
	for index := range vendors {
		item := metrics[vendors[index].URN]
		vendors[index].OpenFindings = item.OpenFindings
		vendors[index].CriticalFindings = item.CriticalFindings
		vendors[index].HighFindings = item.HighFindings
		vendors[index].EvidenceItems = item.EvidenceItems
	}
	return vendors, nil
}

func vendorFindingMetrics(findings []grcFindingItem) map[string]grcVendorFindingMetrics {
	metrics := map[string]grcVendorFindingMetrics{}
	for _, finding := range findings {
		for _, urn := range finding.ResourceURNs {
			urn = strings.TrimSpace(urn)
			if urn == "" {
				continue
			}
			item := metrics[urn]
			item.OpenFindings++
			switch strings.ToUpper(strings.TrimSpace(finding.Severity)) {
			case "CRITICAL":
				item.CriticalFindings++
			case "HIGH":
				item.HighFindings++
			}
			item.EvidenceItems += finding.EvidenceCount
			metrics[urn] = item
		}
	}
	return metrics
}

func grcVendorURNs(vendors []grcvendor.Vendor) []string {
	urns := make([]string, 0, len(vendors))
	seen := map[string]struct{}{}
	for _, vendor := range vendors {
		urn := strings.TrimSpace(vendor.URN)
		if urn == "" {
			continue
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns
}

func grcDiscoveryURNs(discoveries []grcvendor.VendorDiscovery) []string {
	urns := make([]string, 0, len(discoveries))
	seen := map[string]struct{}{}
	for _, discovery := range discoveries {
		urn := strings.TrimSpace(discovery.URN)
		if urn == "" {
			continue
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		urns = append(urns, urn)
	}
	return urns
}

func (a *App) listGRCVendorDiscoveryDecisions(r *http.Request, scope grcScope, discoveryURNs []string) ([]*ports.GRCVendorDiscoveryDecisionRecord, error) {
	store := grcVendorDiscoveryDecisionStore(a.deps.StateStore)
	if store == nil || len(discoveryURNs) == 0 {
		return nil, nil
	}
	return store.ListGRCVendorDiscoveryDecisions(r.Context(), ports.GRCVendorDiscoveryDecisionFilter{
		TenantID:      scope.TenantID,
		DiscoveryURNs: discoveryURNs,
		SourceID:      scope.SourceID,
		Limit:         boundedUint32(len(discoveryURNs)),
	})
}

func grcVendorFindingLimit(vendorCount int, scopeLimit uint32) uint32 {
	limit := boundedUint32(vendorCount * 10)
	if limit < scopeLimit {
		limit = scopeLimit
	}
	if limit == 0 {
		limit = grcDefaultLimit
	}
	if limit > grcMaxLimit {
		return grcMaxLimit
	}
	return limit
}

func validateGRCVendorURN(vendorURN string) error {
	return validateGRCVendorEntityURN("vendor_urn", vendorURN, "vendor")
}

func validateGRCVendorDiscoveryURN(discoveryURN string) error {
	return validateGRCVendorEntityURN("discovery_urn", discoveryURN, "vendor_discovery")
}

func validateGRCVendorEntityURN(field string, value string, entityType string) error {
	parts := strings.Split(value, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return fmt.Errorf("%w: %s must be of the form urn:cerebro:<tenant>:%s:<id>", errInvalidHTTPRequest, field, entityType)
	}
	if parts[3] != entityType || parts[len(parts)-1] == "" {
		return fmt.Errorf("%w: %s must be of the form urn:cerebro:<tenant>:%s:<id>", errInvalidHTTPRequest, field, entityType)
	}
	for index, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (index < 3 && part == "") {
			return fmt.Errorf("%w: %s must be of the form urn:cerebro:<tenant>:%s:<id>", errInvalidHTTPRequest, field, entityType)
		}
	}
	return nil
}

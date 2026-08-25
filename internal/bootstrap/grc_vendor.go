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
	GraphRevision uint64                      `json:"graph_revision"`
	DataAuthority string                      `json:"data_authority"`
	Vendors       []ports.VendorRegisterRow   `json:"vendors"`
	Summary       ports.VendorRegisterSummary `json:"summary"`
	GeneratedAt   string                      `json:"generated_at"`
}

type grcVendorDetailResponse struct {
	Vendor        grcvendor.Vendor              `json:"vendor"`
	Relationships grcvendor.VendorRelationships `json:"relationships"`
	Packet        grcvendor.VendorPacket        `json:"packet"`
	Graph         any                           `json:"graph,omitempty"`
	Findings      []grcFindingItem              `json:"findings"`
	Evidence      []grcEvidenceItem             `json:"evidence"`
	GraphRevision uint64                        `json:"graph_revision"`
	DataAuthority string                        `json:"data_authority"`
	GeneratedAt   time.Time                     `json:"generated_at"`
}

type grcVendorDiscoveriesResponse struct {
	Summary        grcvendor.DiscoverySummary                     `json:"summary"`
	Discoveries    []grcvendor.VendorDiscovery                    `json:"discoveries"`
	Decisions      []*ports.GRCVendorDiscoveryDecisionRecord      `json:"decisions,omitempty"`
	DecisionEvents []*ports.GRCVendorDiscoveryDecisionEventRecord `json:"decision_events,omitempty"`
	GeneratedAt    time.Time                                      `json:"generated_at"`
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
	queueOnly, err := boolQueryParam(r, "queue")
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if a.deps.GraphReads.VendorRegister == nil {
		writeGRCError(w, grcvendor.ErrRuntimeUnavailable)
		return
	}
	runtimeIDs := append([]string{}, scope.RuntimeIDs...)
	if scope.RuntimeID != "" {
		runtimeIDs = []string{scope.RuntimeID}
	}
	page, err := a.deps.GraphReads.VendorRegister.ListVendorRegister(r.Context(), ports.VendorRegisterFilter{
		TenantID: scope.TenantID, SourceID: scope.SourceID, RuntimeIDs: runtimeIDs,
		Query: strings.TrimSpace(r.URL.Query().Get("q")), RiskLevel: strings.TrimSpace(r.URL.Query().Get("risk_level")), ReviewState: strings.TrimSpace(r.URL.Query().Get("review_state")), OwnerState: strings.TrimSpace(r.URL.Query().Get("owner_state")), LifecycleState: strings.TrimSpace(r.URL.Query().Get("lifecycle_state")), QueueOnly: queueOnly, Limit: int(scope.Limit),
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcVendorsResponse{
		GraphRevision: page.GraphRevision,
		DataAuthority: page.DataAuthority,
		Vendors:       page.Vendors,
		Summary:       page.Summary,
		GeneratedAt:   page.GeneratedAt,
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
	registerRow, registerPage, err := a.grcVendorRegisterDetail(r, scope, urn, vendorID)
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	detail, err := grcvendor.NewWithCapabilities(a.deps.GraphReads.Catalog, a.deps.GraphReads.Neighborhoods).GetVendor(r.Context(), grcvendor.VendorDetailRequest{
		URN:        registerRow.URN,
		TenantID:   scope.TenantID,
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	})
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	detail.Vendor = grcvendor.VendorFromRegisterRow(registerRow, time.Now().UTC())
	urn = detail.Vendor.URN
	questionnaireRollups, err := grcvendor.QuestionnaireVendorRollups(r.Context(), grcQuestionnaireRunStore(a.deps.StateStore), scope.TenantID, []string{urn}, time.Now().UTC())
	if err != nil {
		return grcVendorDetailResponse{}, err
	}
	detail.Vendor = grcvendor.ApplyQuestionnaireVendorRollup(detail.Vendor, questionnaireRollups[urn])
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
	detail.Vendor = grcvendor.RefreshVendorQueuePosture(detail.Vendor)
	detail.Packet = grcvendor.BuildVendorPacket(detail.Vendor, detail.Relationships)
	return grcVendorDetailResponse{
		Vendor:        detail.Vendor,
		Relationships: detail.Relationships,
		Packet:        detail.Packet,
		Graph:         detail.Graph,
		Findings:      findingItems,
		Evidence:      evidenceItems,
		GraphRevision: registerPage.GraphRevision,
		DataAuthority: registerPage.DataAuthority,
		GeneratedAt:   time.Now().UTC(),
	}, nil
}

func (a *App) grcVendorRegisterDetail(r *http.Request, scope grcScope, urn string, vendorID string) (ports.VendorRegisterRow, *ports.VendorRegisterPage, error) {
	if a.deps.GraphReads.VendorRegister == nil {
		return ports.VendorRegisterRow{}, nil, grcvendor.ErrRuntimeUnavailable
	}
	runtimeIDs := append([]string{}, scope.RuntimeIDs...)
	if scope.RuntimeID != "" {
		runtimeIDs = []string{scope.RuntimeID}
	}
	query := strings.TrimSpace(urn)
	if query == "" {
		query = strings.TrimSpace(vendorID)
	}
	page, err := a.deps.GraphReads.VendorRegister.ListVendorRegister(r.Context(), ports.VendorRegisterFilter{
		TenantID: scope.TenantID, SourceID: scope.SourceID, RuntimeIDs: runtimeIDs, Query: query, Limit: int(scope.Limit),
	})
	if err != nil {
		return ports.VendorRegisterRow{}, nil, err
	}
	if page == nil || page.TenantID != scope.TenantID || page.DataAuthority != "rust_graph" {
		return ports.VendorRegisterRow{}, nil, grcvendor.ErrRuntimeUnavailable
	}
	matched := make([]ports.VendorRegisterRow, 0, 1)
	for _, row := range page.Vendors {
		if urn != "" && row.URN == urn {
			matched = append(matched, row)
			continue
		}
		if urn == "" && (strings.EqualFold(row.VendorID, vendorID) || strings.EqualFold(row.Name, vendorID) || strings.HasSuffix(strings.ToLower(row.URN), ":"+strings.ToLower(vendorID))) {
			matched = append(matched, row)
		}
	}
	if len(matched) == 0 {
		return ports.VendorRegisterRow{}, nil, ports.ErrGraphEntityNotFound
	}
	if len(matched) != 1 {
		return ports.VendorRegisterRow{}, nil, grcvendor.ErrRuntimeUnavailable
	}
	return matched[0], page, nil
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
	discoveries, err := grcvendor.NewWithCapabilities(a.deps.GraphReads.Catalog, a.deps.GraphReads.Neighborhoods).ListDiscoveries(r.Context(), grcvendor.ListDiscoveriesRequest{
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
	decisions = filterGRCVendorDiscoveryDecisions(decisions, grcDiscoveryURNs(discoveries))
	decisionEvents, err := a.listGRCVendorDiscoveryDecisionEvents(r, scope, grcDiscoveryURNs(discoveries))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcVendorDiscoveriesResponse{
		Summary:        grcvendor.SummarizeDiscoveries(discoveries),
		Discoveries:    discoveries,
		Decisions:      decisions,
		DecisionEvents: decisionEvents,
		GeneratedAt:    time.Now().UTC(),
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

func grcQuestionnaireRunStore(store ports.StateStore) ports.QuestionnaireRunStore {
	runStore, ok := store.(ports.QuestionnaireRunStore)
	if !ok || isNilInterface(runStore) {
		return nil
	}
	return runStore
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

func (a *App) listGRCVendorDiscoveryDecisionEvents(r *http.Request, scope grcScope, discoveryURNs []string) ([]*ports.GRCVendorDiscoveryDecisionEventRecord, error) {
	store := grcVendorDiscoveryDecisionStore(a.deps.StateStore)
	if store == nil || len(discoveryURNs) == 0 {
		return nil, nil
	}
	return store.ListGRCVendorDiscoveryDecisionEvents(r.Context(), ports.GRCVendorDiscoveryDecisionEventFilter{
		TenantID:      scope.TenantID,
		DiscoveryURNs: discoveryURNs,
		SourceID:      scope.SourceID,
		Limit:         boundedUint32(len(discoveryURNs) * 10),
	})
}

func filterGRCVendorDiscoveryDecisions(records []*ports.GRCVendorDiscoveryDecisionRecord, discoveryURNs []string) []*ports.GRCVendorDiscoveryDecisionRecord {
	if len(records) == 0 || len(discoveryURNs) == 0 {
		return nil
	}
	visible := make(map[string]struct{}, len(discoveryURNs))
	for _, urn := range discoveryURNs {
		visible[strings.TrimSpace(urn)] = struct{}{}
	}
	filtered := records[:0]
	for _, record := range records {
		if record == nil {
			continue
		}
		if _, ok := visible[strings.TrimSpace(record.DiscoveryURN)]; ok {
			filtered = append(filtered, record)
		}
	}
	return filtered
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

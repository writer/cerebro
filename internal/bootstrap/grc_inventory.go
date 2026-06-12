package bootstrap

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
)

const (
	grcRuntimeStatusConfigKey           = "__cerebro_runtime_status"
	maxGRCInventoryScopeBodyBytes       = 32 << 10
	maxGRCInventoryAssetReportBodyBytes = 32 << 10
	grcInventoryScopeStateInScope       = ports.GRCInventoryScopeStateIn
	grcInventoryScopeStateOutScope      = ports.GRCInventoryScopeStateOut
)

type grcInventoryCategoriesResponse struct {
	Categories  []graphquery.InventoryCategory `json:"categories"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

type grcInventoryAssetsResponse struct {
	Assets      []graphquery.InventoryAsset `json:"assets"`
	Summary     grcInventorySummary         `json:"summary"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type grcInventoryAssetDetailResponse struct {
	Asset           graphquery.InventoryAsset              `json:"asset"`
	Graph           any                                    `json:"graph,omitempty"`
	Findings        []grcFindingItem                       `json:"findings"`
	Evidence        []grcEvidenceItem                      `json:"evidence"`
	Controls        []grcControlItem                       `json:"controls"`
	Tests           []grcInventoryTestItem                 `json:"tests"`
	Vulnerabilities []grcInventoryVulnerability            `json:"vulnerabilities"`
	AssetReports    []*ports.GRCInventoryAssetReportRecord `json:"asset_reports,omitempty"`
	Timeline        []grcInventoryTimelineEvent            `json:"timeline"`
	Actions         []grcInventoryAction                   `json:"actions"`
	GeneratedAt     time.Time                              `json:"generated_at"`
}

type grcInventorySummary struct {
	TotalAssets         int `json:"total_assets"`
	InScopeAssets       int `json:"in_scope_assets"`
	OutOfScopeAssets    int `json:"out_of_scope_assets"`
	HighRiskAssets      int `json:"high_risk_assets"`
	UnassignedAssets    int `json:"unassigned_assets"`
	OrgGroups           int `json:"org_groups"`
	PublicAssets        int `json:"public_assets"`
	ScopedCoveragePct   int `json:"scoped_coverage_pct"`
	AssignedCoveragePct int `json:"assigned_coverage_pct"`
}

type grcInventoryTimelineEvent struct {
	At          *time.Time `json:"at,omitempty"`
	Kind        string     `json:"kind"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Status      string     `json:"status,omitempty"`
}

type grcInventoryAction struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Href        string `json:"href,omitempty"`
}

type grcInventoryTestItem struct {
	Name         string     `json:"name"`
	Owner        string     `json:"owner"`
	Status       string     `json:"status"`
	DueAt        *time.Time `json:"due_at,omitempty"`
	ControlID    string     `json:"control_id,omitempty"`
	Framework    string     `json:"framework,omitempty"`
	FindingID    string     `json:"finding_id,omitempty"`
	FindingTitle string     `json:"finding_title,omitempty"`
}

type grcInventoryVulnerability struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	SourceID  string `json:"source_id,omitempty"`
	FindingID string `json:"finding_id,omitempty"`
}

type grcResourceScopeResponse struct {
	SourceID    string                      `json:"source_id"`
	Runtimes    []grcResourceScopeRuntime   `json:"runtimes"`
	Resources   []graphquery.InventoryAsset `json:"resources"`
	Summary     grcInventorySummary         `json:"summary"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type grcInventoryScopeUpdateRequest struct {
	TenantID   string            `json:"tenant_id,omitempty"`
	AssetURN   string            `json:"asset_urn"`
	SourceID   string            `json:"source_id,omitempty"`
	ScopeState string            `json:"scope_state"`
	Reason     string            `json:"reason,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type grcInventoryScopeUpdateResponse struct {
	Scope       *ports.GRCInventoryScopeRecord `json:"scope"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

type grcInventoryAssetReportCreateRequest struct {
	TenantID     string            `json:"tenant_id,omitempty"`
	AssetURN     string            `json:"asset_urn"`
	SourceID     string            `json:"source_id,omitempty"`
	Reason       string            `json:"reason"`
	Reporter     string            `json:"reporter,omitempty"`
	TriageStatus string            `json:"triage_status,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

type grcInventoryAssetReportTriageRequest struct {
	TenantID     string `json:"tenant_id,omitempty"`
	TriageStatus string `json:"triage_status"`
	TriageReason string `json:"triage_reason,omitempty"`
	TriagedBy    string `json:"triaged_by,omitempty"`
}

type grcInventoryAssetReportResponse struct {
	Report      *ports.GRCInventoryAssetReportRecord `json:"report"`
	GeneratedAt time.Time                            `json:"generated_at"`
}

type grcInventoryAssetReportsResponse struct {
	Reports     []*ports.GRCInventoryAssetReportRecord `json:"reports"`
	GeneratedAt time.Time                              `json:"generated_at"`
}

type grcResourceScopeRuntime struct {
	RuntimeID string `json:"runtime_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Family    string `json:"family,omitempty"`
	Status    string `json:"status"`
}

func (a *App) handleGRCInventoryCategories(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	categories, err := a.graphQueryService().ListInventoryCategories(r.Context(), graphquery.InventoryCategoryRequest{
		TenantID: scope.TenantID,
		SourceID: scope.SourceID,
		Limit:    scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryCategoriesResponse{Categories: categories, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleGRCInventoryAssets(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	assets, err := a.graphQueryService().ListInventoryAssets(r.Context(), graphquery.InventoryAssetRequest{
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		CategoryID: strings.TrimSpace(r.URL.Query().Get("category_id")),
		EntityType: strings.TrimSpace(r.URL.Query().Get("entity_type")),
		Query:      strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:      scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	assets, err = a.enrichGRCInventoryAssets(r, scope, assets)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	summary := summarizeGRCInventoryAssets(assets)
	assets = filterGRCInventoryAssetsByScope(assets, strings.TrimSpace(r.URL.Query().Get("scope_state")))
	writeJSON(w, http.StatusOK, grcInventoryAssetsResponse{Assets: assets, Summary: summary, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleGRCInventoryAssetDetail(w http.ResponseWriter, r *http.Request) {
	urn := strings.TrimSpace(r.URL.Query().Get("urn"))
	if err := authorizeCerebroURNTenant(r.Context(), urn); err != nil {
		writeGRCError(w, err)
		return
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	detail, err := a.graphQueryService().GetInventoryAsset(r.Context(), graphquery.InventoryAssetDetailRequest{
		URN:   urn,
		Limit: scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{ResourceURN: urn, Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	sourceIDs := grcRuntimeSourceIDs(runtimes)
	evidenceCounts, counted, err := a.grcEvidenceCountsByFindingID(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings)})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingIDs: grcFindingIDs(findings), GraphRootURN: urn, Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if !counted {
		evidenceCounts = grcEvidenceCounts(evidence)
	}
	findingItems := grcFindingItems(findings, sourceIDs, evidenceCounts)
	evidenceItems := grcEvidenceItems(evidence, grcFindingTitleMap(findings))
	controls := grcControlItems(findingItems, evidenceItems)
	tests := grcInventoryTests(findingItems, controls)
	vulnerabilities := grcInventoryVulnerabilities(findingItems)
	asset, err := a.enrichGRCInventoryAsset(r, scope, detail.Asset)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	asset = applyFindingRiskToInventoryAsset(asset, findingItems, tests, vulnerabilities)
	reports, err := a.listGRCInventoryAssetReportsForAsset(r, scope, asset.URN, scope.Limit)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryAssetDetailResponse{
		Asset:           asset,
		Graph:           detail.Graph,
		Findings:        findingItems,
		Evidence:        evidenceItems,
		Controls:        controls,
		Tests:           tests,
		Vulnerabilities: vulnerabilities,
		AssetReports:    reports,
		Timeline:        grcInventoryTimeline(asset, findingItems, evidenceItems, tests, reports),
		Actions:         grcInventoryActions(asset, findingItems, controls, tests, vulnerabilities),
		GeneratedAt:     time.Now().UTC(),
	})
}

func (a *App) handleGRCResourceScope(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	sourceID := strings.TrimSpace(r.URL.Query().Get("source_id"))
	if sourceID == "" {
		sourceID = "github"
	}
	runtimeScope := scope
	runtimeScope.SourceID = sourceID
	runtimes, err := a.grcListRuntimes(r, runtimeScope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	resources, err := a.graphQueryService().ListInventoryAssets(r.Context(), graphquery.InventoryAssetRequest{
		TenantID:   scope.TenantID,
		SourceID:   sourceID,
		CategoryID: strings.TrimSpace(r.URL.Query().Get("category_id")),
		EntityType: strings.TrimSpace(r.URL.Query().Get("entity_type")),
		Query:      strings.TrimSpace(r.URL.Query().Get("q")),
		Limit:      scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	resources, err = a.enrichGRCInventoryAssets(r, scope, resources)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	items := make([]grcResourceScopeRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		items = append(items, grcResourceScopeRuntime{
			RuntimeID: runtime.GetId(),
			TenantID:  runtime.GetTenantId(),
			Owner:     runtimeConfigValue(runtime.GetConfig(), "owner"),
			Family:    runtimeConfigValue(runtime.GetConfig(), "family"),
			Status:    runtimeConfigValue(runtime.GetConfig(), grcRuntimeStatusConfigKey),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RuntimeID < items[j].RuntimeID })
	writeJSON(w, http.StatusOK, grcResourceScopeResponse{
		SourceID:    sourceID,
		Runtimes:    items,
		Resources:   resources,
		Summary:     summarizeGRCInventoryAssets(resources),
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleUpdateGRCResourceScope(w http.ResponseWriter, r *http.Request) {
	var request grcInventoryScopeUpdateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCInventoryScopeBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode inventory scope request: %w", errInvalidHTTPRequest, err))
		return
	}
	request.AssetURN = strings.TrimSpace(request.AssetURN)
	if request.AssetURN == "" {
		writeGRCError(w, fmt.Errorf("%w: asset_urn is required", errInvalidHTTPRequest))
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), request.AssetURN); err != nil {
		writeGRCError(w, err)
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = tenantIDFromCerebroURN(request.AssetURN)
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	state := strings.TrimSpace(request.ScopeState)
	if state != grcInventoryScopeStateInScope && state != grcInventoryScopeStateOutScope {
		writeGRCError(w, fmt.Errorf("%w: scope_state must be in_scope or out_of_scope", errInvalidHTTPRequest))
		return
	}
	store := grcInventoryScopeStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	record, err := store.UpsertGRCInventoryScope(r.Context(), ports.GRCInventoryScopeRecord{
		TenantID:   tenantID,
		AssetURN:   request.AssetURN,
		SourceID:   strings.TrimSpace(request.SourceID),
		ScopeState: state,
		Reason:     strings.TrimSpace(request.Reason),
		UpdatedBy:  grcInventoryUpdatedBy(r),
		Attributes: request.Attributes,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryScopeUpdateResponse{Scope: record, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleCreateGRCInventoryAssetReport(w http.ResponseWriter, r *http.Request) {
	var request grcInventoryAssetReportCreateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCInventoryAssetReportBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode inventory asset report request: %w", errInvalidHTTPRequest, err))
		return
	}
	request.AssetURN = strings.TrimSpace(request.AssetURN)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.AssetURN == "" {
		writeGRCError(w, fmt.Errorf("%w: asset_urn is required", errInvalidHTTPRequest))
		return
	}
	if request.Reason == "" {
		writeGRCError(w, fmt.Errorf("%w: reason is required", errInvalidHTTPRequest))
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), request.AssetURN); err != nil {
		writeGRCError(w, err)
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		tenantID = tenantIDFromCerebroURN(request.AssetURN)
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	status := strings.TrimSpace(request.TriageStatus)
	if status == "" {
		status = ports.GRCInventoryAssetReportStatusSubmitted
	}
	if !ports.IsGRCInventoryAssetReportStatus(status) {
		writeGRCError(w, fmt.Errorf("%w: triage_status is invalid", errInvalidHTTPRequest))
		return
	}
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	reporter := strings.TrimSpace(request.Reporter)
	if reporter == "" {
		reporter = grcInventoryUpdatedBy(r)
	}
	record, err := store.CreateGRCInventoryAssetReport(r.Context(), ports.GRCInventoryAssetReportRecord{
		ID:           newGRCInventoryAssetReportID(),
		TenantID:     tenantID,
		AssetURN:     request.AssetURN,
		SourceID:     strings.TrimSpace(request.SourceID),
		Reason:       request.Reason,
		Reporter:     reporter,
		TriageStatus: status,
		Attributes:   request.Attributes,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, grcInventoryAssetReportResponse{Report: record, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleListGRCInventoryAssetReports(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	assetURN := strings.TrimSpace(r.URL.Query().Get("asset_urn"))
	if assetURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), assetURN); err != nil {
			writeGRCError(w, err)
			return
		}
		if scope.TenantID == "" {
			scope.TenantID = tenantIDFromCerebroURN(assetURN)
		}
	}
	if err := authorizeTenantID(r.Context(), scope.TenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("triage_status"))
	if status != "" && !ports.IsGRCInventoryAssetReportStatus(status) {
		writeGRCError(w, fmt.Errorf("%w: triage_status is invalid", errInvalidHTTPRequest))
		return
	}
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	var urns []string
	if assetURN != "" {
		urns = []string{assetURN}
	}
	records, err := store.ListGRCInventoryAssetReports(r.Context(), ports.GRCInventoryAssetReportFilter{
		TenantID:     scope.TenantID,
		AssetURNs:    urns,
		SourceID:     scope.SourceID,
		TriageStatus: status,
		Limit:        scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryAssetReportsResponse{Reports: records, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleGetGRCInventoryAssetReport(w http.ResponseWriter, r *http.Request) {
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	record, err := store.GetGRCInventoryAssetReport(r.Context(), strings.TrimSpace(r.PathValue("reportID")), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), record.TenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), record.AssetURN); err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryAssetReportResponse{Report: record, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleUpdateGRCInventoryAssetReportTriage(w http.ResponseWriter, r *http.Request) {
	var request grcInventoryAssetReportTriageRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCInventoryAssetReportBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode inventory asset report triage request: %w", errInvalidHTTPRequest, err))
		return
	}
	status := strings.TrimSpace(request.TriageStatus)
	if !ports.IsGRCInventoryAssetReportStatus(status) {
		writeGRCError(w, fmt.Errorf("%w: triage_status is invalid", errInvalidHTTPRequest))
		return
	}
	reportID := strings.TrimSpace(r.PathValue("reportID"))
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	record, err := store.GetGRCInventoryAssetReport(r.Context(), reportID, strings.TrimSpace(request.TenantID))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), record.TenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), record.AssetURN); err != nil {
		writeGRCError(w, err)
		return
	}
	triagedBy := strings.TrimSpace(request.TriagedBy)
	if triagedBy == "" {
		triagedBy = grcInventoryUpdatedBy(r)
	}
	record, err = store.UpdateGRCInventoryAssetReportTriage(r.Context(), ports.GRCInventoryAssetReportTriageUpdate{
		ID:           reportID,
		TenantID:     record.TenantID,
		TriageStatus: status,
		TriageReason: strings.TrimSpace(request.TriageReason),
		TriagedBy:    triagedBy,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcInventoryAssetReportResponse{Report: record, GeneratedAt: time.Now().UTC()})
}

func grcInventoryTests(findings []grcFindingItem, controls []grcControlItem) []grcInventoryTestItem {
	tests := []grcInventoryTestItem{}
	seen := map[string]struct{}{}
	for _, finding := range findings {
		refs := finding.Controls
		if len(refs) == 0 {
			refs = []grcControlRef{{FrameworkName: "Unmapped", ControlID: fallbackString(finding.PolicyName, finding.RuleID, finding.ID)}}
		}
		for _, ref := range refs {
			name := fallbackString(finding.PolicyName, finding.Title, ref.ControlID)
			key := name + "\x00" + ref.FrameworkName + "\x00" + ref.ControlID + "\x00" + finding.ID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tests = append(tests, grcInventoryTestItem{
				Name:         name,
				Owner:        finding.Owner,
				Status:       inventoryTestStatus(finding),
				DueAt:        finding.DueAt,
				ControlID:    ref.ControlID,
				Framework:    ref.FrameworkName,
				FindingID:    finding.ID,
				FindingTitle: finding.Title,
			})
		}
	}
	if len(tests) == 0 {
		for _, control := range controls {
			key := control.FrameworkName + "\x00" + control.ControlID
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			tests = append(tests, grcInventoryTestItem{
				Name:      control.ControlID,
				Owner:     "Unassigned",
				Status:    control.Status,
				ControlID: control.ControlID,
				Framework: control.FrameworkName,
			})
		}
	}
	sort.Slice(tests, func(i, j int) bool {
		if tests[i].Status != tests[j].Status {
			return tests[i].Status < tests[j].Status
		}
		return tests[i].Name < tests[j].Name
	})
	return tests
}

func inventoryTestStatus(finding grcFindingItem) string {
	if finding.Status == "OPEN" || strings.EqualFold(finding.Status, "open") {
		if finding.SLAStatus == "overdue" {
			return "overdue"
		}
		return "failing"
	}
	return "ok"
}

func grcInventoryVulnerabilities(findings []grcFindingItem) []grcInventoryVulnerability {
	vulnerabilities := []grcInventoryVulnerability{}
	for _, finding := range findings {
		text := strings.ToLower(strings.Join([]string{finding.Title, finding.Summary, finding.RuleID, finding.PolicyID}, " "))
		if !strings.Contains(text, "vulnerab") && !strings.Contains(text, "cve-") && !strings.Contains(text, "package") {
			continue
		}
		vulnerabilities = append(vulnerabilities, grcInventoryVulnerability{
			ID:        fallbackString(finding.PolicyID, finding.RuleID, finding.ID),
			Title:     finding.Title,
			Severity:  finding.Severity,
			Status:    finding.Status,
			SourceID:  finding.SourceID,
			FindingID: finding.ID,
		})
	}
	return vulnerabilities
}

func (a *App) enrichGRCInventoryAssets(r *http.Request, scope grcScope, assets []graphquery.InventoryAsset) ([]graphquery.InventoryAsset, error) {
	if len(assets) == 0 {
		return assets, nil
	}
	store := grcInventoryScopeStore(a.deps.StateStore)
	if store != nil {
		urns := make([]string, 0, len(assets))
		for _, asset := range assets {
			if strings.TrimSpace(asset.URN) != "" {
				urns = append(urns, asset.URN)
			}
		}
		records, err := store.ListGRCInventoryScopes(r.Context(), ports.GRCInventoryScopeFilter{
			TenantID:  scope.TenantID,
			AssetURNs: urns,
			Limit:     boundedUint32(len(urns)),
		})
		if err != nil {
			return nil, err
		}
		byURN := map[string]*ports.GRCInventoryScopeRecord{}
		for _, record := range records {
			if record != nil {
				byURN[record.AssetURN] = record
			}
		}
		for index := range assets {
			applyGRCInventoryScope(&assets[index], byURN[assets[index].URN])
		}
	}
	return a.enrichGRCInventoryAssetsWithReports(r, scope, assets)
}

func (a *App) enrichGRCInventoryAsset(r *http.Request, scope grcScope, asset graphquery.InventoryAsset) (graphquery.InventoryAsset, error) {
	assets, err := a.enrichGRCInventoryAssets(r, scope, []graphquery.InventoryAsset{asset})
	if err != nil || len(assets) == 0 {
		return asset, err
	}
	return assets[0], nil
}

func (a *App) enrichGRCInventoryAssetsWithReports(r *http.Request, scope grcScope, assets []graphquery.InventoryAsset) ([]graphquery.InventoryAsset, error) {
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil || len(assets) == 0 {
		return assets, nil
	}
	urns := make([]string, 0, len(assets))
	for _, asset := range assets {
		if strings.TrimSpace(asset.URN) != "" {
			urns = append(urns, asset.URN)
		}
	}
	summaries, err := store.SummarizeGRCInventoryAssetReports(r.Context(), ports.GRCInventoryAssetReportFilter{
		TenantID:  scope.TenantID,
		AssetURNs: urns,
	})
	if err != nil {
		return nil, err
	}
	byURN := map[string]*ports.GRCInventoryAssetReportSummary{}
	for _, summary := range summaries {
		if summary == nil {
			continue
		}
		byURN[summary.AssetURN] = summary
	}
	for index := range assets {
		applyGRCInventoryAssetReportSummary(&assets[index], byURN[assets[index].URN])
	}
	return assets, nil
}

func (a *App) listGRCInventoryAssetReportsForAsset(r *http.Request, scope grcScope, assetURN string, limit uint32) ([]*ports.GRCInventoryAssetReportRecord, error) {
	store := grcInventoryAssetReportStore(a.deps.StateStore)
	if store == nil || strings.TrimSpace(assetURN) == "" {
		return []*ports.GRCInventoryAssetReportRecord{}, nil
	}
	return store.ListGRCInventoryAssetReports(r.Context(), ports.GRCInventoryAssetReportFilter{
		TenantID:  fallbackString(scope.TenantID, tenantIDFromCerebroURN(assetURN)),
		AssetURNs: []string{assetURN},
		SourceID:  scope.SourceID,
		Limit:     limit,
	})
}

func applyGRCInventoryScope(asset *graphquery.InventoryAsset, record *ports.GRCInventoryScopeRecord) {
	if asset == nil {
		return
	}
	if strings.TrimSpace(asset.ScopeState) == "" {
		asset.ScopeState = grcInventoryScopeStateInScope
	}
	if record == nil {
		return
	}
	asset.ScopeState = record.ScopeState
	asset.ScopeReason = record.Reason
	if !record.UpdatedAt.IsZero() {
		asset.ScopeUpdatedAt = record.UpdatedAt.UTC().Format(time.RFC3339)
	}
}

func applyGRCInventoryAssetReportSummary(asset *graphquery.InventoryAsset, summary *ports.GRCInventoryAssetReportSummary) {
	if asset == nil || summary == nil {
		return
	}
	asset.AssetReportCount = summary.ReportCount
	asset.LatestAssetReportStatus = summary.TriageStatus
	asset.LatestAssetReportReason = summary.Reason
	if !summary.UpdatedAt.IsZero() {
		asset.LatestAssetReportUpdatedAt = summary.UpdatedAt.UTC().Format(time.RFC3339)
	}
}

func filterGRCInventoryAssetsByScope(assets []graphquery.InventoryAsset, state string) []graphquery.InventoryAsset {
	state = strings.TrimSpace(state)
	if state == "" || state == "all" {
		return assets
	}
	filtered := make([]graphquery.InventoryAsset, 0, len(assets))
	for _, asset := range assets {
		assetState := strings.TrimSpace(asset.ScopeState)
		if assetState == "" {
			assetState = grcInventoryScopeStateInScope
		}
		if assetState == state {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}

func summarizeGRCInventoryAssets(assets []graphquery.InventoryAsset) grcInventorySummary {
	summary := grcInventorySummary{TotalAssets: len(assets)}
	orgs := map[string]struct{}{}
	for _, asset := range assets {
		state := strings.TrimSpace(asset.ScopeState)
		if state == "" || state == grcInventoryScopeStateInScope {
			summary.InScopeAssets++
		}
		if state == grcInventoryScopeStateOutScope {
			summary.OutOfScopeAssets++
		}
		if asset.RiskScore >= 70 {
			summary.HighRiskAssets++
		}
		if inventoryAssetOwner(asset) == "Unassigned" {
			summary.UnassignedAssets++
		}
		if inventoryAssetPublic(asset) {
			summary.PublicAssets++
		}
		if org := inventoryAssetOrg(asset); org != "" {
			orgs[org] = struct{}{}
		}
	}
	summary.OrgGroups = len(orgs)
	if summary.TotalAssets > 0 {
		summary.ScopedCoveragePct = int(float64(summary.InScopeAssets) / float64(summary.TotalAssets) * 100)
		summary.AssignedCoveragePct = int(float64(summary.TotalAssets-summary.UnassignedAssets) / float64(summary.TotalAssets) * 100)
	}
	return summary
}

func applyFindingRiskToInventoryAsset(asset graphquery.InventoryAsset, findings []grcFindingItem, tests []grcInventoryTestItem, vulnerabilities []grcInventoryVulnerability) graphquery.InventoryAsset {
	score := asset.RiskScore
	reasons := append([]string{}, asset.RiskReasons...)
	for _, finding := range findings {
		if int(finding.RiskScore) > score {
			score = int(finding.RiskScore)
		}
		if strings.EqualFold(finding.Status, "open") {
			reasons = append(reasons, "open finding")
		}
	}
	if failingGRCInventoryTests(tests) > 0 {
		score += 10
		reasons = append(reasons, "failing compliance tests")
	}
	if criticalHighGRCInventoryVulnerabilities(vulnerabilities) > 0 {
		score += 15
		reasons = append(reasons, "critical or high vulnerabilities")
	}
	if asset.ScopeState == grcInventoryScopeStateOutScope {
		reasons = append(reasons, "out of GRC purview")
	}
	asset.RiskScore = clampGRCInventoryRisk(score)
	asset.RiskLevel = grcInventoryRiskLevel(asset.RiskScore)
	asset.RiskReasons = uniqueGRCInventoryStrings(reasons)
	return asset
}

func grcInventoryTimeline(asset graphquery.InventoryAsset, findings []grcFindingItem, evidence []grcEvidenceItem, tests []grcInventoryTestItem, reports []*ports.GRCInventoryAssetReportRecord) []grcInventoryTimelineEvent {
	events := []grcInventoryTimelineEvent{}
	for _, key := range []string{"created_at", "first_seen_at"} {
		if at := parseGRCInventoryTime(asset.Attributes[key]); at != nil {
			events = append(events, grcInventoryTimelineEvent{At: at, Kind: "asset", Title: "Asset first observed", Status: "observed"})
			break
		}
	}
	for _, key := range []string{"updated_at", "last_seen_at", "last_synced_at"} {
		if at := parseGRCInventoryTime(asset.Attributes[key]); at != nil {
			events = append(events, grcInventoryTimelineEvent{At: at, Kind: "asset", Title: "Asset refreshed", Status: "observed"})
			break
		}
	}
	if asset.ScopeUpdatedAt != "" {
		events = append(events, grcInventoryTimelineEvent{At: parseGRCInventoryTime(asset.ScopeUpdatedAt), Kind: "scope", Title: "GRC purview updated", Description: asset.ScopeReason, Status: asset.ScopeState})
	}
	for _, report := range reports {
		if report == nil {
			continue
		}
		createdAt := report.CreatedAt.UTC()
		events = append(events, grcInventoryTimelineEvent{At: &createdAt, Kind: "asset_report", Title: "Asset reported for curation", Description: report.Reason, Status: report.TriageStatus})
		if report.TriagedAt != nil {
			events = append(events, grcInventoryTimelineEvent{At: report.TriagedAt, Kind: "asset_report", Title: "Asset report triaged", Description: report.TriageReason, Status: report.TriageStatus})
		}
	}
	for _, finding := range findings {
		events = append(events, grcInventoryTimelineEvent{At: finding.LastObservedAt, Kind: "finding", Title: finding.Title, Description: finding.ID, Status: finding.Status})
	}
	for _, item := range evidence {
		events = append(events, grcInventoryTimelineEvent{At: timePtr(item.CreatedAt), Kind: "evidence", Title: "Evidence attached", Description: item.ID, Status: "collected"})
	}
	for _, test := range tests {
		if test.DueAt != nil {
			events = append(events, grcInventoryTimelineEvent{At: test.DueAt, Kind: "test", Title: test.Name, Description: test.ControlID, Status: test.Status})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		left, right := events[i].At, events[j].At
		if left == nil {
			return false
		}
		if right == nil {
			return true
		}
		return left.After(*right)
	})
	if len(events) > 25 {
		return events[:25]
	}
	return events
}

func grcInventoryActions(asset graphquery.InventoryAsset, findings []grcFindingItem, controls []grcControlItem, tests []grcInventoryTestItem, vulnerabilities []grcInventoryVulnerability) []grcInventoryAction {
	actions := []grcInventoryAction{}
	if asset.ScopeState == grcInventoryScopeStateOutScope {
		actions = append(actions, grcInventoryAction{Title: "Confirm GRC purview", Description: "This asset is scoped out. Scope it back in if it should participate in controls, tests, and evidence review.", Priority: "high"})
	}
	if inventoryAssetOwner(asset) == "Unassigned" {
		actions = append(actions, grcInventoryAction{Title: "Assign an owner", Description: "Add ownership metadata so findings and control evidence route to an accountable team.", Priority: "high"})
	}
	if criticalHighGRCInventoryVulnerabilities(vulnerabilities) > 0 {
		actions = append(actions, grcInventoryAction{Title: "Remediate critical or high vulnerabilities", Description: "Review linked findings and confirm active remediation plans for severe vulnerability exposure.", Priority: "high"})
	}
	if failingGRCInventoryTests(tests) > 0 {
		actions = append(actions, grcInventoryAction{Title: "Fix failing compliance tests", Description: "Prioritize failing or overdue tests mapped to this asset before audit evidence collection.", Priority: "medium"})
	}
	if len(controls) == 0 && len(findings) > 0 {
		actions = append(actions, grcInventoryAction{Title: "Map framework scope", Description: "Attach affected findings to framework controls to make audit impact explicit.", Priority: "medium"})
	}
	if len(actions) == 0 {
		actions = append(actions, grcInventoryAction{Title: "Keep monitoring", Description: "No immediate scope, ownership, vulnerability, or test gaps were detected for this asset.", Priority: "low"})
	}
	return actions
}

func failingGRCInventoryTests(tests []grcInventoryTestItem) int {
	count := 0
	for _, test := range tests {
		switch strings.ToLower(test.Status) {
		case "failing", "overdue", "open":
			count++
		}
	}
	return count
}

func criticalHighGRCInventoryVulnerabilities(items []grcInventoryVulnerability) int {
	count := 0
	for _, item := range items {
		switch strings.ToUpper(item.Severity) {
		case "CRITICAL", "HIGH":
			count++
		}
	}
	return count
}

func inventoryAssetOwner(asset graphquery.InventoryAsset) string {
	return fallbackString(asset.Attributes["owner"], asset.Attributes["owner_email"], asset.Attributes["assignee"], asset.Attributes["account_manager_email"], asset.Attributes["owner_login"], "Unassigned")
}

func inventoryAssetOrg(asset graphquery.InventoryAsset) string {
	return fallbackString(asset.Attributes["org"], asset.Attributes["owner_login"], asset.Attributes["account_id"], asset.Attributes["project_id"], asset.SourceID)
}

func inventoryAssetPublic(asset graphquery.InventoryAsset) bool {
	for _, key := range []string{"public", "publicly_accessible", "internet_exposed", "external"} {
		switch strings.ToLower(strings.TrimSpace(asset.Attributes[key])) {
		case "1", "t", "true", "yes", "y":
			return true
		}
	}
	return false
}

func parseGRCInventoryTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, time.DateOnly} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed
		}
	}
	return nil
}

func clampGRCInventoryRisk(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func grcInventoryRiskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func uniqueGRCInventoryStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func grcInventoryUpdatedBy(r *http.Request) string {
	if r == nil {
		return ""
	}
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		return strings.TrimSpace(auth.principal.Name)
	}
	return ""
}

func newGRCInventoryAssetReportID() string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("asset-report-%d", time.Now().UnixNano())
	}
	return "asset-report-" + hex.EncodeToString(random[:])
}

func runtimeConfigValue(config map[string]string, key string) string {
	if config == nil {
		return ""
	}
	return strings.TrimSpace(config[key])
}

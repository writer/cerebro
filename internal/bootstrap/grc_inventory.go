package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcinventory"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"google.golang.org/protobuf/proto"
)

const (
	grcRuntimeStatusConfigKey           = "__cerebro_runtime_status"
	maxGRCInventoryScopeBodyBytes       = 32 << 10
	maxGRCInventoryAssetReportBodyBytes = 32 << 10
)

func validateGRCInventoryAssetURN(assetURN string) error {
	parts := strings.Split(assetURN, ":")
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return fmt.Errorf("%w: asset_urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", errInvalidHTTPRequest)
	}
	if parts[len(parts)-1] == "" {
		return fmt.Errorf("%w: asset_urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", errInvalidHTTPRequest)
	}
	for index, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (index < 3 && part == "") {
			return fmt.Errorf("%w: asset_urn must be of the form urn:cerebro:<tenant>:<entity_type>:<id>", errInvalidHTTPRequest)
		}
	}
	return nil
}

type grcInventoryCategoriesResponse struct {
	Categories  []graphquery.InventoryCategory `json:"categories"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

type grcInventoryAssetsResponse struct {
	Assets      []graphquery.InventoryAsset `json:"assets"`
	Summary     grcinventory.Summary        `json:"summary"`
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
	Summary     grcinventory.Summary        `json:"summary"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type grcInventoryScopeUpdateRequest struct {
	TenantID   string            `json:"tenant_id,omitempty"`
	AssetURN   string            `json:"asset_urn"`
	SourceID   string            `json:"source_id,omitempty"`
	RuntimeID  string            `json:"runtime_id,omitempty"`
	ScopeState string            `json:"scope_state"`
	Reason     string            `json:"reason,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type grcInventoryAccountabilityUpdateRequest struct {
	TenantID  string `json:"tenant_id,omitempty"`
	AssetURN  string `json:"asset_urn"`
	SourceID  string `json:"source_id,omitempty"`
	RuntimeID string `json:"runtime_id,omitempty"`
	State     string `json:"state"`
	Owner     string `json:"owner,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type grcInventoryScopeUpdateResponse struct {
	Scope       *ports.GRCInventoryScopeRecord       `json:"scope"`
	Propagation []grcInventoryScopePropagationResult `json:"propagation,omitempty"`
	GeneratedAt time.Time                            `json:"generated_at"`
}

type grcInventoryAccountabilityUpdateResponse struct {
	Scope       *ports.GRCInventoryScopeRecord `json:"scope"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

type grcInventoryScopePropagationResult struct {
	RuntimeID        string `json:"runtime_id,omitempty"`
	SourceID         string `json:"source_id,omitempty"`
	Status           string `json:"status"`
	ExclusionApplied bool   `json:"exclusion_applied"`
	Reason           string `json:"reason,omitempty"`
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
	assets = grcinventory.FilterByScope(assets, strings.TrimSpace(r.URL.Query().Get("scope_state")))
	assets = grcinventory.FilterByReviewDisposition(assets, strings.TrimSpace(r.URL.Query().Get("review_state")))
	assets = grcinventory.FilterByAccountability(assets, strings.TrimSpace(r.URL.Query().Get("accountability_state")))
	summary := grcinventory.Summarize(assets)
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
	grcinventory.ApplyReviewPosture(&asset)
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
		Summary:     grcinventory.Summarize(resources),
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
	if err := validateGRCInventoryAssetURN(request.AssetURN); err != nil {
		writeGRCError(w, err)
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
	if state != grcinventory.ScopeStateInScope && state != grcinventory.ScopeStateOutScope {
		writeGRCError(w, fmt.Errorf("%w: scope_state must be in_scope or out_of_scope", errInvalidHTTPRequest))
		return
	}
	request.ScopeState = state
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	request.Reason = strings.TrimSpace(request.Reason)
	store := grcInventoryScopeStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	record, err := store.UpsertGRCInventoryScope(r.Context(), ports.GRCInventoryScopeRecord{
		TenantID:   tenantID,
		AssetURN:   request.AssetURN,
		SourceID:   request.SourceID,
		ScopeState: state,
		Reason:     request.Reason,
		UpdatedBy:  grcInventoryUpdatedBy(r),
		Attributes: request.Attributes,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	propagation, err := a.applyGRCInventoryScopeToSourceRuntimes(r.Context(), tenantID, request)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeInventory)
	writeJSON(w, http.StatusOK, grcInventoryScopeUpdateResponse{Scope: record, Propagation: propagation, GeneratedAt: time.Now().UTC()})
}

func (a *App) handleUpdateGRCInventoryAccountability(w http.ResponseWriter, r *http.Request) {
	var request grcInventoryAccountabilityUpdateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCInventoryScopeBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode inventory accountability request: %w", errInvalidHTTPRequest, err))
		return
	}
	request.AssetURN = strings.TrimSpace(request.AssetURN)
	if request.AssetURN == "" {
		writeGRCError(w, fmt.Errorf("%w: asset_urn is required", errInvalidHTTPRequest))
		return
	}
	if err := validateGRCInventoryAssetURN(request.AssetURN); err != nil {
		writeGRCError(w, err)
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
	store := grcInventoryScopeStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	record, err := upsertGRCInventoryAccountability(r.Context(), store, tenantID, grcInventoryUpdatedBy(r), request)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeInventory)
	writeJSON(w, http.StatusOK, grcInventoryAccountabilityUpdateResponse{Scope: record, GeneratedAt: time.Now().UTC()})
}

func upsertGRCInventoryAccountability(ctx context.Context, store ports.GRCInventoryScopeStore, tenantID string, updatedBy string, request grcInventoryAccountabilityUpdateRequest) (*ports.GRCInventoryScopeRecord, error) {
	if store == nil {
		return nil, graphquery.ErrRuntimeUnavailable
	}
	request.AssetURN = strings.TrimSpace(request.AssetURN)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.State = strings.TrimSpace(request.State)
	request.Owner = strings.TrimSpace(request.Owner)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.AssetURN == "" {
		return nil, fmt.Errorf("%w: asset_urn is required", errInvalidHTTPRequest)
	}
	if err := validateGRCInventoryAssetURN(request.AssetURN); err != nil {
		return nil, err
	}
	existing, err := loadGRCInventoryScopeRecord(ctx, store, tenantID, request.AssetURN)
	if err != nil {
		return nil, err
	}
	scopeState := grcinventory.ScopeStateInScope
	scopeReason := ""
	sourceID := request.SourceID
	attributes := map[string]string{}
	if existing != nil {
		if strings.TrimSpace(existing.ScopeState) != "" {
			scopeState = existing.ScopeState
		}
		scopeReason = existing.Reason
		if sourceID == "" {
			sourceID = existing.SourceID
		}
		for key, value := range existing.Attributes {
			if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
				attributes[key] = value
			}
		}
	}
	switch request.State {
	case grcinventory.AccountabilityKnown:
		if request.Owner == "" {
			return nil, fmt.Errorf("%w: owner is required when state is known", errInvalidHTTPRequest)
		}
		attributes[grcinventory.AttributeAccountabilityState] = grcinventory.AccountabilityKnown
		attributes[grcinventory.AttributeAccountabilityPrincipal] = request.Owner
		attributes["owner"] = request.Owner
		attributes[grcinventory.AttributeOwnerSource] = grcinventory.AttributeOwnerSourceCerebro
		attributes["accountability_required"] = "true"
		delete(attributes, grcinventory.AttributeOwnerNotRequired)
	case grcinventory.AccountabilityNone:
		attributes[grcinventory.AttributeAccountabilityState] = grcinventory.AccountabilityNone
		attributes[grcinventory.AttributeOwnerNotRequired] = "true"
		delete(attributes, grcinventory.AttributeAccountabilityPrincipal)
		delete(attributes, "owner")
		delete(attributes, grcinventory.AttributeOwnerSource)
		delete(attributes, "accountability_required")
	case "clear":
		delete(attributes, grcinventory.AttributeAccountabilityState)
		delete(attributes, grcinventory.AttributeAccountabilityPrincipal)
		delete(attributes, grcinventory.AttributeAccountabilityReason)
		delete(attributes, grcinventory.AttributeOwnerNotRequired)
		delete(attributes, grcinventory.AttributeOwnerSource)
		delete(attributes, "owner")
		delete(attributes, "accountability_required")
		delete(attributes, "accountability_updated_by")
		delete(attributes, "accountability_updated_at")
	default:
		return nil, fmt.Errorf("%w: state must be known, not_required, or clear", errInvalidHTTPRequest)
	}
	if request.State != "clear" {
		attributes[grcinventory.AttributeAccountabilityReason] = fallbackString(request.Reason, accountabilityDefaultReason(request.State))
		attributes["accountability_updated_by"] = strings.TrimSpace(updatedBy)
		attributes["accountability_updated_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	return store.UpsertGRCInventoryScope(ctx, ports.GRCInventoryScopeRecord{
		TenantID:   tenantID,
		AssetURN:   request.AssetURN,
		SourceID:   sourceID,
		ScopeState: scopeState,
		Reason:     scopeReason,
		UpdatedBy:  updatedBy,
		Attributes: attributes,
	})
}

func loadGRCInventoryScopeRecord(ctx context.Context, store ports.GRCInventoryScopeStore, tenantID string, assetURN string) (*ports.GRCInventoryScopeRecord, error) {
	records, err := store.ListGRCInventoryScopes(ctx, ports.GRCInventoryScopeFilter{
		TenantID:  tenantID,
		AssetURNs: []string{assetURN},
		Limit:     1,
	})
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return records[0], nil
}

func accountabilityDefaultReason(state string) string {
	switch state {
	case grcinventory.AccountabilityKnown:
		return "Owner assigned from inventory"
	case grcinventory.AccountabilityNone:
		return "Owner not required for GRC review"
	default:
		return ""
	}
}

func (a *App) applyGRCInventoryScopeToSourceRuntimes(ctx context.Context, tenantID string, request grcInventoryScopeUpdateRequest) ([]grcInventoryScopePropagationResult, error) {
	store := sourceRuntimeStore(a.deps.StateStore)
	if store == nil {
		return nil, nil
	}
	request.AssetURN = strings.TrimSpace(request.AssetURN)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	if request.AssetURN == "" || (request.RuntimeID == "" && request.SourceID == "") {
		return nil, nil
	}
	runtimes, skipped, err := grcInventoryScopeTargetRuntimes(ctx, store, tenantID, request)
	if err != nil {
		return nil, err
	}
	results := append([]grcInventoryScopePropagationResult{}, skipped...)
	selector := resourcescope.SelectorFromURN(request.AssetURN, request.Reason)
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		if tenantID != "" && runtime.GetTenantId() != tenantID {
			return nil, errTenantForbidden
		}
		if request.SourceID != "" && runtime.GetSourceId() != request.SourceID {
			return nil, fmt.Errorf("%w: source_id does not match runtime", errInvalidHTTPRequest)
		}
		next := proto.Clone(runtime).(*cerebrov1.SourceRuntime)
		if next.Config == nil {
			next.Config = map[string]string{}
		}
		policy, err := resourcescope.FromConfig(next.Config)
		if err != nil {
			return nil, fmt.Errorf("%w: source runtime resource scope policy", errInvalidHTTPRequest)
		}
		switch request.ScopeState {
		case grcinventory.ScopeStateOutScope:
			policy, err = resourcescope.AddExcludedResource(policy, selector)
		case grcinventory.ScopeStateInScope:
			policy, err = resourcescope.RemoveExcludedResource(policy, selector)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: update source runtime resource scope policy: %w", errInvalidHTTPRequest, err)
		}
		value, err := resourcescope.ConfigValue(policy)
		if err != nil {
			return nil, fmt.Errorf("%w: encode source runtime resource scope policy: %w", errInvalidHTTPRequest, err)
		}
		if value == "" {
			delete(next.Config, resourcescope.ConfigKey)
		} else {
			next.Config[resourcescope.ConfigKey] = value
		}
		if err := store.PutSourceRuntime(ctx, next); err != nil {
			return nil, err
		}
		results = append(results, grcInventoryScopePropagationResult{
			RuntimeID:        next.GetId(),
			SourceID:         next.GetSourceId(),
			Status:           "updated",
			ExclusionApplied: request.ScopeState == grcinventory.ScopeStateOutScope,
		})
	}
	return results, nil
}

func grcInventoryScopeTargetRuntimes(ctx context.Context, store ports.SourceRuntimeStore, tenantID string, request grcInventoryScopeUpdateRequest) ([]*cerebrov1.SourceRuntime, []grcInventoryScopePropagationResult, error) {
	if request.RuntimeID != "" {
		runtime, err := store.GetSourceRuntime(ctx, request.RuntimeID)
		if err != nil {
			return nil, nil, err
		}
		return []*cerebrov1.SourceRuntime{runtime}, nil, nil
	}
	if request.SourceID == "" {
		return nil, nil, nil
	}
	listStore, ok := store.(ports.SourceRuntimeListStore)
	if !ok {
		return nil, []grcInventoryScopePropagationResult{{
			SourceID: request.SourceID,
			Status:   "skipped",
			Reason:   "source runtime listing is unavailable",
		}}, nil
	}
	runtimes, err := listStore.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{
		TenantID: tenantID,
		SourceID: request.SourceID,
		Limit:    500,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(runtimes) == 0 {
		return nil, []grcInventoryScopePropagationResult{{
			SourceID: request.SourceID,
			Status:   "skipped",
			Reason:   "no matching source runtimes",
		}}, nil
	}
	return runtimes, nil, nil
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
	if err := validateGRCInventoryAssetURN(request.AssetURN); err != nil {
		writeGRCError(w, err)
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
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeInventory)
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
		writeGRCError(w, normalizeIDLookupError(err, ports.ErrGRCInventoryAssetReportNotFound))
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), record.AssetURN); err != nil {
		writeGRCError(w, normalizeIDLookupError(err, ports.ErrGRCInventoryAssetReportNotFound))
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
	a.bumpGRCCacheVersions(r.Context(), record.TenantID, grcCacheScopeInventory)
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
			grcinventory.ApplyScope(&assets[index], byURN[assets[index].URN])
		}
	}
	assets, err := a.enrichGRCInventoryAssetsWithReports(r, scope, assets)
	if err != nil {
		return nil, err
	}
	for index := range assets {
		grcinventory.ApplyReviewPosture(&assets[index])
	}
	return assets, nil
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
		grcinventory.ApplyAssetReportSummary(&assets[index], byURN[assets[index].URN])
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
	if asset.ScopeState == grcinventory.ScopeStateOutScope {
		reasons = append(reasons, "out of GRC purview")
	}
	asset.RiskScore = grcinventory.ClampRisk(score)
	asset.RiskLevel = grcinventory.RiskLevel(asset.RiskScore)
	asset.RiskReasons = grcinventory.UniqueStrings(reasons)
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
	grcinventory.ApplyReviewPosture(&asset)
	actions := []grcInventoryAction{}
	if asset.ScopeState == grcinventory.ScopeStateOutScope {
		actions = append(actions, grcInventoryAction{Title: "Confirm GRC purview", Description: "This asset is scoped out. Scope it back in if it should participate in controls, tests, and evidence review.", Priority: "high"})
	}
	if asset.Accountability != nil && asset.Accountability.State == grcinventory.AccountabilityRequired {
		actions = append(actions, grcInventoryAction{Title: "Assign accountable owner", Description: "Add ownership metadata for this GRC-relevant asset so evidence, findings, and remediation work have a responsible team.", Priority: "high"})
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
		actions = append(actions, grcInventoryAction{Title: "Keep monitoring", Description: "No immediate scope, accountability, vulnerability, or test gaps were detected for this asset.", Priority: "low"})
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

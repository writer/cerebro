package bootstrap

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
)

const grcRuntimeStatusConfigKey = "__cerebro_runtime_status"

type grcInventoryCategoriesResponse struct {
	Categories  []graphquery.InventoryCategory `json:"categories"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

type grcInventoryAssetsResponse struct {
	Assets      []graphquery.InventoryAsset `json:"assets"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

type grcInventoryAssetDetailResponse struct {
	Asset           graphquery.InventoryAsset   `json:"asset"`
	Graph           any                         `json:"graph,omitempty"`
	Findings        []grcFindingItem            `json:"findings"`
	Evidence        []grcEvidenceItem           `json:"evidence"`
	Controls        []grcControlItem            `json:"controls"`
	Tests           []grcInventoryTestItem      `json:"tests"`
	Vulnerabilities []grcInventoryVulnerability `json:"vulnerabilities"`
	GeneratedAt     time.Time                   `json:"generated_at"`
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
	GeneratedAt time.Time                   `json:"generated_at"`
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
	writeJSON(w, http.StatusOK, grcInventoryAssetsResponse{Assets: assets, GeneratedAt: time.Now().UTC()})
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
	writeJSON(w, http.StatusOK, grcInventoryAssetDetailResponse{
		Asset:           detail.Asset,
		Graph:           detail.Graph,
		Findings:        findingItems,
		Evidence:        evidenceItems,
		Controls:        controls,
		Tests:           grcInventoryTests(findingItems, controls),
		Vulnerabilities: grcInventoryVulnerabilities(findingItems),
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
		GeneratedAt: time.Now().UTC(),
	})
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
	var vulnerabilities []grcInventoryVulnerability
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

func runtimeConfigValue(config map[string]string, key string) string {
	if config == nil {
		return ""
	}
	return strings.TrimSpace(config[key])
}

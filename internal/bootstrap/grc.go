package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	grcDefaultLimit = uint32(100)
	grcMaxLimit     = uint32(500)
)

type grcScope struct {
	TenantID  string
	RuntimeID string
	SourceID  string
	Limit     uint32
}

type grcDashboardResponse struct {
	Summary     grcSummary        `json:"summary"`
	Findings    []grcFindingItem  `json:"findings"`
	Controls    []grcControlItem  `json:"controls"`
	Evidence    []grcEvidenceItem `json:"evidence"`
	Connectors  []grcConnector    `json:"connectors"`
	GeneratedAt time.Time         `json:"generated_at"`
}

type grcSummary struct {
	OpenFindings     int `json:"open_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	OverdueFindings  int `json:"overdue_findings"`
	Unassigned       int `json:"unassigned"`
	ControlsFailing  int `json:"controls_failing"`
	EvidenceItems    int `json:"evidence_items"`
	Connectors       int `json:"connectors"`
	StaleConnectors  int `json:"stale_connectors"`
}

type grcFindingItem struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Severity        string          `json:"severity"`
	Status          string          `json:"status"`
	Summary         string          `json:"summary,omitempty"`
	TenantID        string          `json:"tenant_id,omitempty"`
	RuntimeID       string          `json:"runtime_id,omitempty"`
	SourceID        string          `json:"source_id,omitempty"`
	Entity          string          `json:"entity,omitempty"`
	ResourceURNs    []string        `json:"resource_urns,omitempty"`
	RuleID          string          `json:"rule_id,omitempty"`
	PolicyID        string          `json:"policy_id,omitempty"`
	PolicyName      string          `json:"policy_name,omitempty"`
	Controls        []grcControlRef `json:"controls,omitempty"`
	EvidenceCount   int             `json:"evidence_count"`
	Owner           string          `json:"owner"`
	SLAStatus       string          `json:"sla_status"`
	DueAt           *time.Time      `json:"due_at,omitempty"`
	FirstObservedAt *time.Time      `json:"first_observed_at,omitempty"`
	LastObservedAt  *time.Time      `json:"last_observed_at,omitempty"`
}

type grcControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type grcControlItem struct {
	FrameworkName    string           `json:"framework_name"`
	ControlID        string           `json:"control_id"`
	Status           string           `json:"status"`
	OpenFindings     int              `json:"open_findings"`
	CriticalFindings int              `json:"critical_findings"`
	HighFindings     int              `json:"high_findings"`
	EvidenceItems    int              `json:"evidence_items"`
	Findings         []grcFindingItem `json:"findings,omitempty"`
}

type grcEvidenceItem struct {
	ID            string    `json:"id"`
	RuntimeID     string    `json:"runtime_id,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	FindingID     string    `json:"finding_id,omitempty"`
	FindingTitle  string    `json:"finding_title,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	ClaimIDs      []string  `json:"claim_ids,omitempty"`
	EventIDs      []string  `json:"event_ids,omitempty"`
	GraphRootURNs []string  `json:"graph_root_urns,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

type grcConnector struct {
	RuntimeID    string     `json:"runtime_id"`
	SourceID     string     `json:"source_id,omitempty"`
	TenantID     string     `json:"tenant_id,omitempty"`
	Status       string     `json:"status"`
	Freshness    string     `json:"freshness"`
	LastSyncedAt *time.Time `json:"last_synced_at,omitempty"`
}

type grcEntityImpactResponse struct {
	EntityURN   string                    `json:"entity_urn"`
	Graph       *ports.EntityNeighborhood `json:"graph,omitempty"`
	Findings    []grcFindingItem          `json:"findings"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

type grcAuditPacketResponse struct {
	ID                string                    `json:"id"`
	Finding           grcFindingItem            `json:"finding"`
	Evidence          []grcEvidenceItem         `json:"evidence"`
	Graph             *ports.EntityNeighborhood `json:"graph,omitempty"`
	Controls          []grcControlRef           `json:"controls,omitempty"`
	RecommendedAction string                    `json:"recommended_action"`
	GeneratedAt       time.Time                 `json:"generated_at"`
}

func (a *App) handleGRCDashboard(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimeSourceIDs := grcRuntimeSourceIDs(runtimes)
	evidenceCounts := grcEvidenceCounts(evidence)
	findingItems := grcFindingItems(findings, runtimeSourceIDs, evidenceCounts)
	evidenceItems := grcEvidenceItems(evidence, grcFindingTitleMap(findings))
	controls := grcControlItems(findingItems, evidenceItems)

	writeJSON(w, http.StatusOK, grcDashboardResponse{
		Summary:     grcBuildSummary(findingItems, controls, evidenceItems, runtimes),
		Findings:    grcLimitFindings(findingItems, 25),
		Controls:    grcLimitControls(controls, 25),
		Evidence:    grcLimitEvidence(evidenceItems, 25),
		Connectors:  grcConnectorItems(runtimes),
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleGRCFindings(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status == "" {
		status = "open"
	} else if strings.EqualFold(status, "all") {
		status = ""
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{
		FindingID:   strings.TrimSpace(r.URL.Query().Get("finding_id")),
		RuleID:      strings.TrimSpace(r.URL.Query().Get("rule_id")),
		Severity:    strings.TrimSpace(r.URL.Query().Get("severity")),
		Status:      status,
		ResourceURN: strings.TrimSpace(r.URL.Query().Get("resource_urn")),
		EventID:     strings.TrimSpace(r.URL.Query().Get("event_id")),
		PolicyID:    strings.TrimSpace(r.URL.Query().Get("policy_id")),
		Limit:       scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":     grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence)),
		"generated_at": time.Now().UTC(),
	})
}

func (a *App) handleGRCControls(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Status: "open", Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	items := grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence))
	writeJSON(w, http.StatusOK, map[string]any{
		"controls":     grcControlItems(items, grcEvidenceItems(evidence, grcFindingTitleMap(findings))),
		"generated_at": time.Now().UTC(),
	})
}

func (a *App) handleGRCEvidence(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{Limit: scope.Limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{
		FindingID:    strings.TrimSpace(r.URL.Query().Get("finding_id")),
		RunID:        strings.TrimSpace(r.URL.Query().Get("run_id")),
		RuleID:       strings.TrimSpace(r.URL.Query().Get("rule_id")),
		GraphRootURN: strings.TrimSpace(r.URL.Query().Get("graph_root_urn")),
		Limit:        scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence":     grcEvidenceItems(evidence, grcFindingTitleMap(findings)),
		"generated_at": time.Now().UTC(),
	})
}

func (a *App) handleGRCEntityImpact(w http.ResponseWriter, r *http.Request) {
	entityURN := strings.TrimSpace(r.PathValue("entityID"))
	if rootURN := strings.TrimSpace(r.URL.Query().Get("root_urn")); rootURN != "" {
		entityURN = rootURN
	}
	if entityURN == "" {
		writeGRCError(w, fmt.Errorf("%w: entity urn is required", errInvalidHTTPRequest))
		return
	}
	if err := authorizeCerebroURNTenant(r.Context(), entityURN); err != nil {
		writeGRCError(w, err)
		return
	}
	limit, err := grcLimitFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	graph, err := graphStore.GetEntityNeighborhood(r.Context(), entityURN, int(limit))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findings, err := a.grcListFindingRecords(r, runtimes, grcFindingFilter{ResourceURN: entityURN, Limit: limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{Limit: limit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grcEntityImpactResponse{
		EntityURN:   entityURN,
		Graph:       graph,
		Findings:    grcFindingItems(findings, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence)),
		GeneratedAt: time.Now().UTC(),
	})
}

func (a *App) handleGRCAuditPacket(w http.ResponseWriter, r *http.Request) {
	findingID := strings.TrimSpace(r.PathValue("packetID"))
	if findingID == "" {
		writeGRCError(w, fmt.Errorf("%w: finding id is required", errInvalidHTTPRequest))
		return
	}
	store := findingStore(a.deps.StateStore)
	if store == nil {
		writeGRCError(w, findings.ErrRuntimeUnavailable)
		return
	}
	if err := authorizeFindingIDTenant(r.Context(), store, findingID); err != nil {
		writeGRCError(w, err)
		return
	}
	finding, err := store.GetFinding(r.Context(), findingID)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, grcScope{TenantID: finding.TenantID, RuntimeID: finding.RuntimeID, Limit: grcDefaultLimit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingID: finding.ID, Limit: grcDefaultLimit})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	var graph *ports.EntityNeighborhood
	if len(finding.ResourceURNs) > 0 {
		if graphStore := graphQueryStore(a.deps.GraphStore); graphStore != nil {
			graph, _ = graphStore.GetEntityNeighborhood(r.Context(), finding.ResourceURNs[0], int(grcDefaultLimit))
		}
	}
	items := grcFindingItems([]*ports.FindingRecord{finding}, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence))
	if len(items) == 0 {
		writeGRCError(w, ports.ErrFindingNotFound)
		return
	}
	writeJSON(w, http.StatusOK, grcAuditPacketResponse{
		ID:                finding.ID,
		Finding:           items[0],
		Evidence:          grcEvidenceItems(evidence, map[string]string{finding.ID: finding.Title}),
		Graph:             graph,
		Controls:          grcControlRefs(finding.ControlRefs),
		RecommendedAction: grcRecommendedAction(items[0]),
		GeneratedAt:       time.Now().UTC(),
	})
}

type grcFindingFilter struct {
	FindingID   string
	RuleID      string
	Severity    string
	Status      string
	ResourceURN string
	EventID     string
	PolicyID    string
	Limit       uint32
}

type grcEvidenceFilter struct {
	FindingID    string
	RunID        string
	RuleID       string
	GraphRootURN string
	Limit        uint32
}

func grcScopeFromRequest(r *http.Request) (grcScope, error) {
	limit, err := grcLimitFromRequest(r)
	if err != nil {
		return grcScope{}, err
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
			tenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant"))
	}
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		return grcScope{}, errTenantForbidden
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		return grcScope{}, err
	}
	return grcScope{
		TenantID:  tenantID,
		RuntimeID: strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		SourceID:  strings.TrimSpace(r.URL.Query().Get("source_id")),
		Limit:     limit,
	}, nil
}

func grcLimitFromRequest(r *http.Request) (uint32, error) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		return 0, err
	}
	if limit == 0 {
		return grcDefaultLimit, nil
	}
	if limit > grcMaxLimit {
		return 0, fmt.Errorf("%w: limit must be <= %d", errInvalidHTTPRequest, grcMaxLimit)
	}
	return limit, nil
}

func (a *App) grcListRuntimes(r *http.Request, scope grcScope) ([]*cerebrov1.SourceRuntime, error) {
	runtimes, err := a.runtimeService().List(r.Context(), ports.SourceRuntimeFilter{
		RuntimeID: scope.RuntimeID,
		TenantID:  scope.TenantID,
		SourceID:  scope.SourceID,
		Limit:     scope.Limit,
	})
	if err != nil {
		return nil, err
	}
	return runtimes, nil
}

func (a *App) grcListFindingRecords(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcFindingFilter) ([]*ports.FindingRecord, error) {
	store := findingStore(a.deps.StateStore)
	if store == nil {
		return nil, findings.ErrRuntimeUnavailable
	}
	limit := filter.Limit
	if limit == 0 {
		limit = grcDefaultLimit
	}
	var records []*ports.FindingRecord
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		items, err := store.ListFindings(r.Context(), ports.ListFindingsRequest{
			TenantID:    strings.TrimSpace(runtime.GetTenantId()),
			RuntimeID:   strings.TrimSpace(runtime.GetId()),
			FindingID:   filter.FindingID,
			RuleID:      filter.RuleID,
			Severity:    filter.Severity,
			Status:      filter.Status,
			ResourceURN: filter.ResourceURN,
			EventID:     filter.EventID,
			PolicyID:    filter.PolicyID,
			Limit:       limit,
		})
		if err != nil {
			return nil, err
		}
		records = append(records, items...)
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) < severityRank(right.Severity)
		}
		if left.LastObservedAt.Equal(right.LastObservedAt) {
			return left.ID < right.ID
		}
		return left.LastObservedAt.After(right.LastObservedAt)
	})
	if len(records) > int(limit) {
		records = records[:int(limit)]
	}
	return records, nil
}

func (a *App) grcListEvidenceRecords(r *http.Request, runtimes []*cerebrov1.SourceRuntime, filter grcEvidenceFilter) ([]*cerebrov1.FindingEvidence, error) {
	store := findingEvidenceStore(a.deps.StateStore)
	if store == nil {
		return nil, findings.ErrRuntimeUnavailable
	}
	limit := filter.Limit
	if limit == 0 {
		limit = grcDefaultLimit
	}
	var records []*cerebrov1.FindingEvidence
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		items, err := store.ListFindingEvidence(r.Context(), ports.ListFindingEvidenceRequest{
			RuntimeID:    strings.TrimSpace(runtime.GetId()),
			FindingID:    filter.FindingID,
			RunID:        filter.RunID,
			RuleID:       filter.RuleID,
			GraphRootURN: filter.GraphRootURN,
			Limit:        limit,
		})
		if err != nil {
			return nil, err
		}
		records = append(records, items...)
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i].GetCreatedAt().AsTime()
		right := records[j].GetCreatedAt().AsTime()
		if left.Equal(right) {
			return records[i].GetId() < records[j].GetId()
		}
		return left.After(right)
	})
	if len(records) > int(limit) {
		records = records[:int(limit)]
	}
	return records, nil
}

func grcRuntimeSourceIDs(runtimes []*cerebrov1.SourceRuntime) map[string]string {
	values := make(map[string]string, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			values[runtime.GetId()] = runtime.GetSourceId()
		}
	}
	return values
}

func grcEvidenceCounts(evidence []*cerebrov1.FindingEvidence) map[string]int {
	counts := map[string]int{}
	for _, item := range evidence {
		if item != nil && strings.TrimSpace(item.GetFindingId()) != "" {
			counts[item.GetFindingId()]++
		}
	}
	return counts
}

func grcFindingTitleMap(findings []*ports.FindingRecord) map[string]string {
	titles := map[string]string{}
	for _, finding := range findings {
		if finding != nil {
			titles[finding.ID] = finding.Title
		}
	}
	return titles
}

func grcFindingItems(findings []*ports.FindingRecord, sourceIDs map[string]string, evidenceCounts map[string]int) []grcFindingItem {
	items := make([]grcFindingItem, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		items = append(items, grcFindingItem{
			ID:              finding.ID,
			Title:           fallbackString(finding.Title, finding.RuleID, finding.ID),
			Severity:        strings.ToUpper(strings.TrimSpace(finding.Severity)),
			Status:          normalizedFindingStatus(finding.Status),
			Summary:         finding.Summary,
			TenantID:        finding.TenantID,
			RuntimeID:       finding.RuntimeID,
			SourceID:        sourceIDs[finding.RuntimeID],
			Entity:          primaryEntity(finding),
			ResourceURNs:    append([]string(nil), finding.ResourceURNs...),
			RuleID:          finding.RuleID,
			PolicyID:        finding.PolicyID,
			PolicyName:      finding.PolicyName,
			Controls:        grcControlRefs(finding.ControlRefs),
			EvidenceCount:   evidenceCounts[finding.ID],
			Owner:           fallbackString(finding.Assignee, "Unassigned"),
			SLAStatus:       grcSLAStatus(finding),
			DueAt:           timePtr(finding.DueAt),
			FirstObservedAt: timePtr(finding.FirstObservedAt),
			LastObservedAt:  timePtr(finding.LastObservedAt),
		})
	}
	return items
}

func grcControlRefs(refs []ports.FindingControlRef) []grcControlRef {
	items := make([]grcControlRef, 0, len(refs))
	for _, ref := range refs {
		framework := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if framework == "" || controlID == "" {
			continue
		}
		items = append(items, grcControlRef{FrameworkName: framework, ControlID: controlID})
	}
	return items
}

func grcEvidenceItems(evidence []*cerebrov1.FindingEvidence, findingTitles map[string]string) []grcEvidenceItem {
	items := make([]grcEvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		if item == nil {
			continue
		}
		items = append(items, grcEvidenceItem{
			ID:            item.GetId(),
			RuntimeID:     item.GetRuntimeId(),
			RuleID:        item.GetRuleId(),
			FindingID:     item.GetFindingId(),
			FindingTitle:  findingTitles[item.GetFindingId()],
			RunID:         item.GetRunId(),
			ClaimIDs:      append([]string(nil), item.GetClaimIds()...),
			EventIDs:      append([]string(nil), item.GetEventIds()...),
			GraphRootURNs: append([]string(nil), item.GetGraphRootUrns()...),
			CreatedAt:     item.GetCreatedAt().AsTime(),
		})
	}
	return items
}

func grcControlItems(findings []grcFindingItem, evidence []grcEvidenceItem) []grcControlItem {
	controlMap := map[string]*grcControlItem{}
	evidenceByFinding := map[string]int{}
	for _, item := range evidence {
		evidenceByFinding[item.FindingID]++
	}
	for _, finding := range findings {
		refs := finding.Controls
		if len(refs) == 0 {
			refs = []grcControlRef{{FrameworkName: "Unmapped", ControlID: "Needs mapping"}}
		}
		for _, ref := range refs {
			key := ref.FrameworkName + "\x00" + ref.ControlID
			control := controlMap[key]
			if control == nil {
				control = &grcControlItem{
					FrameworkName: ref.FrameworkName,
					ControlID:     ref.ControlID,
					Status:        "passing",
				}
				controlMap[key] = control
			}
			control.Findings = append(control.Findings, finding)
			if finding.Status == "OPEN" || strings.EqualFold(finding.Status, "open") {
				control.OpenFindings++
				control.Status = "failing"
				if finding.Severity == "CRITICAL" {
					control.CriticalFindings++
				}
				if finding.Severity == "HIGH" {
					control.HighFindings++
				}
			}
			control.EvidenceItems += evidenceByFinding[finding.ID]
		}
	}
	controls := make([]grcControlItem, 0, len(controlMap))
	for _, control := range controlMap {
		controls = append(controls, *control)
	}
	sort.Slice(controls, func(i, j int) bool {
		left := controls[i]
		right := controls[j]
		if left.OpenFindings != right.OpenFindings {
			return left.OpenFindings > right.OpenFindings
		}
		return left.FrameworkName+left.ControlID < right.FrameworkName+right.ControlID
	})
	return controls
}

func grcConnectorItems(runtimes []*cerebrov1.SourceRuntime) []grcConnector {
	items := make([]grcConnector, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		lastSyncedAt := timestampPtr(runtime.GetLastSyncedAt())
		items = append(items, grcConnector{
			RuntimeID:    runtime.GetId(),
			SourceID:     runtime.GetSourceId(),
			TenantID:     runtime.GetTenantId(),
			Status:       connectorStatus(lastSyncedAt),
			Freshness:    connectorFreshness(lastSyncedAt),
			LastSyncedAt: lastSyncedAt,
		})
	}
	return items
}

func grcBuildSummary(findings []grcFindingItem, controls []grcControlItem, evidence []grcEvidenceItem, runtimes []*cerebrov1.SourceRuntime) grcSummary {
	var summary grcSummary
	summary.EvidenceItems = len(evidence)
	summary.Connectors = len(runtimes)
	for _, finding := range findings {
		if finding.Status == "OPEN" {
			summary.OpenFindings++
			if finding.Severity == "CRITICAL" {
				summary.CriticalFindings++
			}
			if finding.Severity == "HIGH" {
				summary.HighFindings++
			}
			if finding.SLAStatus == "overdue" {
				summary.OverdueFindings++
			}
			if finding.Owner == "Unassigned" {
				summary.Unassigned++
			}
		}
	}
	for _, control := range controls {
		if control.Status == "failing" {
			summary.ControlsFailing++
		}
	}
	for _, runtime := range runtimes {
		if connectorStatus(timestampPtr(runtime.GetLastSyncedAt())) == "stale" {
			summary.StaleConnectors++
		}
	}
	return summary
}

func grcLimitFindings(items []grcFindingItem, limit int) []grcFindingItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func grcLimitControls(items []grcControlItem, limit int) []grcControlItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func grcLimitEvidence(items []grcEvidenceItem, limit int) []grcEvidenceItem {
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func primaryEntity(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	for _, urn := range finding.ResourceURNs {
		if strings.TrimSpace(urn) != "" {
			return strings.TrimSpace(urn)
		}
	}
	return fallbackString(finding.PolicyName, finding.PolicyID, finding.RuleID)
}

func normalizedFindingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "open", "finding_status_open":
		return "OPEN"
	case "resolved", "finding_status_resolved":
		return "RESOLVED"
	case "suppressed", "finding_status_suppressed":
		return "SUPPRESSED"
	default:
		return "UNKNOWN"
	}
}

func grcSLAStatus(finding *ports.FindingRecord) string {
	if finding == nil {
		return "unknown"
	}
	if normalizedFindingStatus(finding.Status) != "OPEN" {
		return "closed"
	}
	if finding.DueAt.IsZero() {
		return "no_due_date"
	}
	if time.Now().UTC().After(finding.DueAt) {
		return "overdue"
	}
	if time.Until(finding.DueAt) <= 72*time.Hour {
		return "due_soon"
	}
	return "on_track"
}

func grcRecommendedAction(finding grcFindingItem) string {
	if finding.Owner == "Unassigned" {
		return "Assign an owner, confirm evidence, and set a remediation due date."
	}
	if finding.EvidenceCount == 0 {
		return "Request supporting evidence before audit review."
	}
	if len(finding.Controls) == 0 {
		return "Map this finding to the affected control objective."
	}
	return "Review evidence, confirm impact, and update remediation status."
}

func connectorStatus(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "unknown"
	}
	if time.Since(*lastSyncedAt) > 24*time.Hour {
		return "stale"
	}
	return "healthy"
}

func connectorFreshness(lastSyncedAt *time.Time) string {
	if lastSyncedAt == nil {
		return "never_synced"
	}
	age := time.Since(*lastSyncedAt)
	switch {
	case age <= time.Hour:
		return "fresh"
	case age <= 24*time.Hour:
		return "recent"
	default:
		return "stale"
	}
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

func fallbackString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func timestampPtr(value *timestamppb.Timestamp) *time.Time {
	if value == nil {
		return nil
	}
	return timePtr(value.AsTime())
}

func writeGRCError(w http.ResponseWriter, err error) {
	statusCode := http.StatusInternalServerError
	switch {
	case errors.Is(err, errTenantForbidden):
		statusCode = http.StatusForbidden
	case errors.Is(err, ports.ErrSourceRuntimeNotFound),
		errors.Is(err, ports.ErrFindingNotFound),
		errors.Is(err, ports.ErrFindingEvidenceNotFound),
		errors.Is(err, ports.ErrGraphEntityNotFound):
		statusCode = http.StatusNotFound
	case errors.Is(err, sourceruntime.ErrRuntimeUnavailable),
		errors.Is(err, findings.ErrRuntimeUnavailable),
		errors.Is(err, graphquery.ErrRuntimeUnavailable):
		statusCode = http.StatusServiceUnavailable
	case errors.Is(err, sourceruntime.ErrInvalidRequest),
		errors.Is(err, findings.ErrInvalidRequest),
		errors.Is(err, graphquery.ErrInvalidRequest),
		errors.Is(err, errInvalidHTTPRequest):
		statusCode = http.StatusBadRequest
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}

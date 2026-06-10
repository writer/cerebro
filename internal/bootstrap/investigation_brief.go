package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
)

const investigationBriefDefaultLimit = uint32(25)

var askFindingIDPattern = regexp.MustCompile(`(?i)\bfinding[-_][a-z0-9_.:-]+\b`)

type investigationBriefResponse struct {
	ID                string                    `json:"id"`
	Kind              string                    `json:"kind"`
	Finding           grcFindingItem            `json:"finding"`
	Evidence          []grcEvidenceItem         `json:"evidence"`
	Graph             *ports.EntityNeighborhood `json:"graph,omitempty"`
	Controls          []grcControlRef           `json:"controls,omitempty"`
	Trust             investigationBriefTrust   `json:"trust"`
	NextPivots        []investigationBriefPivot `json:"next_pivots"`
	RecommendedAction string                    `json:"recommended_action"`
	Markdown          string                    `json:"markdown"`
	GeneratedAt       time.Time                 `json:"generated_at"`
}

type investigationBriefTrust struct {
	RuntimeID        string     `json:"runtime_id,omitempty"`
	SourceID         string     `json:"source_id,omitempty"`
	RuntimeStatus    string     `json:"runtime_status,omitempty"`
	RuntimeFreshness string     `json:"runtime_freshness,omitempty"`
	LastSyncedAt     *time.Time `json:"last_synced_at,omitempty"`
	SyncLagSeconds   *int64     `json:"sync_lag_seconds,omitempty"`
	GraphStatus      string     `json:"graph_status"`
	GraphRootURN     string     `json:"graph_root_urn,omitempty"`
	EvidenceCount    int        `json:"evidence_count"`
	LimitApplied     uint32     `json:"limit_applied"`
	DataGaps         []string   `json:"data_gaps,omitempty"`
}

type investigationBriefPivot struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
	ID    string `json:"id,omitempty"`
	URN   string `json:"urn,omitempty"`
	Route string `json:"route,omitempty"`
}

func (a *App) handleGetInvestigationBrief(w http.ResponseWriter, r *http.Request) {
	limit, err := investigationBriefLimitFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	brief, err := a.buildInvestigationBrief(r, strings.TrimSpace(r.PathValue("findingID")), limit, boolQueryParamDefault(r, "skip_graph", false))
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, brief)
}

func (a *App) buildInvestigationBrief(r *http.Request, findingID string, limit uint32, skipGraph bool) (investigationBriefResponse, error) {
	if findingID == "" {
		return investigationBriefResponse{}, fmt.Errorf("%w: finding id is required", errInvalidHTTPRequest)
	}
	if limit == 0 {
		limit = investigationBriefDefaultLimit
	}
	store := findingStore(a.deps.StateStore)
	if store == nil {
		return investigationBriefResponse{}, findings.ErrRuntimeUnavailable
	}
	if err := authorizeFindingIDTenant(r.Context(), store, findingID); err != nil {
		return investigationBriefResponse{}, err
	}
	finding, err := a.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return investigationBriefResponse{}, err
	}
	runtimes, err := a.grcListRuntimes(r, grcScope{TenantID: finding.TenantID, RuntimeID: finding.RuntimeID, Limit: limit})
	if err != nil {
		return investigationBriefResponse{}, err
	}
	evidence, err := a.grcListEvidenceRecords(r, runtimes, grcEvidenceFilter{FindingID: finding.ID, Limit: limit})
	if err != nil {
		return investigationBriefResponse{}, err
	}
	gaps := []string{}
	var graph *ports.EntityNeighborhood
	graphStatus := "unavailable"
	graphRootURN := firstNonEmptyBriefString(finding.ResourceURNs...)
	if skipGraph {
		graphStatus = "skipped"
	} else if graphRootURN == "" {
		gaps = append(gaps, "finding has no resource URN for graph context")
	} else if graphStore := graphQueryStore(a.deps.GraphStore); graphStore != nil {
		graph, err = graphStore.GetEntityNeighborhood(r.Context(), graphRootURN, int(limit))
		if err != nil {
			gaps = append(gaps, "graph neighborhood unavailable")
			graphStatus = "error"
		} else {
			graphStatus = "available"
		}
	} else {
		gaps = append(gaps, "graph store is not configured")
	}
	items := grcFindingItems([]*ports.FindingRecord{finding}, grcRuntimeSourceIDs(runtimes), grcEvidenceCounts(evidence))
	if len(items) == 0 {
		return investigationBriefResponse{}, ports.ErrFindingNotFound
	}
	if len(evidence) == 0 {
		gaps = append(gaps, "no finding evidence matched this brief scope")
	}
	runtime := firstRuntimeByID(runtimes, finding.RuntimeID)
	if runtime == nil {
		gaps = append(gaps, "source runtime metadata was not found")
	}
	trust := investigationBriefTrust{
		RuntimeID:      finding.RuntimeID,
		GraphStatus:    graphStatus,
		GraphRootURN:   graphRootURN,
		EvidenceCount:  len(evidence),
		LimitApplied:   limit,
		DataGaps:       gaps,
		SyncLagSeconds: nil,
	}
	if runtime != nil {
		lastSyncedAt := timestampPtr(runtime.GetLastSyncedAt())
		trust.SourceID = runtime.GetSourceId()
		trust.RuntimeStatus = connectorStatus(lastSyncedAt)
		trust.RuntimeFreshness = connectorFreshness(lastSyncedAt)
		trust.LastSyncedAt = lastSyncedAt
		trust.SyncLagSeconds = timestampLagSeconds(lastSyncedAt)
	}
	brief := investigationBriefResponse{
		ID:                finding.ID,
		Kind:              "finding",
		Finding:           items[0],
		Evidence:          grcEvidenceItems(evidence, map[string]string{finding.ID: finding.Title}),
		Graph:             graph,
		Controls:          grcControlRefs(finding.ControlRefs),
		Trust:             trust,
		NextPivots:        investigationBriefPivots(finding, graphRootURN),
		RecommendedAction: grcRecommendedAction(items[0]),
		GeneratedAt:       time.Now().UTC(),
	}
	brief.Markdown = investigationBriefMarkdown(brief)
	return brief, nil
}

func investigationBriefLimitFromRequest(r *http.Request) (uint32, error) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		return 0, err
	}
	if limit == 0 {
		return investigationBriefDefaultLimit, nil
	}
	if limit > grcMaxLimit {
		return 0, fmt.Errorf("%w: limit must be <= %d", errInvalidHTTPRequest, grcMaxLimit)
	}
	return limit, nil
}

func boolQueryParamDefault(r *http.Request, key string, fallback bool) bool {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	return strings.EqualFold(raw, "true") || raw == "1" || strings.EqualFold(raw, "yes")
}

func firstRuntimeByID(runtimes []*cerebrov1.SourceRuntime, id string) *cerebrov1.SourceRuntime {
	for _, runtime := range runtimes {
		if runtime != nil && runtime.GetId() == id {
			return runtime
		}
	}
	return nil
}

func firstNonEmptyBriefString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func investigationBriefPivots(finding *ports.FindingRecord, graphRootURN string) []investigationBriefPivot {
	if finding == nil {
		return nil
	}
	pivots := []investigationBriefPivot{{
		Label: "Open finding record",
		Kind:  "finding",
		ID:    finding.ID,
		Route: "/findings/" + url.PathEscape(finding.ID),
	}}
	if finding.RuntimeID != "" {
		pivots = append(pivots, investigationBriefPivot{
			Label: "Review supporting evidence",
			Kind:  "evidence",
			ID:    finding.ID,
			Route: "/source-runtimes/" + url.PathEscape(finding.RuntimeID) + "/finding-evidence?finding_id=" + url.QueryEscape(finding.ID),
		}, investigationBriefPivot{
			Label: "Check source runtime freshness",
			Kind:  "runtime",
			ID:    finding.RuntimeID,
			Route: "/source-runtimes/" + url.PathEscape(finding.RuntimeID),
		})
	}
	if graphRootURN != "" {
		pivots = append(pivots, investigationBriefPivot{
			Label: "Inspect graph neighborhood",
			Kind:  "graph",
			URN:   graphRootURN,
			Route: "/platform/graph/neighborhood?root_urn=" + url.QueryEscape(graphRootURN),
		})
	}
	if finding.RuleID != "" && finding.RuntimeID != "" {
		pivots = append(pivots, investigationBriefPivot{
			Label: "Compare candidate snapshots",
			Kind:  "candidate",
			ID:    finding.RuleID,
			Route: "/source-runtimes/" + url.PathEscape(finding.RuntimeID) + "/finding-candidates?rule_id=" + url.QueryEscape(finding.RuleID),
		})
	}
	return pivots
}

func investigationBriefMarkdown(brief investigationBriefResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Investigation Brief: %s\n\n", brief.Finding.Title)
	fmt.Fprintf(&b, "- Finding: `%s` (%s, %s)\n", brief.Finding.ID, brief.Finding.Severity, brief.Finding.Status)
	if brief.Finding.RiskScore != 0 {
		fmt.Fprintf(&b, "- Risk score: `%d`\n", brief.Finding.RiskScore)
	}
	if brief.Finding.Owner != "" {
		fmt.Fprintf(&b, "- Owner: `%s`\n", brief.Finding.Owner)
	}
	if brief.Trust.RuntimeID != "" {
		fmt.Fprintf(&b, "- Runtime: `%s` (%s, %s)\n", brief.Trust.RuntimeID, fallbackString(brief.Trust.RuntimeStatus, "unknown"), fallbackString(brief.Trust.RuntimeFreshness, "unknown"))
	}
	fmt.Fprintf(&b, "- Evidence records returned: `%d`\n", brief.Trust.EvidenceCount)
	fmt.Fprintf(&b, "- Graph context: `%s`\n\n", brief.Trust.GraphStatus)
	if brief.Finding.Summary != "" {
		fmt.Fprintf(&b, "## What matters\n\n%s\n\n", brief.Finding.Summary)
	}
	if len(brief.Finding.RiskReasons) > 0 {
		b.WriteString("## Risk reasons\n\n")
		for _, reason := range brief.Finding.RiskReasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		b.WriteString("\n")
	}
	if len(brief.Trust.DataGaps) > 0 {
		b.WriteString("## Trust gaps\n\n")
		for _, gap := range brief.Trust.DataGaps {
			fmt.Fprintf(&b, "- %s\n", gap)
		}
		b.WriteString("\n")
	}
	if brief.RecommendedAction != "" {
		fmt.Fprintf(&b, "## Recommended next action\n\n%s\n", brief.RecommendedAction)
	}
	return strings.TrimSpace(b.String())
}

func (a *App) mcpInvestigationBrief(r *http.Request, args map[string]any) (any, error) {
	findingID := mcpStringArg(args, "finding_id")
	if findingID == "" {
		return nil, fmt.Errorf("%w: finding_id is required", findings.ErrInvalidRequest)
	}
	limit, err := mcpBoundedLimit(args, "limit", int(investigationBriefDefaultLimit), int(grcMaxLimit))
	if err != nil {
		return nil, err
	}
	brief, err := a.buildInvestigationBrief(r, findingID, boundedUint32(limit), mcpBoolArg(args, "skip_graph"))
	if err != nil {
		return nil, mcpNormalizeIDLookupError(err, ports.ErrFindingNotFound)
	}
	value, err := jsonValue(brief)
	if err != nil {
		return nil, err
	}
	return mcpAddResponseMetadata(value, mcpResponseMetadata(limit, len(brief.Evidence), brief.Trust.DataGaps)), nil
}

func askInvestigationBriefFindingID(request graphagent.AskRequest) (string, bool) {
	question := strings.ToLower(strings.TrimSpace(request.Question))
	if !strings.Contains(question, "brief") && !strings.Contains(question, "investigat") {
		return "", false
	}
	if id := findingIDFromAskValue(request.ScopeURN); id != "" {
		return id, true
	}
	if match := askFindingIDPattern.FindString(request.Question); match != "" {
		return match, true
	}
	return "", false
}

func findingIDFromAskValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(value), "finding-") || strings.HasPrefix(strings.ToLower(value), "finding_") {
		return value
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == '/' || r == '#'
	})
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if strings.HasPrefix(strings.ToLower(part), "finding-") || strings.HasPrefix(strings.ToLower(part), "finding_") {
			return part
		}
	}
	return ""
}

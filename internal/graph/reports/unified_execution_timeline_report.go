package reports

import (
	"sort"
	"strings"
	"time"
)

const (
	defaultUnifiedExecutionTimelineWindow    = 30 * 24 * time.Hour
	defaultUnifiedExecutionTimelineMaxEvents = 200
)

// UnifiedExecutionTimelineReportOptions controls cross-workflow timeline aggregation.
type UnifiedExecutionTimelineReportOptions struct {
	Now             time.Time
	Window          time.Duration
	TenantID        string
	TargetKind      string
	PlaybookID      string
	EvaluationRunID string
	MaxEvents       int
}

// UnifiedExecutionTimelineSummary captures top-line counts for the selected timeline scope.
type UnifiedExecutionTimelineSummary struct {
	Events         int `json:"events"`
	EvaluationRuns int `json:"evaluation_runs"`
	PlaybookRuns   int `json:"playbook_runs"`
	Threads        int `json:"threads"`
	Decisions      int `json:"decisions"`
	Actions        int `json:"actions"`
	Outcomes       int `json:"outcomes"`
	Claims         int `json:"claims"`
	Evidence       int `json:"evidence"`
}

// UnifiedExecutionTimelineEvent captures one chronological workflow event.
type UnifiedExecutionTimelineEvent struct {
	At              time.Time `json:"at,omitempty"`
	ID              string    `json:"id"`
	Kind            string    `json:"kind"`
	Workflow        string    `json:"workflow"`
	Title           string    `json:"title,omitempty"`
	TenantID        string    `json:"tenant_id,omitempty"`
	TargetIDs       []string  `json:"target_ids,omitempty"`
	TargetKinds     []string  `json:"target_kinds,omitempty"`
	EvaluationRunID string    `json:"evaluation_run_id,omitempty"`
	ConversationID  string    `json:"conversation_id,omitempty"`
	PlaybookID      string    `json:"playbook_id,omitempty"`
	PlaybookRunID   string    `json:"playbook_run_id,omitempty"`
	StageID         string    `json:"stage_id,omitempty"`
	Status          string    `json:"status,omitempty"`
	Verdict         string    `json:"verdict,omitempty"`
	EvidenceIDs     []string  `json:"evidence_ids,omitempty"`
	RelatedClaimIDs []string  `json:"related_claim_ids,omitempty"`
}

// UnifiedExecutionTimelineReport packages one chronological execution view across evaluation and playbook workflows.
type UnifiedExecutionTimelineReport struct {
	GeneratedAt time.Time                       `json:"generated_at"`
	WindowStart time.Time                       `json:"window_start,omitempty"`
	WindowEnd   time.Time                       `json:"window_end,omitempty"`
	Summary     UnifiedExecutionTimelineSummary `json:"summary"`
	Events      []UnifiedExecutionTimelineEvent `json:"events,omitempty"`
}

type unifiedExecutionTimelineCandidate struct {
	UnifiedExecutionTimelineEvent
	scopeKey string
}

type unifiedExecutionTimelineScope struct {
	targetIDs   map[string]struct{}
	targetKinds map[string]struct{}
}

// BuildUnifiedExecutionTimelineReport derives one chronological timeline across evaluation and playbook workflow events.
func BuildUnifiedExecutionTimelineReport(g *Graph, opts UnifiedExecutionTimelineReportOptions) UnifiedExecutionTimelineReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	window := opts.Window
	if window <= 0 {
		window = defaultUnifiedExecutionTimelineWindow
	}
	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultUnifiedExecutionTimelineMaxEvents
	}

	report := UnifiedExecutionTimelineReport{
		GeneratedAt: now,
		WindowStart: now.Add(-window),
		WindowEnd:   now,
	}
	if g == nil {
		return report
	}

	candidates := make([]unifiedExecutionTimelineCandidate, 0)
	scopes := make(map[string]*unifiedExecutionTimelineScope)
	nodes := g.GetNodesByKind(NodeKind("communication_thread"), NodeKindDecision, NodeKindAction, NodeKindOutcome, NodeKindClaim)
	for _, node := range nodes {
		candidate, ok := unifiedExecutionTimelineCandidateFromNode(g, node)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate)
		scope := scopes[candidate.scopeKey]
		if scope == nil {
			scope = &unifiedExecutionTimelineScope{
				targetIDs:   make(map[string]struct{}),
				targetKinds: make(map[string]struct{}),
			}
			scopes[candidate.scopeKey] = scope
		}
		for _, targetID := range candidate.TargetIDs {
			scope.targetIDs[targetID] = struct{}{}
		}
		for _, targetKind := range candidate.TargetKinds {
			scope.targetKinds[targetKind] = struct{}{}
		}
	}

	baseEvents := make([]UnifiedExecutionTimelineEvent, 0, len(candidates))
	filteredClaims := make([]UnifiedExecutionTimelineEvent, 0)
	for _, candidate := range candidates {
		scope := scopes[candidate.scopeKey]
		if scope != nil {
			if len(candidate.TargetIDs) == 0 {
				candidate.TargetIDs = sortedTimelineStrings(scope.targetIDs)
			}
			if len(candidate.TargetKinds) == 0 {
				candidate.TargetKinds = sortedTimelineStrings(scope.targetKinds)
			}
		}
		if !unifiedExecutionTimelineMatchesFilters(candidate.UnifiedExecutionTimelineEvent, report.WindowStart, report.WindowEnd, opts) {
			continue
		}
		baseEvents = append(baseEvents, candidate.UnifiedExecutionTimelineEvent)
		if candidate.Kind == string(NodeKindClaim) {
			filteredClaims = append(filteredClaims, candidate.UnifiedExecutionTimelineEvent)
		}
	}

	evidenceEvents := unifiedExecutionTimelineEvidenceEvents(g, filteredClaims, report.WindowStart, report.WindowEnd)
	events := append(baseEvents, evidenceEvents...)
	sort.Slice(events, func(i, j int) bool {
		if !events[i].At.Equal(events[j].At) {
			return events[i].At.Before(events[j].At)
		}
		if unifiedExecutionTimelineKindRank(events[i].Kind) != unifiedExecutionTimelineKindRank(events[j].Kind) {
			return unifiedExecutionTimelineKindRank(events[i].Kind) < unifiedExecutionTimelineKindRank(events[j].Kind)
		}
		return events[i].ID < events[j].ID
	})
	if len(events) > maxEvents {
		events = events[:maxEvents]
	}

	report.Events = events
	report.Summary = unifiedExecutionTimelineSummary(events)
	return report
}

func unifiedExecutionTimelineCandidateFromNode(g *Graph, node *Node) (unifiedExecutionTimelineCandidate, bool) {
	if node == nil {
		return unifiedExecutionTimelineCandidate{}, false
	}
	at, ok := graphObservedAt(node)
	if !ok {
		return unifiedExecutionTimelineCandidate{}, false
	}

	workflow, scopeKey := unifiedExecutionTimelineWorkflow(node)
	if workflow == "" || scopeKey == "" {
		return unifiedExecutionTimelineCandidate{}, false
	}

	event := UnifiedExecutionTimelineEvent{
		At:              at.UTC(),
		ID:              strings.TrimSpace(node.ID),
		Kind:            string(node.Kind),
		Workflow:        workflow,
		Title:           firstNonEmpty(node.Name, graphNodePropertyString(node, "title"), graphNodePropertyString(node, "stage_name")),
		TenantID:        graphNodePropertyString(node, "tenant_id"),
		EvaluationRunID: graphNodePropertyString(node, "evaluation_run_id"),
		ConversationID:  graphNodePropertyString(node, "conversation_id"),
		PlaybookID:      graphNodePropertyString(node, "playbook_id"),
		PlaybookRunID:   graphNodePropertyString(node, "playbook_run_id"),
		StageID:         firstNonEmpty(graphNodePropertyString(node, "stage_id"), graphNodePropertyString(node, "final_stage_id")),
		Status:          graphNodePropertyString(node, "status"),
		Verdict:         graphNodePropertyString(node, "verdict"),
		TargetIDs:       unifiedExecutionTimelineTargetIDs(node),
	}
	if node.Kind == NodeKindClaim {
		if subjectID := strings.TrimSpace(graphNodePropertyString(node, "subject_id")); subjectID != "" {
			event.TargetIDs = append(event.TargetIDs, subjectID)
		}
	}
	event.TargetIDs = uniqueSortedStrings(event.TargetIDs)
	event.TargetKinds = unifiedExecutionTimelineResolveTargetKinds(g, event.TargetIDs)
	event.RelatedClaimIDs = unifiedExecutionTimelineRelatedClaimIDs(g, node.ID)
	if node.Kind == NodeKindClaim {
		event.EvidenceIDs = unifiedExecutionTimelineEvidenceIDs(g, node.ID)
	}
	return unifiedExecutionTimelineCandidate{UnifiedExecutionTimelineEvent: event, scopeKey: scopeKey}, true
}

func unifiedExecutionTimelineWorkflow(node *Node) (string, string) {
	if node == nil {
		return "", ""
	}
	if evaluationRunID := strings.TrimSpace(graphNodePropertyString(node, "evaluation_run_id")); evaluationRunID != "" {
		scopeConversation := firstNonEmpty(graphNodePropertyString(node, "conversation_id"), "__run__")
		return "evaluation", "evaluation:" + evaluationRunID + ":" + scopeConversation
	}
	if playbookRunID := strings.TrimSpace(graphNodePropertyString(node, "playbook_run_id")); playbookRunID != "" {
		return "playbook", "playbook:" + playbookRunID
	}
	if isPlaybookThread(node) || isPlaybookStage(node) || isPlaybookAction(node) || isPlaybookOutcome(node) {
		playbookID := strings.TrimSpace(graphNodePropertyString(node, "playbook_id"))
		if playbookID != "" {
			return "playbook", "playbook:" + playbookID
		}
	}
	return "", ""
}

func unifiedExecutionTimelineTargetIDs(node *Node) []string {
	targetIDs := graphNodePropertyStrings(node, "target_ids")
	return uniqueSortedStrings(targetIDs)
}

func unifiedExecutionTimelineResolveTargetKinds(g *Graph, targetIDs []string) []string {
	if g == nil || len(targetIDs) == 0 {
		return nil
	}
	out := make([]string, 0, len(targetIDs))
	for _, targetID := range targetIDs {
		targetNode, ok := g.GetNode(targetID)
		if !ok || targetNode == nil {
			continue
		}
		if targetKind := strings.TrimSpace(string(targetNode.Kind)); targetKind != "" {
			out = append(out, targetKind)
		}
	}
	return uniqueSortedStrings(out)
}

func unifiedExecutionTimelineEvidenceIDs(g *Graph, claimID string) []string {
	if g == nil || strings.TrimSpace(claimID) == "" {
		return nil
	}
	out := make([]string, 0)
	for _, edge := range g.GetOutEdges(claimID) {
		if edge == nil || edge.Kind != EdgeKindBasedOn {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil || target.Kind != NodeKindEvidence {
			continue
		}
		out = append(out, strings.TrimSpace(target.ID))
	}
	return uniqueSortedStrings(out)
}

func unifiedExecutionTimelineRelatedClaimIDs(g *Graph, nodeID string) []string {
	if g == nil || strings.TrimSpace(nodeID) == "" {
		return nil
	}
	out := make([]string, 0)
	collect := func(edges []*Edge, pick func(*Edge) string) {
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			switch edge.Kind {
			case EdgeKindBasedOn, EdgeKindSupports, EdgeKind("contradicts"), EdgeKindSupersedes:
			default:
				continue
			}
			otherID := strings.TrimSpace(pick(edge))
			if otherID == "" {
				continue
			}
			other, ok := g.GetNode(otherID)
			if !ok || other == nil || other.Kind != NodeKindClaim {
				continue
			}
			out = append(out, otherID)
		}
	}
	collect(g.GetOutEdges(nodeID), func(edge *Edge) string { return edge.Target })
	collect(g.GetInEdges(nodeID), func(edge *Edge) string { return edge.Source })
	return uniqueSortedStrings(out)
}

func unifiedExecutionTimelineEvidenceEvents(g *Graph, claims []UnifiedExecutionTimelineEvent, windowStart, windowEnd time.Time) []UnifiedExecutionTimelineEvent {
	if g == nil || len(claims) == 0 {
		return nil
	}
	type evidenceAccumulator struct {
		UnifiedExecutionTimelineEvent
	}
	acc := make(map[string]*evidenceAccumulator)
	for _, claim := range claims {
		for _, evidenceID := range claim.EvidenceIDs {
			node, ok := g.GetNode(evidenceID)
			if !ok || node == nil || node.Kind != NodeKindEvidence {
				continue
			}
			at, ok := graphObservedAt(node)
			if !ok {
				continue
			}
			at = at.UTC()
			if at.Before(windowStart) || at.After(windowEnd) {
				continue
			}
			key := claim.Workflow + ":" + evidenceID
			entry := acc[key]
			if entry == nil {
				entry = &evidenceAccumulator{
					UnifiedExecutionTimelineEvent: UnifiedExecutionTimelineEvent{
						At:              at,
						ID:              evidenceID,
						Kind:            string(NodeKindEvidence),
						Workflow:        claim.Workflow,
						Title:           firstNonEmpty(node.Name, evidenceID),
						TenantID:        claim.TenantID,
						TargetIDs:       append([]string(nil), claim.TargetIDs...),
						TargetKinds:     append([]string(nil), claim.TargetKinds...),
						EvaluationRunID: claim.EvaluationRunID,
						ConversationID:  claim.ConversationID,
						PlaybookID:      claim.PlaybookID,
						PlaybookRunID:   claim.PlaybookRunID,
						StageID:         claim.StageID,
						RelatedClaimIDs: []string{claim.ID},
					},
				}
				acc[key] = entry
				continue
			}
			entry.RelatedClaimIDs = append(entry.RelatedClaimIDs, claim.ID)
		}
	}
	out := make([]UnifiedExecutionTimelineEvent, 0, len(acc))
	for _, entry := range acc {
		entry.RelatedClaimIDs = uniqueSortedStrings(entry.RelatedClaimIDs)
		out = append(out, entry.UnifiedExecutionTimelineEvent)
	}
	return out
}

func unifiedExecutionTimelineMatchesFilters(event UnifiedExecutionTimelineEvent, windowStart, windowEnd time.Time, opts UnifiedExecutionTimelineReportOptions) bool {
	if event.At.Before(windowStart) || event.At.After(windowEnd) {
		return false
	}
	if filter := strings.TrimSpace(opts.TenantID); filter != "" && strings.TrimSpace(event.TenantID) != filter {
		return false
	}
	if filter := strings.TrimSpace(opts.PlaybookID); filter != "" && strings.TrimSpace(event.PlaybookID) != filter {
		return false
	}
	if filter := strings.TrimSpace(opts.EvaluationRunID); filter != "" && strings.TrimSpace(event.EvaluationRunID) != filter {
		return false
	}
	if filter := strings.TrimSpace(opts.TargetKind); filter != "" {
		for _, targetKind := range event.TargetKinds {
			if strings.TrimSpace(targetKind) == filter {
				return true
			}
		}
		return false
	}
	return true
}

func unifiedExecutionTimelineKindRank(kind string) int {
	switch kind {
	case "communication_thread":
		return 0
	case string(NodeKindDecision):
		return 1
	case string(NodeKindAction):
		return 2
	case string(NodeKindClaim):
		return 3
	case string(NodeKindEvidence):
		return 4
	case string(NodeKindOutcome):
		return 5
	default:
		return 100
	}
}

func unifiedExecutionTimelineSummary(events []UnifiedExecutionTimelineEvent) UnifiedExecutionTimelineSummary {
	summary := UnifiedExecutionTimelineSummary{Events: len(events)}
	evaluationRuns := make(map[string]struct{})
	playbookRuns := make(map[string]struct{})
	for _, event := range events {
		if event.EvaluationRunID != "" {
			evaluationRuns[event.EvaluationRunID] = struct{}{}
		}
		if event.PlaybookRunID != "" {
			playbookRuns[event.PlaybookRunID] = struct{}{}
		}
		switch event.Kind {
		case "communication_thread":
			summary.Threads++
		case string(NodeKindDecision):
			summary.Decisions++
		case string(NodeKindAction):
			summary.Actions++
		case string(NodeKindOutcome):
			summary.Outcomes++
		case string(NodeKindClaim):
			summary.Claims++
		case string(NodeKindEvidence):
			summary.Evidence++
		}
	}
	summary.EvaluationRuns = len(evaluationRuns)
	summary.PlaybookRuns = len(playbookRuns)
	return summary
}

func sortedTimelineStrings(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	return out
}

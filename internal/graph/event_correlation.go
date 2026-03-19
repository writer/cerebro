package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	eventCorrelationSourceSystem = "event_correlation"

	eventCorrelationDefaultLimit          = 25
	eventCorrelationMaxLimit              = 200
	eventCorrelationNeighborhoodDepth     = 3
	eventCorrelationCurrentWindow         = 7 * 24 * time.Hour
	eventCorrelationBaselineWindow        = 28 * 24 * time.Hour
	eventCorrelationIncidentHistoryWindow = 90 * 24 * time.Hour
)

// EventCorrelationPatternDefinition describes one built-in temporal correlation rule.
type EventCorrelationPatternDefinition struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Description       string     `json:"description"`
	CauseKind         NodeKind   `json:"cause_kind"`
	EffectKind        NodeKind   `json:"effect_kind"`
	EdgeKind          EdgeKind   `json:"edge_kind"`
	MaxGap            string     `json:"max_gap"`
	MaxGapSeconds     int64      `json:"max_gap_seconds"`
	SharedTargetKinds []NodeKind `json:"shared_target_kinds,omitempty"`
	Severity          string     `json:"severity,omitempty"`
}

// EventCorrelationPatternCatalog is a timestamped view of the built-in correlation patterns.
type EventCorrelationPatternCatalog struct {
	GeneratedAt time.Time                           `json:"generated_at"`
	Patterns    []EventCorrelationPatternDefinition `json:"patterns"`
}

// EventCorrelationQuery filters materialized event-correlation edges.
type EventCorrelationQuery struct {
	EventID          string    `json:"event_id,omitempty"`
	EntityID         string    `json:"entity_id,omitempty"`
	PatternID        string    `json:"pattern_id,omitempty"`
	Limit            int       `json:"limit,omitempty"`
	Since            time.Time `json:"since,omitempty"`
	Until            time.Time `json:"until,omitempty"`
	IncludeAnomalies bool      `json:"include_anomalies,omitempty"`
}

// EventCorrelationSummary captures high-level counts for one correlation query.
type EventCorrelationSummary struct {
	PatternCount     int `json:"pattern_count"`
	CorrelationCount int `json:"correlation_count"`
	AnomalyCount     int `json:"anomaly_count,omitempty"`
}

// EventReference is the API/tool shape for one event node.
type EventReference struct {
	ID           string    `json:"id"`
	Kind         NodeKind  `json:"kind"`
	Name         string    `json:"name,omitempty"`
	Provider     string    `json:"provider,omitempty"`
	Account      string    `json:"account,omitempty"`
	ObservedAt   time.Time `json:"observed_at,omitempty"`
	ValidFrom    time.Time `json:"valid_from,omitempty"`
	ServiceID    string    `json:"service_id,omitempty"`
	Status       string    `json:"status,omitempty"`
	SourceSystem string    `json:"source_system,omitempty"`
}

// EventCorrelationRecord captures one derived causal edge between two events.
type EventCorrelationRecord struct {
	ID              string         `json:"id"`
	PatternID       string         `json:"pattern_id"`
	PatternName     string         `json:"pattern_name"`
	Description     string         `json:"description,omitempty"`
	EdgeKind        EdgeKind       `json:"edge_kind"`
	Cause           EventReference `json:"cause"`
	Effect          EventReference `json:"effect"`
	SharedTargetIDs []string       `json:"shared_target_ids,omitempty"`
	GapSeconds      int64          `json:"gap_seconds"`
	WindowSeconds   int64          `json:"window_seconds"`
	Score           float64        `json:"score"`
}

// EventCorrelationResult is the query/tool response for event correlation lookup.
type EventCorrelationResult struct {
	GeneratedAt  time.Time                `json:"generated_at"`
	Query        EventCorrelationQuery    `json:"query"`
	Summary      EventCorrelationSummary  `json:"summary"`
	Correlations []EventCorrelationRecord `json:"correlations,omitempty"`
	Anomalies    []EventAnomaly           `json:"anomalies,omitempty"`
}

// EventAnomaly describes an event-frequency deviation for one event/context scope.
type EventAnomaly struct {
	ID                  string    `json:"id"`
	Classification      string    `json:"classification"`
	Severity            string    `json:"severity"`
	EventKind           NodeKind  `json:"event_kind"`
	EntityID            string    `json:"entity_id,omitempty"`
	SourceSystem        string    `json:"source_system,omitempty"`
	Status              string    `json:"status,omitempty"`
	Summary             string    `json:"summary"`
	CurrentWindowStart  time.Time `json:"current_window_start"`
	CurrentWindowEnd    time.Time `json:"current_window_end"`
	BaselineWindowStart time.Time `json:"baseline_window_start"`
	BaselineWindowEnd   time.Time `json:"baseline_window_end"`
	CurrentCount        int       `json:"current_count"`
	BaselineCount       int       `json:"baseline_count"`
	BaselineAverage     float64   `json:"baseline_average"`
	DeviationRatio      float64   `json:"deviation_ratio,omitempty"`
}

// EventCorrelationPatternMatchSummary captures per-pattern materialization counts.
type EventCorrelationPatternMatchSummary struct {
	PatternID    string `json:"pattern_id"`
	Correlations int    `json:"correlations"`
}

// EventCorrelationMaterializationSummary captures one full rematerialization pass.
type EventCorrelationMaterializationSummary struct {
	GeneratedAt         time.Time                             `json:"generated_at"`
	PatternsEvaluated   int                                   `json:"patterns_evaluated"`
	CorrelationsRemoved int                                   `json:"correlations_removed"`
	CorrelationsCreated int                                   `json:"correlations_created"`
	MatchesByPattern    []EventCorrelationPatternMatchSummary `json:"matches_by_pattern,omitempty"`
}

type eventCorrelationRule struct {
	definition          EventCorrelationPatternDefinition
	maxGap              time.Duration
	causeAllowedStatus  []string
	effectAllowedStatus []string
}

type eventCorrelationCandidate struct {
	node         *Node
	observedAt   time.Time
	validFrom    time.Time
	status       string
	sourceSystem string
	contextIDs   []string
}

type eventAnomalyWindow struct {
	current  int
	baseline int
	history  int
}

var builtInEventCorrelationRules = []eventCorrelationRule{
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "pr_deploy_chain",
			Name:              "PR Merge Triggers Deployment",
			Description:       "Merged pull requests followed by one deployment_run on the same service within 30 minutes.",
			CauseKind:         NodeKindPullRequest,
			EffectKind:        NodeKindDeploymentRun,
			EdgeKind:          EdgeKindTriggeredBy,
			MaxGap:            (30 * time.Minute).String(),
			MaxGapSeconds:     int64((30 * time.Minute).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "medium",
		},
		maxGap:             30 * time.Minute,
		causeAllowedStatus: []string{"merged"},
	},
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "deploy_incident_chain",
			Name:              "Deployment Precedes Incident",
			Description:       "One deployment_run followed by one incident on the same service within 1 hour.",
			CauseKind:         NodeKindDeploymentRun,
			EffectKind:        NodeKindIncident,
			EdgeKind:          EdgeKindCausedBy,
			MaxGap:            time.Hour.String(),
			MaxGapSeconds:     int64(time.Hour.Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "high",
		},
		maxGap:             time.Hour,
		causeAllowedStatus: []string{"completed", "success", "successful", "succeeded", "failed", "failure", "error", "cancelled"},
	},
}

// IsEventCorrelationNodeKind returns true when a node kind participates in built-in event-correlation rules.
func IsEventCorrelationNodeKind(kind NodeKind) bool {
	switch kind {
	case NodeKindPullRequest, NodeKindDeploymentRun, NodeKindIncident:
		return true
	default:
		return false
	}
}

// EventCorrelationPatternCatalogSnapshot returns a timestamped view of built-in event-correlation patterns.
func EventCorrelationPatternCatalogSnapshot(now time.Time) EventCorrelationPatternCatalog {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return EventCorrelationPatternCatalog{
		GeneratedAt: now.UTC(),
		Patterns:    eventCorrelationPatternDefinitions(),
	}
}

// MaterializeEventCorrelations rebuilds deterministic cross-event causal edges.
func MaterializeEventCorrelations(g *Graph, now time.Time) EventCorrelationMaterializationSummary {
	summary := EventCorrelationMaterializationSummary{
		GeneratedAt: now.UTC(),
	}
	if g == nil {
		return summary
	}
	if now.IsZero() {
		now = time.Now().UTC()
		summary.GeneratedAt = now
	}

	summary.CorrelationsRemoved = purgeDerivedEventCorrelationEdges(g)
	candidatesByKind := collectEventCorrelationCandidates(g)
	summary.PatternsEvaluated = len(builtInEventCorrelationRules)
	summary.MatchesByPattern = make([]EventCorrelationPatternMatchSummary, 0, len(builtInEventCorrelationRules))

	for _, rule := range builtInEventCorrelationRules {
		matches := materializeEventCorrelationRule(g, rule, candidatesByKind, now)
		summary.CorrelationsCreated += matches
		summary.MatchesByPattern = append(summary.MatchesByPattern, EventCorrelationPatternMatchSummary{
			PatternID:    rule.definition.ID,
			Correlations: matches,
		})
	}

	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		meta.BuiltAt = now
	}
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)

	sort.Slice(summary.MatchesByPattern, func(i, j int) bool {
		return summary.MatchesByPattern[i].PatternID < summary.MatchesByPattern[j].PatternID
	})
	return summary
}

// QueryEventCorrelations lists materialized causal edges and scoped anomaly summaries.
func QueryEventCorrelations(g *Graph, now time.Time, query EventCorrelationQuery) EventCorrelationResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	query.EventID = strings.TrimSpace(query.EventID)
	query.EntityID = strings.TrimSpace(query.EntityID)
	query.PatternID = strings.TrimSpace(query.PatternID)
	query.Limit = clampEventCorrelationLimit(query.Limit)

	result := EventCorrelationResult{
		GeneratedAt: now.UTC(),
		Query:       query,
	}
	if g == nil {
		return result
	}

	patterns := eventCorrelationPatternDefinitions()
	filteredPatterns := make([]EventCorrelationPatternDefinition, 0, len(patterns))
	for _, pattern := range patterns {
		if query.PatternID != "" && pattern.ID != query.PatternID {
			continue
		}
		filteredPatterns = append(filteredPatterns, pattern)
	}
	result.Summary.PatternCount = len(filteredPatterns)

	filtered := collectEventCorrelationRecords(g, filteredPatterns)
	allowedEventIDs, allowedContextIDs := correlationNeighborhoodFilters(g, query, filteredPatterns)
	if (query.EventID != "" || query.EntityID != "") && len(allowedEventIDs) == 0 && len(allowedContextIDs) == 0 {
		return result
	}
	filtered = filterEventCorrelationRecords(filtered, query, allowedEventIDs, allowedContextIDs)
	sort.Slice(filtered, func(i, j int) bool {
		if !filtered[i].Effect.ObservedAt.Equal(filtered[j].Effect.ObservedAt) {
			return filtered[i].Effect.ObservedAt.After(filtered[j].Effect.ObservedAt)
		}
		if filtered[i].GapSeconds != filtered[j].GapSeconds {
			return filtered[i].GapSeconds < filtered[j].GapSeconds
		}
		return filtered[i].ID < filtered[j].ID
	})
	if len(filtered) > query.Limit {
		filtered = filtered[:query.Limit]
	}
	result.Correlations = filtered
	result.Summary.CorrelationCount = len(filtered)

	if query.IncludeAnomalies && len(allowedContextIDs) > 0 {
		anomalies := detectEventAnomalies(g, now, allowedContextIDs, filteredPatterns)
		if len(anomalies) > query.Limit {
			anomalies = anomalies[:query.Limit]
		}
		result.Anomalies = anomalies
		result.Summary.AnomalyCount = len(anomalies)
	}
	return result
}

func eventCorrelationPatternDefinitions() []EventCorrelationPatternDefinition {
	patterns := make([]EventCorrelationPatternDefinition, 0, len(builtInEventCorrelationRules))
	for _, rule := range builtInEventCorrelationRules {
		patterns = append(patterns, rule.definition)
	}
	return patterns
}

func purgeDerivedEventCorrelationEdges(g *Graph) int {
	if g == nil {
		return 0
	}
	removed := 0
	for source, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if !isMaterializedEventCorrelationEdge(edge) {
				continue
			}
			if g.RemoveEdge(source, edge.Target, edge.Kind) {
				removed++
			}
		}
	}
	if removed > 0 {
		g.CompactDeletedEdges()
	}
	return removed
}

func materializeEventCorrelationRule(g *Graph, rule eventCorrelationRule, candidatesByKind map[NodeKind][]eventCorrelationCandidate, now time.Time) int {
	causes := candidatesByKind[rule.definition.CauseKind]
	effects := candidatesByKind[rule.definition.EffectKind]
	if len(causes) == 0 || len(effects) == 0 {
		return 0
	}

	causesByContext := make(map[string][]eventCorrelationCandidate)
	for _, cause := range causes {
		if !eventCorrelationCandidateAllowed(cause, rule.causeAllowedStatus) {
			continue
		}
		cause.contextIDs = eventCorrelationContextIDsForKinds(g, cause.node, rule.definition.SharedTargetKinds)
		if len(cause.contextIDs) == 0 {
			continue
		}
		for _, contextID := range cause.contextIDs {
			causesByContext[contextID] = append(causesByContext[contextID], cause)
		}
	}
	for contextID := range causesByContext {
		sort.Slice(causesByContext[contextID], func(i, j int) bool {
			if !causesByContext[contextID][i].observedAt.Equal(causesByContext[contextID][j].observedAt) {
				return causesByContext[contextID][i].observedAt.Before(causesByContext[contextID][j].observedAt)
			}
			return causesByContext[contextID][i].node.ID < causesByContext[contextID][j].node.ID
		})
	}

	sort.Slice(effects, func(i, j int) bool {
		if !effects[i].observedAt.Equal(effects[j].observedAt) {
			return effects[i].observedAt.Before(effects[j].observedAt)
		}
		return effects[i].node.ID < effects[j].node.ID
	})

	created := 0
	for _, effect := range effects {
		if !eventCorrelationCandidateAllowed(effect, rule.effectAllowedStatus) {
			continue
		}
		effect.contextIDs = eventCorrelationContextIDsForKinds(g, effect.node, rule.definition.SharedTargetKinds)
		if len(effect.contextIDs) == 0 {
			continue
		}
		cause, sharedTargetIDs, gap := selectBestEventCorrelationCause(effect, causesByContext, rule.maxGap)
		if cause == nil || cause.node.ID == effect.node.ID {
			continue
		}
		edge := buildEventCorrelationEdge(rule.definition, *cause, effect, sharedTargetIDs, gap, now)
		g.AddEdge(edge)
		created++
	}
	return created
}

func selectBestEventCorrelationCause(effect eventCorrelationCandidate, causesByContext map[string][]eventCorrelationCandidate, maxGap time.Duration) (*eventCorrelationCandidate, []string, time.Duration) {
	var (
		bestCause      *eventCorrelationCandidate
		bestShared     []string
		bestGap        time.Duration
		bestObservedAt time.Time
		seenCauseByID  = make(map[string]struct{})
	)
	for _, contextID := range effect.contextIDs {
		causes := causesByContext[contextID]
		for i := len(causes) - 1; i >= 0; i-- {
			cause := causes[i]
			if effect.observedAt.Before(cause.observedAt) {
				continue
			}
			gap := effect.observedAt.Sub(cause.observedAt)
			if gap > maxGap {
				break
			}
			if _, seen := seenCauseByID[cause.node.ID]; seen {
				continue
			}
			seenCauseByID[cause.node.ID] = struct{}{}
			shared := intersectSortedStrings(effect.contextIDs, cause.contextIDs)
			if len(shared) == 0 {
				continue
			}
			if bestCause == nil ||
				gap < bestGap ||
				(gap == bestGap && cause.observedAt.After(bestObservedAt)) ||
				(gap == bestGap && cause.observedAt.Equal(bestObservedAt) && cause.node.ID < bestCause.node.ID) {
				copyCause := cause
				bestCause = &copyCause
				bestShared = shared
				bestGap = gap
				bestObservedAt = cause.observedAt
			}
		}
	}
	return bestCause, bestShared, bestGap
}

func collectEventCorrelationCandidates(g *Graph) map[NodeKind][]eventCorrelationCandidate {
	candidates := make(map[NodeKind][]eventCorrelationCandidate)
	if g == nil {
		return candidates
	}
	for _, node := range g.GetAllNodes() {
		if node == nil || !IsEventCorrelationNodeKind(node.Kind) {
			continue
		}
		observedAt, ok := graphObservedAt(node)
		if !ok || observedAt.IsZero() {
			continue
		}
		validFrom := observedAt
		if ts, ok := temporalPropertyTime(node.Properties, "valid_from"); ok {
			validFrom = ts
		}
		candidates[node.Kind] = append(candidates[node.Kind], eventCorrelationCandidate{
			node:         node,
			observedAt:   observedAt.UTC(),
			validFrom:    validFrom.UTC(),
			status:       normalizeEventStatus(node),
			sourceSystem: strings.TrimSpace(stringProperty(node.Properties, "source_system")),
			contextIDs:   eventCorrelationContextIDs(g, node),
		})
	}
	return candidates
}

func collectEventCorrelationRecords(g *Graph, patterns []EventCorrelationPatternDefinition) []EventCorrelationRecord {
	if g == nil {
		return nil
	}
	patternByID := make(map[string]EventCorrelationPatternDefinition, len(patterns))
	for _, pattern := range patterns {
		patternByID[pattern.ID] = pattern
	}

	records := make([]EventCorrelationRecord, 0)
	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if !isMaterializedEventCorrelationEdge(edge) {
				continue
			}
			patternID := strings.TrimSpace(stringProperty(edge.Properties, "pattern_id"))
			pattern, ok := patternByID[patternID]
			if !ok {
				continue
			}
			effectNode, ok := g.GetNode(edge.Source)
			if !ok || effectNode == nil {
				continue
			}
			causeNode, ok := g.GetNode(edge.Target)
			if !ok || causeNode == nil {
				continue
			}
			record := EventCorrelationRecord{
				ID:              edge.ID,
				PatternID:       patternID,
				PatternName:     pattern.Name,
				Description:     pattern.Description,
				EdgeKind:        edge.Kind,
				Cause:           eventReferenceFromNode(causeNode),
				Effect:          eventReferenceFromNode(effectNode),
				SharedTargetIDs: uniqueSortedStrings(anySliceStrings(edge.Properties["shared_target_ids"])),
				GapSeconds:      int64(readFloat64Property(edge.Properties, "gap_seconds")),
				WindowSeconds:   int64(readFloat64Property(edge.Properties, "window_seconds")),
				Score:           readFloat64Property(edge.Properties, "score"),
			}
			records = append(records, record)
		}
	}
	return records
}

func filterEventCorrelationRecords(records []EventCorrelationRecord, query EventCorrelationQuery, allowedEventIDs map[string]struct{}, allowedContextIDs map[string]struct{}) []EventCorrelationRecord {
	filtered := make([]EventCorrelationRecord, 0, len(records))
	for _, record := range records {
		if query.PatternID != "" && record.PatternID != query.PatternID {
			continue
		}
		if !query.Since.IsZero() && record.Effect.ObservedAt.Before(query.Since.UTC()) {
			continue
		}
		if !query.Until.IsZero() && record.Effect.ObservedAt.After(query.Until.UTC()) {
			continue
		}
		if len(allowedEventIDs) > 0 {
			if _, ok := allowedEventIDs[record.Cause.ID]; !ok {
				if _, ok := allowedEventIDs[record.Effect.ID]; !ok {
					continue
				}
			}
		}
		if len(allowedContextIDs) > 0 && query.EntityID != "" {
			matched := false
			for _, targetID := range record.SharedTargetIDs {
				if _, ok := allowedContextIDs[targetID]; ok {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func correlationNeighborhoodFilters(g *Graph, query EventCorrelationQuery, patterns []EventCorrelationPatternDefinition) (map[string]struct{}, map[string]struct{}) {
	eventIDs := make(map[string]struct{})
	contextIDs := make(map[string]struct{})
	if g == nil {
		return eventIDs, contextIDs
	}
	allowedTargetKinds := eventCorrelationSharedTargetKinds(patterns)

	if query.EventID != "" {
		for id := range expandCorrelationNeighborhood(g, []string{query.EventID}) {
			eventIDs[id] = struct{}{}
		}
		if node, ok := g.GetNode(query.EventID); ok && node != nil {
			for _, contextID := range eventCorrelationContextIDsForKinds(g, node, allowedTargetKinds) {
				contextIDs[contextID] = struct{}{}
			}
		}
		return eventIDs, contextIDs
	}

	if query.EntityID != "" {
		seedEvents := make([]string, 0)
		entityID := strings.TrimSpace(query.EntityID)
		for _, node := range g.GetAllNodes() {
			if node == nil || !IsEventCorrelationNodeKind(node.Kind) {
				continue
			}
			contextIDsForNode := eventCorrelationContextIDsForKinds(g, node, allowedTargetKinds)
			for _, contextID := range contextIDsForNode {
				if contextID == entityID {
					seedEvents = append(seedEvents, node.ID)
					contextIDs[contextID] = struct{}{}
					break
				}
			}
		}
		for id := range expandCorrelationNeighborhood(g, seedEvents) {
			eventIDs[id] = struct{}{}
		}
	}
	return eventIDs, contextIDs
}

func expandCorrelationNeighborhood(g *Graph, seeds []string) map[string]struct{} {
	visited := make(map[string]struct{}, len(seeds))
	frontier := make([]string, 0, len(seeds))
	for _, seed := range seeds {
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}
		if _, ok := visited[seed]; ok {
			continue
		}
		visited[seed] = struct{}{}
		frontier = append(frontier, seed)
	}
	for depth := 0; depth < eventCorrelationNeighborhoodDepth && len(frontier) > 0; depth++ {
		next := make([]string, 0)
		for _, nodeID := range frontier {
			for _, edge := range append(g.GetOutEdges(nodeID), g.GetInEdges(nodeID)...) {
				if !isMaterializedEventCorrelationEdge(edge) {
					continue
				}
				other := edge.Source
				if other == nodeID {
					other = edge.Target
				}
				if other == "" {
					continue
				}
				if _, ok := visited[other]; ok {
					continue
				}
				visited[other] = struct{}{}
				next = append(next, other)
			}
		}
		frontier = next
	}
	return visited
}

func detectEventAnomalies(g *Graph, now time.Time, allowedContextIDs map[string]struct{}, patterns []EventCorrelationPatternDefinition) []EventAnomaly {
	if g == nil || len(patterns) == 0 {
		return nil
	}
	allowedEventKinds := eventCorrelationPatternEventKinds(patterns)
	allowedTargetKinds := eventCorrelationSharedTargetKinds(patterns)
	currentStart := now.Add(-eventCorrelationCurrentWindow)
	baselineStart := currentStart.Add(-eventCorrelationBaselineWindow)
	historyStart := now.Add(-eventCorrelationIncidentHistoryWindow)

	windows := make(map[string]*eventAnomalyWindow)
	anomalyMeta := make(map[string]EventAnomaly)
	for _, node := range g.GetAllNodes() {
		if node == nil || !IsEventCorrelationNodeKind(node.Kind) {
			continue
		}
		if len(allowedEventKinds) > 0 {
			if _, ok := allowedEventKinds[node.Kind]; !ok {
				continue
			}
		}
		observedAt, ok := graphObservedAt(node)
		if !ok || observedAt.IsZero() {
			continue
		}
		status := normalizeEventStatus(node)
		contextIDs := eventCorrelationContextIDsForKinds(g, node, allowedTargetKinds)
		if len(contextIDs) == 0 {
			contextIDs = []string{strings.TrimSpace(stringProperty(node.Properties, "source_system"))}
		}
		for _, contextID := range contextIDs {
			if len(allowedContextIDs) > 0 {
				if _, ok := allowedContextIDs[contextID]; !ok {
					continue
				}
			}

			keys := []string{eventAnomalyKey(node.Kind, contextID, "")}
			if node.Kind == NodeKindDeploymentRun && isFailureStatus(status) {
				keys = append(keys, eventAnomalyKey(node.Kind, contextID, "failed"))
			}
			for _, key := range keys {
				window := windows[key]
				if window == nil {
					window = &eventAnomalyWindow{}
					windows[key] = window
					anomalyMeta[key] = EventAnomaly{
						ID:                  "event_anomaly:" + strings.ReplaceAll(key, "|", ":"),
						EventKind:           node.Kind,
						EntityID:            contextID,
						SourceSystem:        strings.TrimSpace(stringProperty(node.Properties, "source_system")),
						Status:              strings.TrimSpace(status),
						CurrentWindowStart:  currentStart.UTC(),
						CurrentWindowEnd:    now.UTC(),
						BaselineWindowStart: baselineStart.UTC(),
						BaselineWindowEnd:   currentStart.UTC(),
					}
				}
				switch {
				case !observedAt.Before(currentStart):
					window.current++
				case !observedAt.Before(baselineStart) && observedAt.Before(currentStart):
					window.baseline++
				}
				if !observedAt.Before(historyStart) && observedAt.Before(currentStart) {
					window.history++
				}
			}
		}
	}

	out := make([]EventAnomaly, 0)
	for key, window := range windows {
		if window.current == 0 {
			continue
		}
		meta := anomalyMeta[key]
		baselineAverage := float64(window.baseline) / float64(eventCorrelationBaselineWindow/eventCorrelationCurrentWindow)
		if strings.HasSuffix(key, "|failed") {
			if baselineAverage >= 1 && float64(window.current) >= baselineAverage*3 {
				meta.Classification = "failure_spike"
				meta.Severity = "high"
				meta.CurrentCount = window.current
				meta.BaselineCount = window.baseline
				meta.BaselineAverage = baselineAverage
				meta.DeviationRatio = float64(window.current) / baselineAverage
				meta.Summary = fmt.Sprintf("%d failed deployments on %s in the last 7d vs %.1f baseline.", window.current, meta.EntityID, baselineAverage)
				out = append(out, meta)
			}
			continue
		}
		if meta.EventKind == NodeKindIncident && window.history == 0 {
			meta.Classification = "first_in_90d"
			meta.Severity = "medium"
			meta.CurrentCount = window.current
			meta.BaselineCount = window.baseline
			meta.BaselineAverage = baselineAverage
			meta.Summary = fmt.Sprintf("First incident activity on %s in the last 90d.", meta.EntityID)
			out = append(out, meta)
			continue
		}
		if baselineAverage >= 1 && float64(window.current) >= baselineAverage*3 {
			meta.Classification = "volume_spike"
			meta.Severity = "medium"
			if meta.EventKind == NodeKindIncident {
				meta.Severity = "high"
			}
			meta.CurrentCount = window.current
			meta.BaselineCount = window.baseline
			meta.BaselineAverage = baselineAverage
			meta.DeviationRatio = float64(window.current) / baselineAverage
			meta.Summary = fmt.Sprintf("%s events on %s are %.1fx baseline in the last 7d.", meta.EventKind, meta.EntityID, meta.DeviationRatio)
			out = append(out, meta)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			if out[i].DeviationRatio == out[j].DeviationRatio {
				return out[i].ID < out[j].ID
			}
			return out[i].DeviationRatio > out[j].DeviationRatio
		}
		return eventAnomalySeverityRank(out[i].Severity) < eventAnomalySeverityRank(out[j].Severity)
	})
	return out
}

func eventAnomalySeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func buildEventCorrelationEdge(pattern EventCorrelationPatternDefinition, cause, effect eventCorrelationCandidate, sharedTargetIDs []string, gap time.Duration, now time.Time) *Edge {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	score := 1.0
	if pattern.MaxGapSeconds > 0 {
		score = 1.0 - (float64(gap) / float64(time.Duration(pattern.MaxGapSeconds)*time.Second))
		if score < 0 {
			score = 0
		}
	}
	properties := map[string]any{
		"source_system":     eventCorrelationSourceSystem,
		"source_event_id":   pattern.ID + ":" + effect.node.ID,
		"observed_at":       effect.observedAt.UTC().Format(time.RFC3339),
		"valid_from":        effect.validFrom.UTC().Format(time.RFC3339),
		"recorded_at":       now.UTC().Format(time.RFC3339),
		"transaction_from":  now.UTC().Format(time.RFC3339),
		"pattern_id":        pattern.ID,
		"pattern_name":      pattern.Name,
		"shared_target_ids": sharedTargetIDs,
		"gap_seconds":       int64(gap.Seconds()),
		"window_seconds":    pattern.MaxGapSeconds,
		"score":             score,
	}
	return &Edge{
		ID:         eventCorrelationEdgeID(pattern.ID, effect.node.ID, cause.node.ID),
		Source:     effect.node.ID,
		Target:     cause.node.ID,
		Kind:       pattern.EdgeKind,
		Effect:     EdgeEffectAllow,
		Properties: properties,
		CreatedAt:  now.UTC(),
	}
}

func eventCorrelationEdgeID(patternID, effectID, causeID string) string {
	return "event_correlation:" + strings.TrimSpace(patternID) + ":" + strings.TrimSpace(effectID) + ":" + strings.TrimSpace(causeID)
}

func isMaterializedEventCorrelationEdge(edge *Edge) bool {
	if edge == nil {
		return false
	}
	if edge.Kind != EdgeKindTriggeredBy && edge.Kind != EdgeKindCausedBy {
		return false
	}
	if strings.TrimSpace(stringProperty(edge.Properties, "source_system")) == eventCorrelationSourceSystem {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(edge.ID), "event_correlation:")
}

func eventCorrelationCandidateAllowed(candidate eventCorrelationCandidate, allowedStatuses []string) bool {
	if len(allowedStatuses) == 0 {
		return true
	}
	for _, status := range allowedStatuses {
		if candidate.status == strings.ToLower(strings.TrimSpace(status)) {
			return true
		}
	}
	return false
}

func eventCorrelationPatternEventKinds(patterns []EventCorrelationPatternDefinition) map[NodeKind]struct{} {
	if len(patterns) == 0 {
		return nil
	}
	kinds := make(map[NodeKind]struct{}, len(patterns)*2)
	for _, pattern := range patterns {
		if pattern.CauseKind != "" {
			kinds[pattern.CauseKind] = struct{}{}
		}
		if pattern.EffectKind != "" {
			kinds[pattern.EffectKind] = struct{}{}
		}
	}
	return kinds
}

func eventCorrelationSharedTargetKinds(patterns []EventCorrelationPatternDefinition) []NodeKind {
	if len(patterns) == 0 {
		return nil
	}
	seen := make(map[NodeKind]struct{})
	kinds := make([]NodeKind, 0)
	for _, pattern := range patterns {
		for _, kind := range pattern.SharedTargetKinds {
			if _, ok := seen[kind]; ok {
				continue
			}
			seen[kind] = struct{}{}
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

func eventCorrelationContextIDs(g *Graph, node *Node) []string {
	return eventCorrelationContextIDsForKinds(g, node, nil)
}

func eventCorrelationContextIDsForKinds(g *Graph, node *Node, allowedKinds []NodeKind) []string {
	if node == nil || g == nil {
		return nil
	}
	allowed := make(map[NodeKind]struct{}, len(allowedKinds))
	for _, kind := range allowedKinds {
		allowed[kind] = struct{}{}
	}
	kindAllowed := func(kind NodeKind) bool {
		if len(allowed) == 0 {
			return true
		}
		_, ok := allowed[kind]
		return ok
	}
	set := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.Kind != EdgeKindTargets {
			continue
		}
		targetID := strings.TrimSpace(edge.Target)
		if targetID == "" {
			continue
		}
		if len(allowed) > 0 {
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || !kindAllowed(target.Kind) {
				continue
			}
		}
		set[targetID] = struct{}{}
	}
	if serviceID := strings.TrimSpace(stringProperty(node.Properties, "service_id")); serviceID != "" {
		if !kindAllowed(NodeKindService) {
			return sortedStringSet(set)
		}
		if strings.Contains(serviceID, ":") {
			set[serviceID] = struct{}{}
		} else {
			set["service:"+serviceID] = struct{}{}
		}
	}
	return sortedStringSet(set)
}

func eventReferenceFromNode(node *Node) EventReference {
	if node == nil {
		return EventReference{}
	}
	ref := EventReference{
		ID:           node.ID,
		Kind:         node.Kind,
		Name:         node.Name,
		Provider:     node.Provider,
		Account:      node.Account,
		ServiceID:    strings.TrimSpace(stringProperty(node.Properties, "service_id")),
		Status:       normalizeEventStatus(node),
		SourceSystem: strings.TrimSpace(stringProperty(node.Properties, "source_system")),
	}
	if ts, ok := graphObservedAt(node); ok {
		ref.ObservedAt = ts
	}
	if ts, ok := temporalPropertyTime(node.Properties, "valid_from"); ok {
		ref.ValidFrom = ts
	}
	return ref
}

func normalizeEventStatus(node *Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case NodeKindPullRequest:
		return strings.ToLower(strings.TrimSpace(stringProperty(node.Properties, "state")))
	default:
		return strings.ToLower(strings.TrimSpace(stringProperty(node.Properties, "status")))
	}
}

func eventAnomalyKey(kind NodeKind, entityID, qualifier string) string {
	parts := []string{string(kind), strings.TrimSpace(entityID)}
	if qualifier != "" {
		parts = append(parts, strings.TrimSpace(qualifier))
	}
	return strings.Join(parts, "|")
}

func isFailureStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "failure", "error", "cancelled":
		return true
	default:
		return false
	}
}

func clampEventCorrelationLimit(limit int) int {
	if limit <= 0 {
		return eventCorrelationDefaultLimit
	}
	if limit > eventCorrelationMaxLimit {
		return eventCorrelationMaxLimit
	}
	return limit
}

func stringProperty(properties map[string]any, key string) string {
	if len(properties) == 0 {
		return ""
	}
	value, ok := properties[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", value)
	}
}

func readFloat64Property(properties map[string]any, key string) float64 {
	if len(properties) == 0 {
		return 0
	}
	value, ok := properties[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int8:
		return float64(typed)
	case int16:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case uint:
		return float64(typed)
	case uint8:
		return float64(typed)
	case uint16:
		return float64(typed)
	case uint32:
		return float64(typed)
	case uint64:
		return float64(typed)
	default:
		return 0
	}
}

func anySliceStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, strings.TrimSpace(fmt.Sprintf("%v", item)))
		}
		return out
	default:
		return nil
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func intersectSortedStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(left))
	for _, value := range left {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	shared := make([]string, 0)
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := set[value]; ok {
			shared = append(shared, value)
		}
	}
	return uniqueSortedStrings(shared)
}

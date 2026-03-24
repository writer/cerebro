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
	eventCorrelationDefaultChainDepth     = 4
	eventCorrelationMaxChainDepth         = 6
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
	ID               string         `json:"id"`
	PatternID        string         `json:"pattern_id"`
	PatternName      string         `json:"pattern_name"`
	Description      string         `json:"description,omitempty"`
	EdgeKind         EdgeKind       `json:"edge_kind"`
	Cause            EventReference `json:"cause"`
	Effect           EventReference `json:"effect"`
	SharedTargetIDs  []string       `json:"shared_target_ids,omitempty"`
	GapSeconds       int64          `json:"gap_seconds"`
	WindowSeconds    int64          `json:"window_seconds"`
	Score            float64        `json:"score"`
	Confidence       float64        `json:"confidence"`
	CandidateCount   int            `json:"candidate_count,omitempty"`
	ScopeOverlap     float64        `json:"scope_overlap,omitempty"`
	AmbiguityPenalty float64        `json:"ambiguity_penalty,omitempty"`
}

// EventCorrelationResult is the query/tool response for event correlation lookup.
type EventCorrelationResult struct {
	GeneratedAt  time.Time                `json:"generated_at"`
	Query        EventCorrelationQuery    `json:"query"`
	Summary      EventCorrelationSummary  `json:"summary"`
	Correlations []EventCorrelationRecord `json:"correlations,omitempty"`
	Anomalies    []EventAnomaly           `json:"anomalies,omitempty"`
}

// EventCorrelationChainQuery traverses materialized causal edges into explicit chains.
type EventCorrelationChainQuery struct {
	EventID   string    `json:"event_id,omitempty"`
	EntityID  string    `json:"entity_id,omitempty"`
	PatternID string    `json:"pattern_id,omitempty"`
	Direction string    `json:"direction,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	MaxDepth  int       `json:"max_depth,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

// EventCorrelationChainSummary captures top-line chain traversal metrics.
type EventCorrelationChainSummary struct {
	SeedCount    int `json:"seed_count"`
	ChainCount   int `json:"chain_count"`
	MaxDepth     int `json:"max_depth"`
	PatternCount int `json:"pattern_count"`
}

// EventCorrelationChain captures one traversed causal path.
type EventCorrelationChain struct {
	ID           string                   `json:"id"`
	Direction    string                   `json:"direction"`
	Depth        int                      `json:"depth"`
	Score        float64                  `json:"score"`
	Events       []EventReference         `json:"events"`
	Correlations []EventCorrelationRecord `json:"correlations"`
}

// EventCorrelationChainResult returns bounded causal paths rooted in one event or entity scope.
type EventCorrelationChainResult struct {
	GeneratedAt time.Time                    `json:"generated_at"`
	Query       EventCorrelationChainQuery   `json:"query"`
	Summary     EventCorrelationChainSummary `json:"summary"`
	Chains      []EventCorrelationChain      `json:"chains,omitempty"`
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

type eventCorrelationCauseSelection struct {
	cause            *eventCorrelationCandidate
	sharedTargetIDs  []string
	gap              time.Duration
	candidateCount   int
	scopeOverlap     float64
	ambiguityPenalty float64
	confidence       float64
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
			ID:                "pipeline_deploy_chain",
			Name:              "Pipeline Run Gates Deployment",
			Description:       "Completed pipeline_run activity followed by one deployment_run on the same service within 45 minutes.",
			CauseKind:         NodeKindPipelineRun,
			EffectKind:        NodeKindDeploymentRun,
			EdgeKind:          EdgeKindTriggeredBy,
			MaxGap:            (45 * time.Minute).String(),
			MaxGapSeconds:     int64((45 * time.Minute).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "medium",
		},
		maxGap:             45 * time.Minute,
		causeAllowedStatus: []string{"completed", "success", "successful", "succeeded"},
	},
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "check_deploy_chain",
			Name:              "Check Run Gates Deployment",
			Description:       "Completed check_run activity followed by one deployment_run on the same service within 30 minutes.",
			CauseKind:         NodeKindCheckRun,
			EffectKind:        NodeKindDeploymentRun,
			EdgeKind:          EdgeKindTriggeredBy,
			MaxGap:            (30 * time.Minute).String(),
			MaxGapSeconds:     int64((30 * time.Minute).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "medium",
		},
		maxGap:             30 * time.Minute,
		causeAllowedStatus: []string{"completed", "success", "successful", "succeeded", "passed", "neutral"},
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
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "incident_decision_chain",
			Name:              "Incident Drives Decision",
			Description:       "Incident activity followed by one decision on the same service within 6 hours.",
			CauseKind:         NodeKindIncident,
			EffectKind:        NodeKindDecision,
			EdgeKind:          EdgeKindTriggeredBy,
			MaxGap:            (6 * time.Hour).String(),
			MaxGapSeconds:     int64((6 * time.Hour).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "high",
		},
		maxGap: 6 * time.Hour,
	},
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "decision_action_chain",
			Name:              "Decision Triggers Action",
			Description:       "Decision activity followed by one action on the same service within 6 hours.",
			CauseKind:         NodeKindDecision,
			EffectKind:        NodeKindAction,
			EdgeKind:          EdgeKindTriggeredBy,
			MaxGap:            (6 * time.Hour).String(),
			MaxGapSeconds:     int64((6 * time.Hour).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "medium",
		},
		maxGap: 6 * time.Hour,
	},
	{
		definition: EventCorrelationPatternDefinition{
			ID:                "action_outcome_chain",
			Name:              "Action Produces Outcome",
			Description:       "Action activity followed by one outcome on the same service within 24 hours.",
			CauseKind:         NodeKindAction,
			EffectKind:        NodeKindOutcome,
			EdgeKind:          EdgeKindCausedBy,
			MaxGap:            (24 * time.Hour).String(),
			MaxGapSeconds:     int64((24 * time.Hour).Seconds()),
			SharedTargetKinds: []NodeKind{NodeKindService},
			Severity:          "medium",
		},
		maxGap: 24 * time.Hour,
	},
}

// IsEventCorrelationNodeKind returns true when a node kind participates in built-in event-correlation rules.
func IsEventCorrelationNodeKind(kind NodeKind) bool {
	switch kind {
	case NodeKindPullRequest, NodeKindCheckRun, NodeKindPipelineRun, NodeKindDeploymentRun, NodeKindIncident, NodeKindDecision, NodeKindAction, NodeKindOutcome:
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
	allowedEventIDs, allowedContextIDs := correlationNeighborhoodFilters(g, query)
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
		anomalies := detectEventAnomalies(g, now, allowedContextIDs)
		if len(anomalies) > query.Limit {
			anomalies = anomalies[:query.Limit]
		}
		result.Anomalies = anomalies
		result.Summary.AnomalyCount = len(anomalies)
	}
	return result
}

// QueryEventCorrelationChains traverses explicit causal paths over materialized event-correlation edges.
func QueryEventCorrelationChains(g *Graph, now time.Time, query EventCorrelationChainQuery) EventCorrelationChainResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	query.EventID = strings.TrimSpace(query.EventID)
	query.EntityID = strings.TrimSpace(query.EntityID)
	query.PatternID = strings.TrimSpace(query.PatternID)
	query.Direction = normalizeEventChainDirection(query.Direction)
	query.Limit = clampEventCorrelationLimit(query.Limit)
	query.MaxDepth = clampEventCorrelationChainDepth(query.MaxDepth)

	result := EventCorrelationChainResult{
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

	records := collectEventCorrelationRecords(g, filteredPatterns)
	filtered := make([]EventCorrelationRecord, 0, len(records))
	for _, record := range records {
		if !query.Since.IsZero() && record.Effect.ObservedAt.Before(query.Since.UTC()) {
			continue
		}
		if !query.Until.IsZero() && record.Effect.ObservedAt.After(query.Until.UTC()) {
			continue
		}
		filtered = append(filtered, record)
	}

	seeds := eventCorrelationSeedEventIDs(g, query.EventID, query.EntityID)
	result.Summary.SeedCount = len(seeds)
	if len(seeds) == 0 {
		return result
	}

	eventRefs := make(map[string]EventReference, len(filtered)*2)
	upstream := make(map[string][]EventCorrelationRecord)
	downstream := make(map[string][]EventCorrelationRecord)
	for _, record := range filtered {
		eventRefs[record.Cause.ID] = record.Cause
		eventRefs[record.Effect.ID] = record.Effect
		upstream[record.Effect.ID] = append(upstream[record.Effect.ID], record)
		downstream[record.Cause.ID] = append(downstream[record.Cause.ID], record)
	}
	for _, seedID := range seeds {
		if _, ok := eventRefs[seedID]; ok {
			continue
		}
		if node, ok := g.GetNode(seedID); ok && node != nil {
			eventRefs[seedID] = eventReferenceFromNode(node)
		}
	}
	for nodeID := range upstream {
		sortEventCorrelationRecordsForTraversal(upstream[nodeID])
	}
	for nodeID := range downstream {
		sortEventCorrelationRecordsForTraversal(downstream[nodeID])
	}

	var chains []EventCorrelationChain
	directions := []string{query.Direction}
	if query.Direction == "both" {
		directions = []string{"upstream", "downstream"}
	}
	for _, direction := range directions {
		for _, seedID := range seeds {
			visited := map[string]struct{}{seedID: {}}
			dfsEventCorrelationChains(seedID, direction, query.MaxDepth, visited, []string{seedID}, nil, eventRefs, upstream, downstream, &chains)
		}
	}
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		if chains[i].Depth != chains[j].Depth {
			return chains[i].Depth > chains[j].Depth
		}
		return chains[i].ID < chains[j].ID
	})
	if len(chains) > query.Limit {
		chains = chains[:query.Limit]
	}
	result.Chains = chains
	result.Summary.ChainCount = len(chains)
	for _, chain := range chains {
		if chain.Depth > result.Summary.MaxDepth {
			result.Summary.MaxDepth = chain.Depth
		}
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
		selection := selectBestEventCorrelationCause(effect, causesByContext, rule.maxGap)
		if selection.cause == nil || selection.cause.node.ID == effect.node.ID {
			continue
		}
		edge := buildEventCorrelationEdge(rule.definition, *selection.cause, effect, selection, now)
		g.AddEdge(edge)
		created++
	}
	return created
}

func selectBestEventCorrelationCause(effect eventCorrelationCandidate, causesByContext map[string][]eventCorrelationCandidate, maxGap time.Duration) eventCorrelationCauseSelection {
	var (
		bestSelection  eventCorrelationCauseSelection
		bestBaseScore  = -1.0
		bestObservedAt time.Time
		secondBestBase = -1.0
		seenCauseByID  = make(map[string]struct{})
		candidates     = make([]eventCorrelationCauseSelection, 0)
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
			proximityScore := eventCorrelationProximityScore(gap, maxGap)
			scopeOverlap := eventCorrelationScopeOverlap(effect.contextIDs, cause.contextIDs)
			baseScore := (proximityScore * 0.65) + (scopeOverlap * 0.35)
			copyCause := cause
			candidates = append(candidates, eventCorrelationCauseSelection{
				cause:           &copyCause,
				sharedTargetIDs: shared,
				gap:             gap,
				scopeOverlap:    scopeOverlap,
				confidence:      baseScore,
			})
			if baseScore > bestBaseScore ||
				(baseScore == bestBaseScore && gap < bestSelection.gap) ||
				(baseScore == bestBaseScore && gap == bestSelection.gap && cause.observedAt.After(bestObservedAt)) ||
				(baseScore == bestBaseScore && gap == bestSelection.gap && cause.observedAt.Equal(bestObservedAt) && cause.node.ID < bestSelection.cause.node.ID) {
				if bestBaseScore > secondBestBase {
					secondBestBase = bestBaseScore
				}
				bestBaseScore = baseScore
				bestSelection = candidates[len(candidates)-1]
				bestObservedAt = cause.observedAt
			} else if baseScore > secondBestBase {
				secondBestBase = baseScore
			}
		}
	}
	if bestSelection.cause == nil {
		return eventCorrelationCauseSelection{}
	}
	bestSelection.candidateCount = len(candidates)
	bestSelection.ambiguityPenalty = eventCorrelationAmbiguityPenalty(len(candidates), bestBaseScore, secondBestBase)
	bestSelection.confidence = clampUnit(bestSelection.confidence * (1 - bestSelection.ambiguityPenalty))
	return bestSelection
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
		if ts, ok := nodePropertyTime(node, "valid_from"); ok {
			validFrom = ts
		}
		candidates[node.Kind] = append(candidates[node.Kind], eventCorrelationCandidate{
			node:         node,
			observedAt:   observedAt.UTC(),
			validFrom:    validFrom.UTC(),
			status:       normalizeEventStatus(node),
			sourceSystem: nodePropertyString(node, "source_system"),
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
				ID:               edge.ID,
				PatternID:        patternID,
				PatternName:      pattern.Name,
				Description:      pattern.Description,
				EdgeKind:         edge.Kind,
				Cause:            eventReferenceFromNode(causeNode),
				Effect:           eventReferenceFromNode(effectNode),
				SharedTargetIDs:  uniqueSortedStrings(anySliceStrings(edge.Properties["shared_target_ids"])),
				GapSeconds:       int64(readFloat64Property(edge.Properties, "gap_seconds")),
				WindowSeconds:    int64(readFloat64Property(edge.Properties, "window_seconds")),
				Score:            readFloat64Property(edge.Properties, "score"),
				Confidence:       readFloat64Property(edge.Properties, "confidence"),
				CandidateCount:   int(readFloat64Property(edge.Properties, "candidate_count")),
				ScopeOverlap:     readFloat64Property(edge.Properties, "scope_overlap"),
				AmbiguityPenalty: readFloat64Property(edge.Properties, "ambiguity_penalty"),
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

func correlationNeighborhoodFilters(g *Graph, query EventCorrelationQuery) (map[string]struct{}, map[string]struct{}) {
	eventIDs := make(map[string]struct{})
	contextIDs := make(map[string]struct{})
	if g == nil {
		return eventIDs, contextIDs
	}

	if query.EventID != "" {
		for id := range expandCorrelationNeighborhood(g, []string{query.EventID}) {
			eventIDs[id] = struct{}{}
		}
		if node, ok := g.GetNode(query.EventID); ok && node != nil {
			for _, contextID := range eventCorrelationContextIDs(g, node) {
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
			contextIDsForNode := eventCorrelationContextIDs(g, node)
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

func detectEventAnomalies(g *Graph, now time.Time, allowedContextIDs map[string]struct{}) []EventAnomaly {
	if g == nil {
		return nil
	}
	currentStart := now.Add(-eventCorrelationCurrentWindow)
	baselineStart := currentStart.Add(-eventCorrelationBaselineWindow)
	historyStart := now.Add(-eventCorrelationIncidentHistoryWindow)

	windows := make(map[string]*eventAnomalyWindow)
	anomalyMeta := make(map[string]EventAnomaly)
	for _, node := range g.GetAllNodes() {
		if node == nil || !IsEventCorrelationNodeKind(node.Kind) {
			continue
		}
		observedAt, ok := graphObservedAt(node)
		if !ok || observedAt.IsZero() {
			continue
		}
		status := normalizeEventStatus(node)
		contextIDs := eventCorrelationContextIDs(g, node)
		if len(contextIDs) == 0 {
			contextIDs = []string{nodePropertyString(node, "source_system")}
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
						SourceSystem:        nodePropertyString(node, "source_system"),
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

func buildEventCorrelationEdge(pattern EventCorrelationPatternDefinition, cause, effect eventCorrelationCandidate, selection eventCorrelationCauseSelection, now time.Time) *Edge {
	if now.IsZero() {
		now = time.Now().UTC()
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
		"shared_target_ids": selection.sharedTargetIDs,
		"gap_seconds":       int64(selection.gap.Seconds()),
		"window_seconds":    pattern.MaxGapSeconds,
		"score":             selection.confidence,
		"confidence":        selection.confidence,
		"candidate_count":   selection.candidateCount,
		"scope_overlap":     selection.scopeOverlap,
		"ambiguity_penalty": selection.ambiguityPenalty,
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

func eventCorrelationContextIDs(g *Graph, node *Node) []string {
	if node == nil {
		return nil
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
		set[targetID] = struct{}{}
	}
	if serviceID := nodePropertyString(node, "service_id"); serviceID != "" {
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
		ServiceID:    nodePropertyString(node, "service_id"),
		Status:       normalizeEventStatus(node),
		SourceSystem: nodePropertyString(node, "source_system"),
	}
	if ts, ok := graphObservedAt(node); ok {
		ref.ObservedAt = ts
	}
	if ts, ok := nodePropertyTime(node, "valid_from"); ok {
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

func clampEventCorrelationChainDepth(depth int) int {
	if depth <= 0 {
		return eventCorrelationDefaultChainDepth
	}
	if depth > eventCorrelationMaxChainDepth {
		return eventCorrelationMaxChainDepth
	}
	return depth
}

func normalizeEventChainDirection(direction string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "upstream", "downstream", "both":
		return strings.ToLower(strings.TrimSpace(direction))
	default:
		return "both"
	}
}

func eventCorrelationProximityScore(gap, maxGap time.Duration) float64 {
	if maxGap <= 0 {
		return 1
	}
	score := 1.0 - (float64(gap) / float64(maxGap))
	return clampUnit(score)
}

func eventCorrelationScopeOverlap(left, right []string) float64 {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	leftSet := make(map[string]struct{}, len(left))
	for _, value := range left {
		leftSet[value] = struct{}{}
	}
	union := len(leftSet)
	shared := 0
	seenRight := make(map[string]struct{}, len(right))
	for _, value := range right {
		if _, ok := seenRight[value]; ok {
			continue
		}
		seenRight[value] = struct{}{}
		if _, ok := leftSet[value]; ok {
			shared++
			continue
		}
		union++
	}
	if union == 0 {
		return 0
	}
	return float64(shared) / float64(union)
}

func eventCorrelationAmbiguityPenalty(candidateCount int, bestBaseScore, secondBestBase float64) float64 {
	if candidateCount <= 1 {
		return 0
	}
	penalty := float64(candidateCount-1) * 0.08
	if bestBaseScore-secondBestBase <= 0.10 {
		penalty += 0.10
	}
	if penalty > 0.45 {
		penalty = 0.45
	}
	return penalty
}

func eventCorrelationSeedEventIDs(g *Graph, eventID, entityID string) []string {
	if g == nil {
		return nil
	}
	if eventID != "" {
		if _, ok := g.GetNode(eventID); ok {
			return []string{eventID}
		}
		return nil
	}
	seeds := make(map[string]struct{})
	entityID = strings.TrimSpace(entityID)
	for _, node := range g.GetAllNodes() {
		if node == nil || !IsEventCorrelationNodeKind(node.Kind) {
			continue
		}
		for _, contextID := range eventCorrelationContextIDs(g, node) {
			if contextID == entityID {
				seeds[node.ID] = struct{}{}
				break
			}
		}
	}
	return sortedStringSet(seeds)
}

func sortEventCorrelationRecordsForTraversal(records []EventCorrelationRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Confidence != records[j].Confidence {
			return records[i].Confidence > records[j].Confidence
		}
		if records[i].GapSeconds != records[j].GapSeconds {
			return records[i].GapSeconds < records[j].GapSeconds
		}
		return records[i].ID < records[j].ID
	})
}

func dfsEventCorrelationChains(currentID, direction string, remainingDepth int, visited map[string]struct{}, eventIDs []string, edges []EventCorrelationRecord, eventRefs map[string]EventReference, upstream, downstream map[string][]EventCorrelationRecord, out *[]EventCorrelationChain) {
	if remainingDepth <= 0 {
		emitEventCorrelationChain(direction, eventIDs, edges, eventRefs, out)
		return
	}
	nextEdges := eventCorrelationNextEdges(currentID, direction, upstream, downstream)
	advanced := false
	for _, edge := range nextEdges {
		nextID := edge.Cause.ID
		if direction == "downstream" {
			nextID = edge.Effect.ID
		}
		if nextID == currentID {
			continue
		}
		if _, ok := visited[nextID]; ok {
			continue
		}
		advanced = true
		visited[nextID] = struct{}{}
		dfsEventCorrelationChains(nextID, direction, remainingDepth-1, visited, append(append([]string(nil), eventIDs...), nextID), append(append([]EventCorrelationRecord(nil), edges...), edge), eventRefs, upstream, downstream, out)
		delete(visited, nextID)
	}
	if !advanced {
		emitEventCorrelationChain(direction, eventIDs, edges, eventRefs, out)
	}
}

func eventCorrelationNextEdges(currentID, direction string, upstream, downstream map[string][]EventCorrelationRecord) []EventCorrelationRecord {
	switch direction {
	case "upstream":
		return upstream[currentID]
	case "downstream":
		return downstream[currentID]
	default:
		return nil
	}
}

func emitEventCorrelationChain(direction string, eventIDs []string, edges []EventCorrelationRecord, eventRefs map[string]EventReference, out *[]EventCorrelationChain) {
	if len(edges) == 0 {
		return
	}
	events := make([]EventReference, 0, len(eventIDs))
	for _, eventID := range eventIDs {
		ref, ok := eventRefs[eventID]
		if !ok {
			continue
		}
		events = append(events, ref)
	}
	if len(events) == 0 {
		return
	}
	score := 0.0
	for _, edge := range edges {
		score += edge.Confidence
	}
	score = score / float64(len(edges))
	chainID := "event_chain:" + direction + ":" + strings.Join(eventIDs, "->")
	*out = append(*out, EventCorrelationChain{
		ID:           chainID,
		Direction:    direction,
		Depth:        len(edges),
		Score:        score,
		Events:       events,
		Correlations: append([]EventCorrelationRecord(nil), edges...),
	})
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

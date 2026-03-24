package graph

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	IdentityReviewVerdictAccepted  = "accepted"
	IdentityReviewVerdictRejected  = "rejected"
	IdentityReviewVerdictUncertain = "uncertain"
)

// IdentityReviewDecision captures one human review action for alias resolution.
type IdentityReviewDecision struct {
	AliasNodeID     string    `json:"alias_node_id"`
	CanonicalNodeID string    `json:"canonical_node_id"`
	Verdict         string    `json:"verdict"`
	Reviewer        string    `json:"reviewer,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	SourceSystem    string    `json:"source_system,omitempty"`
	SourceEventID   string    `json:"source_event_id,omitempty"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
	Confidence      float64   `json:"confidence,omitempty"`
}

// IdentityReviewRecord captures one normalized review entry persisted on alias nodes.
type IdentityReviewRecord struct {
	AliasNodeID     string    `json:"alias_node_id"`
	CanonicalNodeID string    `json:"canonical_node_id"`
	Verdict         string    `json:"verdict"`
	Reviewer        string    `json:"reviewer,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	SourceSystem    string    `json:"source_system"`
	SourceEventID   string    `json:"source_event_id"`
	ObservedAt      time.Time `json:"observed_at"`
	Confidence      float64   `json:"confidence"`
	Applied         bool      `json:"applied"`
}

// IdentityReviewQueueOptions controls identity backlog generation.
type IdentityReviewQueueOptions struct {
	SuggestThreshold float64 `json:"suggest_threshold,omitempty"`
	Limit            int     `json:"limit,omitempty"`
}

// IdentityReviewQueueItem describes one alias that needs reviewer attention.
type IdentityReviewQueueItem struct {
	AliasNodeID        string                        `json:"alias_node_id"`
	AliasName          string                        `json:"alias_name,omitempty"`
	SourceSystem       string                        `json:"source_system,omitempty"`
	CurrentCanonicalID string                        `json:"current_canonical_id,omitempty"`
	CandidateCount     int                           `json:"candidate_count"`
	Candidates         []IdentityResolutionCandidate `json:"candidates,omitempty"`
	LastReviewVerdict  string                        `json:"last_review_verdict,omitempty"`
	LastReviewedAt     *time.Time                    `json:"last_reviewed_at,omitempty"`
	PriorityScore      float64                       `json:"priority_score"`
}

// IdentityCalibrationOptions controls identity calibration report generation.
type IdentityCalibrationOptions struct {
	Now              time.Time `json:"now,omitempty"`
	SuggestThreshold float64   `json:"suggest_threshold,omitempty"`
	QueueLimit       int       `json:"queue_limit,omitempty"`
	IncludeQueue     bool      `json:"include_queue,omitempty"`
}

// IdentitySourceCalibration summarizes identity quality per source system.
type IdentitySourceCalibration struct {
	SourceSystem          string  `json:"source_system"`
	AliasNodes            int     `json:"alias_nodes"`
	ReviewedAliases       int     `json:"reviewed_aliases"`
	AcceptedDecisions     int     `json:"accepted_decisions"`
	RejectedDecisions     int     `json:"rejected_decisions"`
	PrecisionPercent      float64 `json:"precision_percent"`
	ReviewCoveragePercent float64 `json:"review_coverage_percent"`
	BacklogAliases        int     `json:"backlog_aliases"`
}

// IdentityCalibrationReport summarizes the operational quality of identity resolution.
type IdentityCalibrationReport struct {
	GeneratedAt           time.Time                   `json:"generated_at"`
	AliasNodes            int                         `json:"alias_nodes"`
	LinkedAliases         int                         `json:"linked_aliases"`
	ReviewedAliases       int                         `json:"reviewed_aliases"`
	DecisionsTotal        int                         `json:"decisions_total"`
	AcceptedDecisions     int                         `json:"accepted_decisions"`
	RejectedDecisions     int                         `json:"rejected_decisions"`
	PrecisionPercent      float64                     `json:"precision_percent"`
	LinkagePercent        float64                     `json:"linkage_percent"`
	ReviewCoveragePercent float64                     `json:"review_coverage_percent"`
	BacklogAliases        int                         `json:"backlog_aliases"`
	SourceMetrics         []IdentitySourceCalibration `json:"source_metrics,omitempty"`
	Queue                 []IdentityReviewQueueItem   `json:"queue,omitempty"`
}

// ReviewIdentityAlias records one reviewer decision and applies identity link mutations.
func ReviewIdentityAlias(g *Graph, decision IdentityReviewDecision) (IdentityReviewRecord, error) {
	if g == nil {
		return IdentityReviewRecord{}, fmt.Errorf("graph is required")
	}

	decision.AliasNodeID = strings.TrimSpace(decision.AliasNodeID)
	decision.CanonicalNodeID = strings.TrimSpace(decision.CanonicalNodeID)
	decision.Verdict = strings.ToLower(strings.TrimSpace(decision.Verdict))
	decision.Reviewer = strings.TrimSpace(decision.Reviewer)
	decision.Reason = strings.TrimSpace(decision.Reason)
	decision.SourceSystem = normalizeIdentitySystem(firstNonEmpty(decision.SourceSystem, "review"))
	decision.SourceEventID = strings.TrimSpace(decision.SourceEventID)
	if decision.SourceEventID == "" {
		decision.SourceEventID = fmt.Sprintf("review:%d", time.Now().UTC().UnixNano())
	}
	if decision.ObservedAt.IsZero() {
		decision.ObservedAt = time.Now().UTC()
	}
	decision.ObservedAt = decision.ObservedAt.UTC()
	if decision.Confidence <= 0 {
		decision.Confidence = 0.95
	}
	decision.Confidence = clampUnit(decision.Confidence)

	if decision.AliasNodeID == "" || decision.CanonicalNodeID == "" {
		return IdentityReviewRecord{}, fmt.Errorf("alias_node_id and canonical_node_id are required")
	}
	if decision.Verdict != IdentityReviewVerdictAccepted && decision.Verdict != IdentityReviewVerdictRejected && decision.Verdict != IdentityReviewVerdictUncertain {
		return IdentityReviewRecord{}, fmt.Errorf("verdict must be one of accepted, rejected, uncertain")
	}

	aliasNode, ok := g.GetNode(decision.AliasNodeID)
	if !ok || aliasNode == nil {
		return IdentityReviewRecord{}, fmt.Errorf("alias node not found: %s", decision.AliasNodeID)
	}
	if aliasNode.Kind != NodeKindIdentityAlias {
		return IdentityReviewRecord{}, fmt.Errorf("node %s is not an identity_alias", decision.AliasNodeID)
	}
	if _, ok := g.GetNode(decision.CanonicalNodeID); !ok {
		return IdentityReviewRecord{}, fmt.Errorf("canonical node not found: %s", decision.CanonicalNodeID)
	}

	record := IdentityReviewRecord{
		AliasNodeID:     decision.AliasNodeID,
		CanonicalNodeID: decision.CanonicalNodeID,
		Verdict:         decision.Verdict,
		Reviewer:        decision.Reviewer,
		Reason:          decision.Reason,
		SourceSystem:    decision.SourceSystem,
		SourceEventID:   decision.SourceEventID,
		ObservedAt:      decision.ObservedAt,
		Confidence:      decision.Confidence,
		Applied:         false,
	}

	switch decision.Verdict {
	case IdentityReviewVerdictAccepted:
		if err := ConfirmIdentityAlias(g, decision.AliasNodeID, decision.CanonicalNodeID, decision.SourceSystem, decision.SourceEventID, decision.ObservedAt, decision.Confidence); err != nil {
			return IdentityReviewRecord{}, err
		}
		record.Applied = true
	case IdentityReviewVerdictRejected:
		removed, err := SplitIdentityAlias(g, decision.AliasNodeID, decision.CanonicalNodeID, decision.Reason, decision.SourceSystem, decision.SourceEventID, decision.ObservedAt)
		if err != nil {
			return IdentityReviewRecord{}, err
		}
		record.Applied = removed
	case IdentityReviewVerdictUncertain:
		// Keep candidate unresolved but preserve review evidence.
	}

	aliasNode, _ = g.GetNode(decision.AliasNodeID)
	if aliasNode != nil {
		props := cloneAnyMap(aliasNode.Properties)
		if props == nil {
			props = make(map[string]any)
		}
		history := identityReviewHistory(props["identity_reviews"])
		history = append(history, record)
		props["identity_reviews"] = identityReviewHistoryAsAny(history)
		props["last_review_verdict"] = record.Verdict
		props["last_reviewer"] = record.Reviewer
		props["last_review_reason"] = record.Reason
		props["last_reviewed_at"] = record.ObservedAt.Format(time.RFC3339)
		props["review_status"] = record.Verdict
		props["review_confidence"] = record.Confidence
		aliasNode.Properties = props
		g.AddNode(aliasNode)
	}

	return record, nil
}

// IdentityReviewQueue returns aliases requiring reviewer attention.
func IdentityReviewQueue(g *Graph, opts IdentityReviewQueueOptions) []IdentityReviewQueueItem {
	if g == nil {
		return nil
	}
	resolvedOpts := normalizeIdentityResolutionOptions(IdentityResolutionOptions{SuggestThreshold: opts.SuggestThreshold})
	limit := opts.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}

	items := make([]IdentityReviewQueueItem, 0)
	for _, alias := range g.GetNodesByKind(NodeKindIdentityAlias) {
		if alias == nil {
			continue
		}
		assertion := identityAssertionFromAliasNode(alias)
		if assertion.SourceSystem == "" || assertion.ExternalID == "" {
			continue
		}

		candidates := candidatesAboveThreshold(identityResolutionCandidates(g, alias.ID, assertion), resolvedOpts.SuggestThreshold)
		if len(candidates) > 5 {
			candidates = candidates[:5]
		}

		currentCanonical := ""
		for _, edge := range g.GetOutEdges(alias.ID) {
			if edge == nil || edge.Kind != EdgeKindAliasOf {
				continue
			}
			currentCanonical = edge.Target
			break
		}

		lastReview, hasLastReview := identityLatestReview(alias)
		ambiguous := len(candidates) > 1
		if ambiguous {
			delta := candidates[0].Score - candidates[1].Score
			ambiguous = delta < 0.12
		}
		unresolved := strings.TrimSpace(currentCanonical) == ""
		recentRejected := hasLastReview && lastReview.Verdict == IdentityReviewVerdictRejected
		if !unresolved && !ambiguous && !recentRejected {
			continue
		}

		// Queue priority intentionally favors unresolved aliases first, then ambiguity and
		// recent rejected reviews (which usually indicate identity drift or stale hints).
		priority := 0.25
		if unresolved {
			priority += 0.45
		}
		if ambiguous {
			priority += 0.20
		}
		if recentRejected {
			priority += 0.10
		}
		if len(candidates) > 0 {
			priority += math.Max(0, 0.15-(candidates[0].Score*0.10))
		}
		if priority > 1 {
			priority = 1
		}
		priority = math.Round(priority*1000) / 1000

		item := IdentityReviewQueueItem{
			AliasNodeID:        alias.ID,
			AliasName:          firstNonEmpty(alias.Name, alias.ID),
			SourceSystem:       normalizeIdentitySystem(nodePropertyString(alias, "source_system")),
			CurrentCanonicalID: currentCanonical,
			CandidateCount:     len(candidates),
			Candidates:         candidates,
			PriorityScore:      priority,
		}
		if hasLastReview {
			item.LastReviewVerdict = lastReview.Verdict
			copy := lastReview.ObservedAt
			item.LastReviewedAt = &copy
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].PriorityScore == items[j].PriorityScore {
			return items[i].AliasNodeID < items[j].AliasNodeID
		}
		return items[i].PriorityScore > items[j].PriorityScore
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// BuildIdentityCalibrationReport computes identity precision, coverage, and backlog metrics.
func BuildIdentityCalibrationReport(g *Graph, opts IdentityCalibrationOptions) IdentityCalibrationReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	report := IdentityCalibrationReport{GeneratedAt: now}
	if g == nil {
		return report
	}

	aliasNodes := g.GetNodesByKind(NodeKindIdentityAlias)
	report.AliasNodes = len(aliasNodes)
	if report.AliasNodes == 0 {
		return report
	}

	type sourceAccumulator struct {
		aliasNodes        int
		reviewedAliasSet  map[string]struct{}
		acceptedDecisions int
		rejectedDecisions int
		backlogAliases    int
	}
	sources := make(map[string]*sourceAccumulator)

	for _, alias := range aliasNodes {
		if alias == nil {
			continue
		}
		source := normalizeIdentitySystem(nodePropertyString(alias, "source_system"))
		if source == "" {
			source = "unknown"
		}
		acc := sources[source]
		if acc == nil {
			acc = &sourceAccumulator{reviewedAliasSet: make(map[string]struct{})}
			sources[source] = acc
		}
		acc.aliasNodes++

		hasLink := false
		for _, edge := range g.GetOutEdges(alias.ID) {
			if edge != nil && edge.Kind == EdgeKindAliasOf {
				hasLink = true
				break
			}
		}
		if hasLink {
			report.LinkedAliases++
		}

		history := identityReviewHistory(alias.Properties["identity_reviews"])
		if len(history) > 0 {
			report.ReviewedAliases++
			acc.reviewedAliasSet[alias.ID] = struct{}{}
		}
		for _, review := range history {
			report.DecisionsTotal++
			switch review.Verdict {
			case IdentityReviewVerdictAccepted:
				report.AcceptedDecisions++
				acc.acceptedDecisions++
			case IdentityReviewVerdictRejected:
				report.RejectedDecisions++
				acc.rejectedDecisions++
			}
		}
	}

	queue := IdentityReviewQueue(g, IdentityReviewQueueOptions{SuggestThreshold: opts.SuggestThreshold, Limit: opts.QueueLimit})
	report.BacklogAliases = len(queue)
	for _, item := range queue {
		source := normalizeIdentitySystem(item.SourceSystem)
		if source == "" {
			source = "unknown"
		}
		acc := sources[source]
		if acc == nil {
			acc = &sourceAccumulator{reviewedAliasSet: make(map[string]struct{})}
			sources[source] = acc
		}
		acc.backlogAliases++
	}
	if opts.IncludeQueue {
		report.Queue = queue
	}

	decisionDenominator := report.AcceptedDecisions + report.RejectedDecisions
	if decisionDenominator > 0 {
		report.PrecisionPercent = (float64(report.AcceptedDecisions) / float64(decisionDenominator)) * 100
	}
	report.LinkagePercent = (float64(report.LinkedAliases) / float64(report.AliasNodes)) * 100
	report.ReviewCoveragePercent = (float64(report.ReviewedAliases) / float64(report.AliasNodes)) * 100
	report.PrecisionPercent = math.Round(report.PrecisionPercent*10) / 10
	report.LinkagePercent = math.Round(report.LinkagePercent*10) / 10
	report.ReviewCoveragePercent = math.Round(report.ReviewCoveragePercent*10) / 10

	sourceMetrics := make([]IdentitySourceCalibration, 0, len(sources))
	for source, acc := range sources {
		metric := IdentitySourceCalibration{
			SourceSystem:      source,
			AliasNodes:        acc.aliasNodes,
			ReviewedAliases:   len(acc.reviewedAliasSet),
			AcceptedDecisions: acc.acceptedDecisions,
			RejectedDecisions: acc.rejectedDecisions,
			BacklogAliases:    acc.backlogAliases,
		}
		denominator := metric.AcceptedDecisions + metric.RejectedDecisions
		if denominator > 0 {
			metric.PrecisionPercent = (float64(metric.AcceptedDecisions) / float64(denominator)) * 100
		}
		if metric.AliasNodes > 0 {
			metric.ReviewCoveragePercent = (float64(metric.ReviewedAliases) / float64(metric.AliasNodes)) * 100
		}
		metric.PrecisionPercent = math.Round(metric.PrecisionPercent*10) / 10
		metric.ReviewCoveragePercent = math.Round(metric.ReviewCoveragePercent*10) / 10
		sourceMetrics = append(sourceMetrics, metric)
	}
	sort.Slice(sourceMetrics, func(i, j int) bool {
		if sourceMetrics[i].AliasNodes == sourceMetrics[j].AliasNodes {
			return sourceMetrics[i].SourceSystem < sourceMetrics[j].SourceSystem
		}
		return sourceMetrics[i].AliasNodes > sourceMetrics[j].AliasNodes
	})
	report.SourceMetrics = sourceMetrics
	return report
}

func identityAssertionFromAliasNode(alias *Node) IdentityAliasAssertion {
	assertion := IdentityAliasAssertion{}
	if alias == nil {
		return assertion
	}
	assertion.AliasID = strings.TrimSpace(alias.ID)
	assertion.SourceSystem = normalizeIdentitySystem(nodePropertyString(alias, "source_system"))
	assertion.SourceEventID = nodePropertyString(alias, "source_event_id")
	assertion.ExternalID = normalizeIdentityToken(nodePropertyString(alias, "external_id"))
	assertion.AliasType = nodePropertyString(alias, "alias_type")
	assertion.CanonicalHint = nodePropertyString(alias, "canonical_hint")
	assertion.Email = normalizePersonEmail(nodePropertyString(alias, "email"))
	assertion.Name = nodePropertyString(alias, "name")
	if observedAt, ok := nodePropertyTime(alias, "observed_at"); ok {
		assertion.ObservedAt = observedAt.UTC()
	}
	if assertion.ObservedAt.IsZero() {
		assertion.ObservedAt = time.Now().UTC()
	}
	assertion.Confidence = nodePropertyFloat(alias, "confidence")
	if assertion.Confidence <= 0 {
		assertion.Confidence = 0.95
	}
	assertion.Confidence = clampUnit(assertion.Confidence)
	return assertion
}

func identityLatestReview(alias *Node) (IdentityReviewRecord, bool) {
	if alias == nil {
		return IdentityReviewRecord{}, false
	}
	reviews := identityReviewHistory(alias.Properties["identity_reviews"])
	if len(reviews) == 0 {
		return IdentityReviewRecord{}, false
	}
	latest := reviews[0]
	for _, review := range reviews[1:] {
		if review.ObservedAt.After(latest.ObservedAt) {
			latest = review
		}
	}
	return latest, true
}

func identityReviewHistory(raw any) []IdentityReviewRecord {
	switch typed := raw.(type) {
	case []IdentityReviewRecord:
		return append([]IdentityReviewRecord(nil), typed...)
	case []map[string]any:
		out := make([]IdentityReviewRecord, 0, len(typed))
		for _, entry := range typed {
			if record, ok := identityReviewRecordFromMap(entry); ok {
				out = append(out, record)
			}
		}
		return out
	case []any:
		out := make([]IdentityReviewRecord, 0, len(typed))
		for _, item := range typed {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if record, ok := identityReviewRecordFromMap(entry); ok {
				out = append(out, record)
			}
		}
		return out
	default:
		return nil
	}
}

func identityReviewRecordFromMap(entry map[string]any) (IdentityReviewRecord, bool) {
	if len(entry) == 0 {
		return IdentityReviewRecord{}, false
	}
	record := IdentityReviewRecord{
		AliasNodeID:     strings.TrimSpace(identityAnyToString(entry["alias_node_id"])),
		CanonicalNodeID: strings.TrimSpace(identityAnyToString(entry["canonical_node_id"])),
		Verdict:         strings.ToLower(strings.TrimSpace(identityAnyToString(entry["verdict"]))),
		Reviewer:        strings.TrimSpace(identityAnyToString(entry["reviewer"])),
		Reason:          strings.TrimSpace(identityAnyToString(entry["reason"])),
		SourceSystem:    normalizeIdentitySystem(identityAnyToString(entry["source_system"])),
		SourceEventID:   strings.TrimSpace(identityAnyToString(entry["source_event_id"])),
		Confidence:      toFloat(identityAnyToString(entry["confidence"])),
	}
	record.Applied = strings.EqualFold(strings.TrimSpace(identityAnyToString(entry["applied"])), "true")
	if ts, ok := identityParseTime(entry["observed_at"]); ok {
		record.ObservedAt = ts.UTC()
	}
	if record.AliasNodeID == "" || record.CanonicalNodeID == "" || record.Verdict == "" {
		return IdentityReviewRecord{}, false
	}
	if record.SourceSystem == "" {
		record.SourceSystem = "review"
	}
	if record.SourceEventID == "" {
		record.SourceEventID = fmt.Sprintf("review:%d", time.Now().UTC().UnixNano())
	}
	if record.ObservedAt.IsZero() {
		record.ObservedAt = time.Now().UTC()
	}
	if record.Confidence <= 0 {
		record.Confidence = 0.95
	}
	record.Confidence = clampUnit(record.Confidence)
	return record, true
}

func identityReviewHistoryAsAny(history []IdentityReviewRecord) []map[string]any {
	if len(history) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(history))
	for _, record := range history {
		out = append(out, map[string]any{
			"alias_node_id":     record.AliasNodeID,
			"canonical_node_id": record.CanonicalNodeID,
			"verdict":           record.Verdict,
			"reviewer":          record.Reviewer,
			"reason":            record.Reason,
			"source_system":     record.SourceSystem,
			"source_event_id":   record.SourceEventID,
			"observed_at":       record.ObservedAt.Format(time.RFC3339),
			"confidence":        record.Confidence,
			"applied":           record.Applied,
		})
	}
	return out
}

func toFloat(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	parsed, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func identityParseTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case string:
		s := strings.TrimSpace(typed)
		if s == "" {
			return time.Time{}, false
		}
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts.UTC(), true
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

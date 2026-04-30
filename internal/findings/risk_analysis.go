package findings

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const defaultFindingCorrelationWindow = 24 * time.Hour

// FindingExposureAnalysisOptions scopes source-agnostic risk correlation output.
type FindingExposureAnalysisOptions struct {
	Limit              int
	SampleLimit        int
	CorrelationWindow  time.Duration
	GraphNeighborhoods map[string]*ports.EntityNeighborhood
}

// FindingExposureAnalysisReport combines generic compound risk, temporal correlation, and graph path summaries.
type FindingExposureAnalysisReport struct {
	CompoundRisks CompoundRiskReport   `json:"compound_risks"`
	Correlations  []FindingCorrelation `json:"correlations"`
	AttackPaths   []FindingAttackPath  `json:"attack_paths"`
}

// FindingRiskContext captures contextual scoring signals for one finding or correlated group.
type FindingRiskContext struct {
	Score   int      `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

// FindingEvidenceBundle is a compact, source-agnostic evidence summary for a finding group or path.
type FindingEvidenceBundle struct {
	FindingIDs      []string `json:"finding_ids,omitempty"`
	RuleIDs         []string `json:"rule_ids,omitempty"`
	EventIDs        []string `json:"event_ids,omitempty"`
	ResourceURNs    []string `json:"resource_urns,omitempty"`
	FirstObservedAt string   `json:"first_observed_at,omitempty"`
	LastObservedAt  string   `json:"last_observed_at,omitempty"`
	FindingCount    int      `json:"finding_count"`
	EventCount      int      `json:"event_count"`
	ResourceCount   int      `json:"resource_count"`
}

// FindingCorrelation captures a generic stateful/temporal correlation over normalized finding dimensions.
type FindingCorrelation struct {
	Kind            string                `json:"kind"`
	Dimension       string                `json:"dimension"`
	Key             string                `json:"key"`
	Label           string                `json:"label,omitempty"`
	Score           int                   `json:"score"`
	TimespanSeconds int64                 `json:"timespan_seconds,omitempty"`
	RuleIDs         []string              `json:"rule_ids"`
	FindingIDs      []string              `json:"finding_ids"`
	Evidence        FindingEvidenceBundle `json:"evidence"`
	Reasons         []string              `json:"reasons,omitempty"`
}

// FindingAttackPath captures one bounded graph path that explains why a finding is connected to risky context.
type FindingAttackPath struct {
	Pattern    string                  `json:"pattern"`
	Score      int                     `json:"score"`
	FindingID  string                  `json:"finding_id"`
	FindingURN string                  `json:"finding_urn"`
	Steps      []FindingAttackPathStep `json:"steps"`
	Evidence   FindingEvidenceBundle   `json:"evidence"`
	Reasons    []string                `json:"reasons,omitempty"`
}

// FindingAttackPathStep is one edge in a generic attack/exposure path.
type FindingAttackPathStep struct {
	FromURN  string `json:"from_urn"`
	Relation string `json:"relation"`
	ToURN    string `json:"to_urn"`
	FromType string `json:"from_type,omitempty"`
	ToType   string `json:"to_type,omitempty"`
}

// AnalyzeFindingExposure summarizes source-agnostic compound risk, temporal correlations, and graph paths.
func AnalyzeFindingExposure(records []*ports.FindingRecord, options FindingExposureAnalysisOptions) FindingExposureAnalysisReport {
	compoundOptions := CompoundRiskOptions{Limit: options.Limit, SampleLimit: options.SampleLimit}
	return FindingExposureAnalysisReport{
		CompoundRisks: AnalyzeCompoundRisks(records, compoundOptions),
		Correlations:  AnalyzeFindingCorrelations(records, options),
		AttackPaths:   AnalyzeFindingAttackPaths(records, options.GraphNeighborhoods, options),
	}
}

// AnalyzeFindingCorrelations creates generic stateful correlation summaries over normalized finding dimensions.
func AnalyzeFindingCorrelations(records []*ports.FindingRecord, options FindingExposureAnalysisOptions) []FindingCorrelation {
	records = dedupeCompoundRiskFindings(records)
	window := options.CorrelationWindow
	if window <= 0 {
		window = defaultFindingCorrelationWindow
	}
	correlations := []FindingCorrelation{}
	for _, kind := range []string{
		compoundRiskKindActor,
		compoundRiskKindResource,
		compoundRiskKindRepository,
		compoundRiskKindSource,
		compoundRiskKindType,
	} {
		for _, bucket := range groupCompoundRiskFindings(records, kind) {
			correlation := newFindingCorrelation(bucket, window)
			if correlation.Kind == "" {
				continue
			}
			correlations = append(correlations, correlation)
		}
	}
	sort.Slice(correlations, func(i int, j int) bool {
		left := correlations[i]
		right := correlations[j]
		switch {
		case left.Score != right.Score:
			return left.Score > right.Score
		case len(left.FindingIDs) != len(right.FindingIDs):
			return len(left.FindingIDs) > len(right.FindingIDs)
		case left.Dimension != right.Dimension:
			return left.Dimension < right.Dimension
		default:
			return left.Key < right.Key
		}
	})
	if options.Limit > 0 && len(correlations) > options.Limit {
		correlations = correlations[:options.Limit]
	}
	return correlations
}

func newFindingCorrelation(bucket compoundRiskBucket, window time.Duration) FindingCorrelation {
	findings := nonNilFindings(bucket.findings)
	if len(findings) < 2 {
		return FindingCorrelation{}
	}
	sort.Slice(findings, func(i int, j int) bool {
		left := findingObservedAt(findings[i])
		right := findingObservedAt(findings[j])
		switch {
		case left.IsZero() && !right.IsZero():
			return false
		case !left.IsZero() && right.IsZero():
			return true
		case !left.Equal(right):
			return left.Before(right)
		default:
			return findings[i].ID < findings[j].ID
		}
	})
	evidence := newFindingEvidenceBundle(findings)
	if evidence.FindingCount < 2 {
		return FindingCorrelation{}
	}
	ruleIDs := evidence.RuleIDs
	if len(ruleIDs) < 2 && evidence.EventCount < 2 {
		return FindingCorrelation{}
	}
	timespan := findingBundleTimespan(findings)
	if window > 0 && timespan > window && len(ruleIDs) < 2 {
		return FindingCorrelation{}
	}
	correlationKind := "event_count"
	if len(ruleIDs) > 1 {
		correlationKind = "temporal"
		if findingTimesAreOrdered(findings) {
			correlationKind = "temporal_ordered"
		}
	}
	context := riskContextForFindings(findings)
	score := context.Score + evidence.FindingCount + len(ruleIDs)*3
	if correlationKind == "temporal_ordered" {
		score += 5
	}
	reasons := append([]string{correlationKind, "shared_" + bucket.kind}, context.Reasons...)
	return FindingCorrelation{
		Kind:            correlationKind,
		Dimension:       bucket.kind,
		Key:             bucket.key,
		Label:           bucket.label,
		Score:           score,
		TimespanSeconds: int64(timespan.Seconds()),
		RuleIDs:         ruleIDs,
		FindingIDs:      evidence.FindingIDs,
		Evidence:        evidence,
		Reasons:         uniqueSortedStrings(reasons),
	}
}

// AnalyzeFindingAttackPaths extracts bounded, source-agnostic paths from supplied graph neighborhoods.
func AnalyzeFindingAttackPaths(records []*ports.FindingRecord, neighborhoods map[string]*ports.EntityNeighborhood, options FindingExposureAnalysisOptions) []FindingAttackPath {
	records = dedupeCompoundRiskFindings(records)
	nodes, relations := flattenNeighborhoods(neighborhoods)
	relationsByTo := map[string][]FindingAttackPathStep{}
	for _, relation := range relations {
		relationsByTo[relation.ToURN] = append(relationsByTo[relation.ToURN], relation)
	}
	paths := []FindingAttackPath{}
	seen := map[string]struct{}{}
	for _, finding := range records {
		if finding == nil {
			continue
		}
		findingURN := findingGraphFindingURN(finding.TenantID, finding)
		hasFindingEdges := relationsByTo[findingURN]
		hasFindingEdges = append(hasFindingEdges, syntheticHasFindingEdges(finding, nodes)...)
		for _, hasFinding := range hasFindingEdges {
			if hasFinding.Relation != "has_finding" {
				continue
			}
			steps := []FindingAttackPathStep{typedAttackPathStep(hasFinding, nodes)}
			paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps)
			for _, upstream := range relationsByTo[hasFinding.FromURN] {
				if upstream.FromURN == findingURN || upstream.Relation == "has_finding" {
					continue
				}
				steps := []FindingAttackPathStep{typedAttackPathStep(upstream, nodes), typedAttackPathStep(hasFinding, nodes)}
				paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps)
			}
			for _, upstream := range syntheticActorEdges(finding, hasFinding.FromURN, nodes) {
				steps := []FindingAttackPathStep{typedAttackPathStep(upstream, nodes), typedAttackPathStep(hasFinding, nodes)}
				paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps)
			}
		}
	}
	sort.Slice(paths, func(i int, j int) bool {
		left := paths[i]
		right := paths[j]
		switch {
		case left.Score != right.Score:
			return left.Score > right.Score
		case len(left.Steps) != len(right.Steps):
			return len(left.Steps) > len(right.Steps)
		case left.Pattern != right.Pattern:
			return left.Pattern < right.Pattern
		default:
			return left.FindingURN < right.FindingURN
		}
	})
	if options.Limit > 0 && len(paths) > options.Limit {
		paths = paths[:options.Limit]
	}
	return paths
}

func appendFindingAttackPath(paths []FindingAttackPath, seen map[string]struct{}, finding *ports.FindingRecord, findingURN string, steps []FindingAttackPathStep) []FindingAttackPath {
	if len(steps) == 0 {
		return paths
	}
	keyParts := make([]string, 0, len(steps))
	for _, step := range steps {
		keyParts = append(keyParts, step.FromURN+"|"+step.Relation+"|"+step.ToURN)
	}
	key := strings.Join(keyParts, "\n")
	if _, ok := seen[key]; ok {
		return paths
	}
	seen[key] = struct{}{}
	context := AnalyzeFindingRiskContext(finding, time.Time{})
	weightScore, weightReasons := weightedAttackPathScore(steps)
	score := context.Score + weightScore
	pattern := attackPathPattern(steps)
	reasons := append([]string{"graph_path", "pattern:" + pattern}, context.Reasons...)
	reasons = append(reasons, weightReasons...)
	return append(paths, FindingAttackPath{
		Pattern:    pattern,
		Score:      score,
		FindingID:  strings.TrimSpace(finding.ID),
		FindingURN: findingURN,
		Steps:      steps,
		Evidence:   newFindingEvidenceBundle([]*ports.FindingRecord{finding}),
		Reasons:    uniqueSortedStrings(reasons),
	})
}

// AnalyzeFindingRiskContext scores one finding with source-agnostic contextual risk signals.
func AnalyzeFindingRiskContext(finding *ports.FindingRecord, now time.Time) FindingRiskContext {
	if finding == nil {
		return FindingRiskContext{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	attributes := finding.Attributes
	score := 0
	reasons := []string{}
	severity := strings.ToUpper(strings.TrimSpace(finding.Severity))
	if severityScore := compoundRiskSeverityScore(severity); severityScore > 0 {
		score += severityScore * 10
		reasons = append(reasons, "severity:"+severity)
	}
	status := strings.ToLower(strings.TrimSpace(finding.Status))
	if status == "" || status == findingStatusOpen {
		score += 2
		reasons = append(reasons, "active")
	}
	if !finding.DueAt.IsZero() && finding.DueAt.Before(now) {
		score += 5
		reasons = append(reasons, "overdue")
	}
	if observedAt := findingObservedAt(finding); !observedAt.IsZero() {
		age := now.Sub(observedAt)
		switch {
		case age >= 0 && age <= 24*time.Hour:
			score += 5
			reasons = append(reasons, "recent_24h")
		case age >= 0 && age <= 7*24*time.Hour:
			score += 2
			reasons = append(reasons, "recent_7d")
		}
	}
	if eventCount := len(uniqueSortedStrings(finding.EventIDs)); eventCount > 1 {
		score += min(eventCount, 10)
		reasons = append(reasons, "multiple_events")
	}
	if resourceCount := len(uniqueSortedStrings(finding.ResourceURNs)); resourceCount > 1 {
		score += min(resourceCount, 8)
		reasons = append(reasons, "multiple_resources")
	}
	if len(finding.ControlRefs) > 0 {
		score += min(len(finding.ControlRefs)*2, 8)
		reasons = append(reasons, "mapped_controls")
	}
	action := strings.ToLower(compoundRiskAction(finding))
	if containsAny(action, "disable", "delete", "destroy", "remove", "revoke", "bypass", "override", "public", "expose") {
		score += 8
		reasons = append(reasons, "risky_action")
	}
	criticality := strings.ToLower(firstNonEmpty(attributes["asset_criticality"], attributes["criticality"], attributes["business_criticality"], attributes["tier"]))
	if containsAny(criticality, "critical", "high", "crown", "tier0", "tier-0") {
		score += 10
		reasons = append(reasons, "critical_asset")
	}
	if findingAttributeBool(attributes, "internet_exposed", "public", "externally_exposed", "external_exposure") {
		score += 8
		reasons = append(reasons, "external_exposure")
	}
	if findingAttributeBool(attributes, "privileged", "actor_privileged", "admin", "is_admin", "has_admin") {
		score += 7
		reasons = append(reasons, "privileged_actor")
	}
	if findingAttributeBool(attributes, "is_kev", "kev", "known_exploited", "known_exploited_vulnerability") {
		score += 12
		reasons = append(reasons, "known_exploited")
	}
	if epss, ok := findingAttributeFloat(attributes, "epss_score", "epss", "exploit_probability"); ok {
		switch {
		case epss >= 0.7:
			score += 10
			reasons = append(reasons, "epss_high")
		case epss >= 0.2:
			score += 5
			reasons = append(reasons, "epss_elevated")
		}
	}
	dataClass := strings.ToLower(firstNonEmpty(attributes["data_classification"], attributes["sensitivity"], attributes["data_sensitivity"]))
	if containsAny(dataClass, "secret", "sensitive", "confidential", "restricted") {
		score += 6
		reasons = append(reasons, "sensitive_data")
	}
	if findingAttributeBool(attributes, "crown_jewel", "contains_secrets") {
		score += 12
		reasons = append(reasons, "crown_jewel")
	}
	return FindingRiskContext{Score: score, Reasons: uniqueSortedStrings(reasons)}
}

func weightedAttackPathScore(steps []FindingAttackPathStep) (int, []string) {
	score := 0
	reasons := make([]string, 0, len(steps))
	for _, step := range steps {
		weight := attackPathRelationWeight(step.Relation)
		score += weight
		if weight > 0 {
			reasons = append(reasons, "edge_weight:"+strings.TrimSpace(step.Relation)+":"+strconv.Itoa(weight))
		}
	}
	if len(steps) > 1 {
		score += len(steps) * 2
	}
	return score, uniqueSortedStrings(reasons)
}

func attackPathRelationWeight(relation string) int {
	switch strings.ToLower(strings.TrimSpace(relation)) {
	case "can_admin":
		return 10
	case "can_assume", "can_impersonate", "can_perform":
		return 8
	case "can_reach":
		return 7
	case "acted_on", "has_evidence", "supports":
		return 5
	case "assigned_to", "member_of", "runs_as":
		return 4
	case "has_finding":
		return 3
	case "has_identifier", "has_classification", "tagged_as":
		return 1
	default:
		return 2
	}
}

func riskContextForFindings(findings []*ports.FindingRecord) FindingRiskContext {
	score := 0
	reasons := []string{}
	for _, finding := range findings {
		context := AnalyzeFindingRiskContext(finding, time.Time{})
		score += context.Score
		reasons = append(reasons, context.Reasons...)
	}
	return FindingRiskContext{Score: score, Reasons: uniqueSortedStrings(reasons)}
}

func newFindingEvidenceBundle(findings []*ports.FindingRecord) FindingEvidenceBundle {
	findingIDs := []string{}
	ruleIDs := []string{}
	eventIDs := []string{}
	resourceURNs := []string{}
	var firstObserved time.Time
	var lastObserved time.Time
	for _, finding := range nonNilFindings(findings) {
		findingIDs = append(findingIDs, finding.ID)
		ruleIDs = append(ruleIDs, finding.RuleID)
		eventIDs = append(eventIDs, finding.EventIDs...)
		resourceURNs = append(resourceURNs, finding.ResourceURNs...)
		if observed := findingFirstObservedAt(finding); !observed.IsZero() && (firstObserved.IsZero() || observed.Before(firstObserved)) {
			firstObserved = observed
		}
		if observed := findingObservedAt(finding); !observed.IsZero() && (lastObserved.IsZero() || observed.After(lastObserved)) {
			lastObserved = observed
		}
	}
	bundle := FindingEvidenceBundle{
		FindingIDs:    uniqueSortedStrings(findingIDs),
		RuleIDs:       uniqueSortedStrings(ruleIDs),
		EventIDs:      uniqueSortedStrings(eventIDs),
		ResourceURNs:  uniqueSortedStrings(resourceURNs),
		FindingCount:  len(nonNilFindings(findings)),
		EventCount:    len(uniqueSortedStrings(eventIDs)),
		ResourceCount: len(uniqueSortedStrings(resourceURNs)),
	}
	if !firstObserved.IsZero() {
		bundle.FirstObservedAt = firstObserved.UTC().Format(time.RFC3339Nano)
	}
	if !lastObserved.IsZero() {
		bundle.LastObservedAt = lastObserved.UTC().Format(time.RFC3339Nano)
	}
	return bundle
}

func nonNilFindings(findings []*ports.FindingRecord) []*ports.FindingRecord {
	values := make([]*ports.FindingRecord, 0, len(findings))
	for _, finding := range findings {
		if finding != nil {
			values = append(values, finding)
		}
	}
	return values
}

func findingFirstObservedAt(finding *ports.FindingRecord) time.Time {
	if finding == nil {
		return time.Time{}
	}
	if !finding.FirstObservedAt.IsZero() {
		return finding.FirstObservedAt.UTC()
	}
	return finding.LastObservedAt.UTC()
}

func findingObservedAt(finding *ports.FindingRecord) time.Time {
	if finding == nil {
		return time.Time{}
	}
	if !finding.LastObservedAt.IsZero() {
		return finding.LastObservedAt.UTC()
	}
	return finding.FirstObservedAt.UTC()
}

func findingBundleTimespan(findings []*ports.FindingRecord) time.Duration {
	var first time.Time
	var last time.Time
	for _, finding := range findings {
		observed := findingObservedAt(finding)
		if observed.IsZero() {
			continue
		}
		if first.IsZero() || observed.Before(first) {
			first = observed
		}
		if last.IsZero() || observed.After(last) {
			last = observed
		}
	}
	if first.IsZero() || last.IsZero() || last.Before(first) {
		return 0
	}
	return last.Sub(first)
}

func findingTimesAreOrdered(findings []*ports.FindingRecord) bool {
	if len(findings) < 2 {
		return false
	}
	previous := time.Time{}
	for _, finding := range findings {
		observed := findingObservedAt(finding)
		if observed.IsZero() {
			return false
		}
		if !previous.IsZero() && !observed.After(previous) {
			return false
		}
		previous = observed
	}
	return true
}

func flattenNeighborhoods(neighborhoods map[string]*ports.EntityNeighborhood) (map[string]ports.NeighborhoodNode, []FindingAttackPathStep) {
	nodes := map[string]ports.NeighborhoodNode{}
	relationsByKey := map[string]FindingAttackPathStep{}
	for _, neighborhood := range neighborhoods {
		if neighborhood == nil {
			continue
		}
		if neighborhood.Root != nil {
			nodes[neighborhood.Root.URN] = *neighborhood.Root
		}
		for _, node := range neighborhood.Neighbors {
			if node != nil {
				nodes[node.URN] = *node
			}
		}
		for _, relation := range neighborhood.Relations {
			if relation == nil {
				continue
			}
			step := FindingAttackPathStep{
				FromURN:  strings.TrimSpace(relation.FromURN),
				Relation: strings.TrimSpace(relation.Relation),
				ToURN:    strings.TrimSpace(relation.ToURN),
			}
			if step.FromURN == "" || step.Relation == "" || step.ToURN == "" {
				continue
			}
			key := step.FromURN + "|" + step.Relation + "|" + step.ToURN
			relationsByKey[key] = step
		}
	}
	relations := make([]FindingAttackPathStep, 0, len(relationsByKey))
	for _, relation := range relationsByKey {
		relations = append(relations, typedAttackPathStep(relation, nodes))
	}
	sort.Slice(relations, func(i int, j int) bool {
		left := relations[i].FromURN + "|" + relations[i].Relation + "|" + relations[i].ToURN
		right := relations[j].FromURN + "|" + relations[j].Relation + "|" + relations[j].ToURN
		return left < right
	})
	return nodes, relations
}

func typedAttackPathStep(step FindingAttackPathStep, nodes map[string]ports.NeighborhoodNode) FindingAttackPathStep {
	if node, ok := nodes[step.FromURN]; ok {
		step.FromType = node.EntityType
	}
	if node, ok := nodes[step.ToURN]; ok {
		step.ToType = node.EntityType
	}
	if step.FromType == "" {
		step.FromType = resourceTypeFromURN(step.FromURN)
	}
	if step.ToType == "" {
		step.ToType = resourceTypeFromURN(step.ToURN)
	}
	return step
}

func syntheticHasFindingEdges(finding *ports.FindingRecord, nodes map[string]ports.NeighborhoodNode) []FindingAttackPathStep {
	if finding == nil {
		return nil
	}
	findingURN := findingGraphFindingURN(finding.TenantID, finding)
	edges := []FindingAttackPathStep{}
	for _, resourceURN := range uniqueSortedStrings(finding.ResourceURNs) {
		if resourceURN == "" || resourceURN == findingURN {
			continue
		}
		if _, ok := nodes[resourceURN]; !ok {
			nodes[resourceURN] = ports.NeighborhoodNode{URN: resourceURN, EntityType: resourceTypeFromURN(resourceURN), Label: resourceURN}
		}
		if _, ok := nodes[findingURN]; !ok {
			nodes[findingURN] = ports.NeighborhoodNode{URN: findingURN, EntityType: "finding", Label: finding.Title}
		}
		edges = append(edges, FindingAttackPathStep{FromURN: resourceURN, Relation: "has_finding", ToURN: findingURN})
	}
	return edges
}

func syntheticActorEdges(finding *ports.FindingRecord, resourceURN string, nodes map[string]ports.NeighborhoodNode) []FindingAttackPathStep {
	if finding == nil || strings.TrimSpace(resourceURN) == "" {
		return nil
	}
	actorURN := firstNonEmpty(finding.Attributes["primary_actor_urn"], finding.Attributes["actor_urn"])
	if !strings.HasPrefix(actorURN, "urn:") || actorURN == resourceURN {
		return nil
	}
	if _, ok := nodes[actorURN]; !ok {
		nodes[actorURN] = ports.NeighborhoodNode{URN: actorURN, EntityType: resourceTypeFromURN(actorURN), Label: firstNonEmpty(finding.Attributes["actor"], actorURN)}
	}
	return []FindingAttackPathStep{{FromURN: actorURN, Relation: "correlated_with", ToURN: resourceURN}}
}

func attackPathPattern(steps []FindingAttackPathStep) string {
	parts := make([]string, 0, len(steps)*2+1)
	for idx, step := range steps {
		fromType := firstNonEmpty(step.FromType, resourceTypeFromURN(step.FromURN), "entity")
		toType := firstNonEmpty(step.ToType, resourceTypeFromURN(step.ToURN), "entity")
		if idx == 0 {
			parts = append(parts, fromType)
		}
		parts = append(parts, "--"+step.Relation+"-->", toType)
	}
	return strings.Join(parts, " ")
}

func findingRiskMetadata(finding *ports.FindingRecord) map[string]string {
	if finding == nil {
		return nil
	}
	attributes := finding.Attributes
	metadata := map[string]string{
		"action":              compoundRiskAction(finding),
		"actor":               firstNonEmpty(attributes["actor"], attributes["user"], attributes["principal"], attributes["subject"]),
		"actor_urn":           firstNonEmpty(attributes["primary_actor_urn"], attributes["actor_urn"]),
		"repository":          repositoryFromFinding(finding),
		"resource_type":       genericResourceType(finding),
		"source_family":       sourceIDForFinding(finding),
		"asset_criticality":   firstNonEmpty(attributes["asset_criticality"], attributes["criticality"], attributes["business_criticality"], attributes["tier"]),
		"data_classification": firstNonEmpty(attributes["data_classification"], attributes["sensitivity"], attributes["data_sensitivity"]),
		"epss_score":          firstNonEmpty(attributes["epss_score"], attributes["epss"], attributes["exploit_probability"]),
		"is_kev":              firstNonEmpty(attributes["is_kev"], attributes["kev"], attributes["known_exploited"], attributes["known_exploited_vulnerability"]),
		"public":              firstNonEmpty(attributes["public"], attributes["internet_exposed"], attributes["externally_exposed"], attributes["external_exposure"]),
		"privileged":          firstNonEmpty(attributes["privileged"], attributes["actor_privileged"], attributes["admin"], attributes["is_admin"], attributes["has_admin"]),
	}
	trimEmptyAttributes(metadata)
	return metadata
}

func sourceIDForFinding(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	attributes := finding.Attributes
	return firstNonEmpty(
		attributes["source_family"],
		attributes["family"],
		attributes["rule_source_id"],
		attributes["source_id"],
		sourceIDFromRuntime(finding.RuntimeID),
		sourceIDFromRule(finding.RuleID),
		finding.RuntimeID,
	)
}

func genericResourceType(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	return firstNonEmpty(
		finding.Attributes["resource_type"],
		resourceTypeFromURN(finding.Attributes["primary_resource_urn"]),
		resourceTypeFromURN(firstFindingResourceURN(finding)),
		finding.Attributes["vulnerability_type"],
		finding.Attributes["ecosystem"],
	)
}

func containsAny(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func findingAttributeBool(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(attributes[key]))
		switch value {
		case "1", "t", "true", "yes", "y", "enabled", "public", "external", "critical":
			return true
		}
	}
	return false
}

func findingAttributeFloat(attributes map[string]string, keys ...string) (float64, bool) {
	for _, key := range keys {
		raw := strings.TrimSpace(attributes[key])
		if raw == "" {
			continue
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		return value, true
	}
	return 0, false
}

package findings

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/writer/cerebro/internal/ports"
)

const defaultFindingCorrelationWindow = 24 * time.Hour

const FindingRiskModelVersion = "likelihood-impact-v2"

const defaultFindingRiskModelVersion = FindingRiskModelVersion

const FindingEffectiveSeverityAttribute = "effective_severity"

const FindingSourceSeverityAttribute = "source_severity"

const FindingRiskGraphProjectedModelVersionAttribute = "risk_graph_projected_model_version"

// FindingExposureAnalysisOptions scopes source-agnostic risk correlation output.
type FindingExposureAnalysisOptions struct {
	Limit                int
	CorrelationLimit     int
	AttackPathLimit      int
	ActionCandidateLimit int
	SampleLimit          int
	CorrelationWindow    time.Duration
	CorrelationPatterns  []FindingCorrelationPattern
	GraphNeighborhoods   map[string]*ports.EntityNeighborhood
	RiskScoringConfig    *ports.RiskScoringConfig
}

// FindingExposureAnalysisReport combines generic compound risk, temporal correlation, and graph path summaries.
type FindingExposureAnalysisReport struct {
	CompoundRisks    CompoundRiskReport       `json:"compound_risks"`
	Correlations     []FindingCorrelation     `json:"correlations"`
	AttackPaths      []FindingAttackPath      `json:"attack_paths"`
	ActionCandidates []FindingActionCandidate `json:"action_candidates"`
}

// FindingRiskContext captures contextual scoring signals for one finding or correlated group.
type FindingRiskContext struct {
	Score             int                       `json:"score"`
	EffectiveSeverity string                    `json:"effective_severity,omitempty"`
	LikelihoodScore   int                       `json:"likelihood_score"`
	ImpactScore       int                       `json:"impact_score"`
	ConfidenceScore   int                       `json:"confidence_score"`
	LikelihoodLevel   string                    `json:"likelihood_level,omitempty"`
	ImpactLevel       string                    `json:"impact_level,omitempty"`
	RiskModelVersion  string                    `json:"risk_model_version,omitempty"`
	Reasons           []string                  `json:"reasons,omitempty"`
	Factors           []ports.FindingRiskFactor `json:"risk_factors,omitempty"`
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

// FindingActionCandidate is a read-only recommendation derived from correlated evidence.
type FindingActionCandidate struct {
	ActionType  string                `json:"action_type"`
	Source      string                `json:"source"`
	TargetURN   string                `json:"target_urn"`
	TargetLabel string                `json:"target_label,omitempty"`
	Owner       string                `json:"owner,omitempty"`
	Score       int                   `json:"score"`
	FindingIDs  []string              `json:"finding_ids"`
	RuleIDs     []string              `json:"rule_ids"`
	Reason      string                `json:"reason,omitempty"`
	Reasons     []string              `json:"reasons,omitempty"`
	RankFactors []string              `json:"rank_factors,omitempty"`
	Evidence    FindingEvidenceBundle `json:"evidence"`
}

// FindingCorrelation captures a generic stateful/temporal correlation over normalized finding dimensions.
type FindingCorrelation struct {
	Kind            string                `json:"kind"`
	PatternID       string                `json:"pattern_id,omitempty"`
	PatternName     string                `json:"pattern_name,omitempty"`
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

type FindingCorrelationPattern struct {
	ID         string
	Name       string
	RuleIDs    []string
	Dimensions []string
	Window     time.Duration
	ScoreBonus int
	Reasons    []string
	Tests      []FindingCorrelationPatternTest
}

type FindingCorrelationPatternTest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ExpectMatch bool   `json:"expect_match"`
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
	candidateOptions := options
	candidateOptions.Limit = 0
	candidateOptions.CorrelationLimit = 0
	candidateOptions.AttackPathLimit = 0
	compoundRisks := AnalyzeCompoundRisks(records, compoundOptions)
	correlations := AnalyzeFindingCorrelations(records, candidateOptions)
	attackPaths := AnalyzeFindingAttackPaths(records, options.GraphNeighborhoods, candidateOptions)
	return FindingExposureAnalysisReport{
		CompoundRisks:    compoundRisks,
		Correlations:     limitFindingCorrelations(correlations, correlationOutputLimit(options)),
		AttackPaths:      limitFindingAttackPaths(attackPaths, attackPathOutputLimit(options)),
		ActionCandidates: buildFindingActionCandidates(records, correlations, attackPaths, options),
	}
}

// AnalyzeFindingCorrelations creates generic stateful correlation summaries over normalized finding dimensions.
func AnalyzeFindingCorrelations(records []*ports.FindingRecord, options FindingExposureAnalysisOptions) []FindingCorrelation {
	records = dedupeCompoundRiskFindings(records)
	window := options.CorrelationWindow
	if window <= 0 {
		window = defaultFindingCorrelationWindow
	}
	correlations := AnalyzeFindingPatternCorrelations(records, options)
	for _, kind := range []string{
		compoundRiskKindActor,
		compoundRiskKindResource,
		compoundRiskKindRepository,
		compoundRiskKindContainerImage,
		compoundRiskKindSource,
		compoundRiskKindType,
	} {
		for _, bucket := range groupCompoundRiskFindings(records, kind) {
			correlation := newFindingCorrelation(bucket, window, options.RiskScoringConfig)
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
	return limitFindingCorrelations(correlations, correlationOutputLimit(options))
}

func limitFindingCorrelations(correlations []FindingCorrelation, limit int) []FindingCorrelation {
	if limit > 0 && len(correlations) > limit {
		return correlations[:limit]
	}
	return correlations
}

// AnalyzeFindingPatternCorrelations applies built-in Panther-style correlation patterns over normalized finding dimensions.
func AnalyzeFindingPatternCorrelations(records []*ports.FindingRecord, options FindingExposureAnalysisOptions) []FindingCorrelation {
	records = dedupeCompoundRiskFindings(records)
	patterns := options.CorrelationPatterns
	if len(patterns) == 0 {
		patterns = BuiltinFindingCorrelationPatterns()
	}
	correlations := []FindingCorrelation{}
	for _, pattern := range patterns {
		for _, dimension := range pattern.Dimensions {
			for _, bucket := range groupCompoundRiskFindings(records, dimension) {
				correlation := newPatternFindingCorrelation(pattern, bucket, options)
				if correlation.Kind == "" {
					continue
				}
				correlations = append(correlations, correlation)
			}
		}
	}
	return correlations
}

func newPatternFindingCorrelation(pattern FindingCorrelationPattern, bucket compoundRiskBucket, options FindingExposureAnalysisOptions) FindingCorrelation {
	window := pattern.Window
	if window <= 0 {
		window = options.CorrelationWindow
	}
	if window <= 0 {
		window = defaultFindingCorrelationWindow
	}
	matched := findingsMatchingRuleSetWithinWindow(bucket.findings, pattern.RuleIDs, window, options.RiskScoringConfig)
	if len(matched) < len(pattern.RuleIDs) {
		return FindingCorrelation{}
	}
	timespan := findingBundleTimespan(matched)
	evidence := newFindingEvidenceBundle(matched)
	if evidence.FindingCount < len(pattern.RuleIDs) {
		return FindingCorrelation{}
	}
	context := riskContextForFindingsWithConfig(matched, options.RiskScoringConfig)
	score := context.Score + pattern.ScoreBonus + evidence.FindingCount*3 + len(evidence.RuleIDs)*4
	reasons := append([]string{"pattern:" + pattern.ID, "shared_" + bucket.kind}, pattern.Reasons...)
	reasons = append(reasons, context.Reasons...)
	return FindingCorrelation{
		Kind:            "pattern",
		PatternID:       pattern.ID,
		PatternName:     pattern.Name,
		Dimension:       bucket.kind,
		Key:             bucket.key,
		Label:           bucket.label,
		Score:           score,
		TimespanSeconds: int64(timespan.Seconds()),
		RuleIDs:         evidence.RuleIDs,
		FindingIDs:      evidence.FindingIDs,
		Evidence:        evidence,
		Reasons:         uniqueSortedStrings(reasons),
	}
}

func findingsMatchingRuleSetWithinWindow(records []*ports.FindingRecord, ruleIDs []string, window time.Duration, config *ports.RiskScoringConfig) []*ports.FindingRecord {
	matched := findingsMatchingRuleSet(records, ruleIDs)
	if len(matched) < len(ruleIDs) {
		return nil
	}
	sort.Slice(matched, func(i int, j int) bool {
		left := findingObservedAt(matched[i])
		right := findingObservedAt(matched[j])
		switch {
		case left.IsZero() && !right.IsZero():
			return false
		case !left.IsZero() && right.IsZero():
			return true
		case !left.Equal(right):
			return left.Before(right)
		default:
			return matched[i].ID < matched[j].ID
		}
	})
	wanted := wantedRuleIDSet(ruleIDs)
	var best []*ports.FindingRecord
	bestEnd := time.Time{}
	bestScore := -1
	for start := range matched {
		windowRecords := []*ports.FindingRecord{}
		seenRules := map[string]struct{}{}
		for end := start; end < len(matched); end++ {
			candidate := matched[end]
			windowRecords = append(windowRecords, candidate)
			if ruleID := strings.TrimSpace(candidate.RuleID); ruleID != "" {
				seenRules[ruleID] = struct{}{}
			}
			if window > 0 && findingBundleTimespan(windowRecords) > window {
				break
			}
			if !containsWantedRuleSet(seenRules, wanted) {
				continue
			}
			windowEnd := findingObservedAt(windowRecords[len(windowRecords)-1])
			score := riskContextForFindingsWithConfig(windowRecords, config).Score + len(windowRecords)
			if best == nil || windowEnd.After(bestEnd) || (windowEnd.Equal(bestEnd) && score > bestScore) {
				best = append([]*ports.FindingRecord(nil), windowRecords...)
				bestEnd = windowEnd
				bestScore = score
			}
		}
	}
	return best
}

func findingsMatchingRuleSet(records []*ports.FindingRecord, ruleIDs []string) []*ports.FindingRecord {
	wanted := wantedRuleIDSet(ruleIDs)
	seenRules := map[string]struct{}{}
	matched := []*ports.FindingRecord{}
	for _, record := range nonNilFindings(records) {
		ruleID := strings.TrimSpace(record.RuleID)
		if _, ok := wanted[ruleID]; !ok {
			continue
		}
		seenRules[ruleID] = struct{}{}
		matched = append(matched, record)
	}
	if len(seenRules) != len(wanted) {
		return nil
	}
	return matched
}

func wantedRuleIDSet(ruleIDs []string) map[string]struct{} {
	wanted := map[string]struct{}{}
	for _, ruleID := range ruleIDs {
		if trimmed := strings.TrimSpace(ruleID); trimmed != "" {
			wanted[trimmed] = struct{}{}
		}
	}
	return wanted
}

func containsWantedRuleSet(seen map[string]struct{}, wanted map[string]struct{}) bool {
	if len(seen) < len(wanted) {
		return false
	}
	for ruleID := range wanted {
		if _, ok := seen[ruleID]; !ok {
			return false
		}
	}
	return true
}

func newFindingCorrelation(bucket compoundRiskBucket, window time.Duration, config *ports.RiskScoringConfig) FindingCorrelation {
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
	context := riskContextForFindingsWithConfig(findings, config)
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

func buildFindingActionCandidates(records []*ports.FindingRecord, correlations []FindingCorrelation, attackPaths []FindingAttackPath, options FindingExposureAnalysisOptions) []FindingActionCandidate {
	recordsByID := map[string]*ports.FindingRecord{}
	for _, record := range nonNilFindings(records) {
		if id := strings.TrimSpace(record.ID); id != "" {
			recordsByID[id] = record
		}
	}
	candidates := []FindingActionCandidate{}
	seen := map[string]struct{}{}
	for _, correlation := range correlations {
		targetURN := actionCandidateTargetURN(correlation.Key, correlation.Evidence.ResourceURNs)
		if targetURN == "" {
			continue
		}
		candidate := FindingActionCandidate{
			ActionType:  recommendedActionType(correlation.RuleIDs, correlation.Reasons),
			Source:      "correlation:" + correlation.Kind,
			TargetURN:   targetURN,
			TargetLabel: correlation.Label,
			Owner:       actionCandidateOwner(correlation.FindingIDs, recordsByID),
			Score:       correlation.Score,
			FindingIDs:  uniqueSortedStrings(correlation.FindingIDs),
			RuleIDs:     uniqueSortedStrings(correlation.RuleIDs),
			Reason:      firstNonEmpty(correlation.PatternName, strings.Join(correlation.Reasons, ",")),
			Evidence:    correlation.Evidence,
		}
		candidate.Reasons = actionCandidateReasons(candidate, correlation.Reasons)
		candidate.RankFactors = actionCandidateRankFactors(candidate)
		candidates = appendUniqueFindingActionCandidate(candidates, seen, candidate)
	}
	for _, path := range attackPaths {
		targetURN := actionCandidateTargetURN(actionPathTargetURN(path), path.Evidence.ResourceURNs)
		if targetURN == "" {
			continue
		}
		candidate := FindingActionCandidate{
			ActionType: recommendedActionType(path.Evidence.RuleIDs, path.Reasons),
			Source:     "attack_path",
			TargetURN:  targetURN,
			Owner:      actionCandidateOwner(path.Evidence.FindingIDs, recordsByID),
			Score:      path.Score,
			FindingIDs: uniqueSortedStrings(path.Evidence.FindingIDs),
			RuleIDs:    uniqueSortedStrings(path.Evidence.RuleIDs),
			Reason:     firstNonEmpty(path.Pattern, strings.Join(path.Reasons, ",")),
			Evidence:   path.Evidence,
		}
		candidate.Reasons = actionCandidateReasons(candidate, path.Reasons)
		candidate.RankFactors = actionCandidateRankFactors(candidate)
		candidates = appendUniqueFindingActionCandidate(candidates, seen, candidate)
	}
	sort.Slice(candidates, func(i int, j int) bool {
		left := candidates[i]
		right := candidates[j]
		switch {
		case left.Score != right.Score:
			return left.Score > right.Score
		case len(left.FindingIDs) != len(right.FindingIDs):
			return len(left.FindingIDs) > len(right.FindingIDs)
		case left.ActionType != right.ActionType:
			return left.ActionType < right.ActionType
		default:
			return left.TargetURN < right.TargetURN
		}
	})
	if limit := actionCandidateOutputLimit(options); limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func correlationOutputLimit(options FindingExposureAnalysisOptions) int {
	if options.CorrelationLimit > 0 {
		return options.CorrelationLimit
	}
	return options.Limit
}

func attackPathOutputLimit(options FindingExposureAnalysisOptions) int {
	if options.AttackPathLimit > 0 {
		return options.AttackPathLimit
	}
	return options.Limit
}

func actionCandidateOutputLimit(options FindingExposureAnalysisOptions) int {
	if options.ActionCandidateLimit > 0 {
		return options.ActionCandidateLimit
	}
	return options.Limit
}

func actionCandidateReasons(candidate FindingActionCandidate, sourceReasons []string) []string {
	reasons := append([]string(nil), sourceReasons...)
	reasons = append(reasons,
		"action_type:"+candidate.ActionType,
		"source:"+candidate.Source,
	)
	return uniqueSortedStrings(reasons)
}

func actionCandidateRankFactors(candidate FindingActionCandidate) []string {
	return uniqueTrimmedStringsPreserveOrder([]string{
		fmt.Sprintf("score:%d", candidate.Score),
		fmt.Sprintf("finding_count:%d", len(candidate.FindingIDs)),
		fmt.Sprintf("rule_count:%d", len(candidate.RuleIDs)),
		"action_type:" + candidate.ActionType,
		"source:" + candidate.Source,
	})
}

func appendUniqueFindingActionCandidate(candidates []FindingActionCandidate, seen map[string]struct{}, candidate FindingActionCandidate) []FindingActionCandidate {
	if candidate.TargetURN == "" || len(candidate.FindingIDs) == 0 {
		return candidates
	}
	key := strings.Join([]string{
		candidate.ActionType,
		candidate.Source,
		candidate.TargetURN,
		strings.Join(candidate.FindingIDs, "|"),
		strings.Join(candidate.RuleIDs, "|"),
	}, "\n")
	if _, ok := seen[key]; ok {
		return candidates
	}
	seen[key] = struct{}{}
	return append(candidates, candidate)
}

func actionCandidateTargetURN(primary string, resourceURNs []string) string {
	if value := strings.TrimSpace(primary); strings.HasPrefix(value, "urn:") {
		return value
	}
	for _, resourceURN := range resourceURNs {
		if value := strings.TrimSpace(resourceURN); strings.HasPrefix(value, "urn:") {
			return value
		}
	}
	return ""
}

func actionPathTargetURN(path FindingAttackPath) string {
	for idx := len(path.Steps) - 1; idx >= 0; idx-- {
		step := path.Steps[idx]
		if step.Relation == "has_finding" {
			if target := strings.TrimSpace(step.FromURN); strings.HasPrefix(target, "urn:") {
				return target
			}
			continue
		}
		if target := strings.TrimSpace(step.ToURN); strings.HasPrefix(target, "urn:") {
			return target
		}
		if target := strings.TrimSpace(step.FromURN); strings.HasPrefix(target, "urn:") {
			return target
		}
	}
	return path.FindingURN
}

func actionCandidateOwner(findingIDs []string, recordsByID map[string]*ports.FindingRecord) string {
	for _, findingID := range uniqueSortedStrings(findingIDs) {
		record := recordsByID[findingID]
		if record == nil {
			continue
		}
		if owner := firstNonEmpty(
			record.Attributes["owner"],
			record.Attributes["service_owner"],
			record.Attributes["repo_owner"],
			record.Attributes["repository_owner"],
			record.Attributes["owning_team"],
			record.Attributes["team"],
			record.Assignee,
		); owner != "" {
			return owner
		}
	}
	return ""
}

func recommendedActionType(ruleIDs []string, reasons []string) string {
	ruleSet := map[string]struct{}{}
	for _, ruleID := range ruleIDs {
		ruleSet[strings.TrimSpace(ruleID)] = struct{}{}
	}
	if _, ok := ruleSet[runtimeActiveThreatEvidenceRuleID]; ok {
		return "investigate_runtime_threat"
	}
	if _, ok := ruleSet[githubSecretScanningAlertCreatedRuleID]; ok {
		return "rotate_secret_and_restore_control"
	}
	if _, hasAurelius := ruleSet[aureliusPromotedVulnerabilityActiveRuleID]; hasAurelius {
		if _, hasTrivy := ruleSet[trivyImageVulnerabilityActiveRuleID]; hasTrivy {
			return "remediate_promoted_container_vulnerability"
		}
	}
	if _, ok := ruleSet[githubDependabotOpenAlertRuleID]; ok {
		return "remediate_vulnerable_dependency"
	}
	if _, ok := ruleSet[cloudPublicResourceExposureRuleID]; ok {
		return "review_public_exposure_path"
	}
	for _, reason := range reasons {
		if strings.Contains(reason, "external_exposure") {
			return "review_public_exposure_path"
		}
	}
	return "review_correlated_findings"
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
			paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps, options.RiskScoringConfig)
			for _, upstream := range relationsByTo[hasFinding.FromURN] {
				if upstream.FromURN == findingURN || upstream.Relation == "has_finding" {
					continue
				}
				steps := []FindingAttackPathStep{typedAttackPathStep(upstream, nodes), typedAttackPathStep(hasFinding, nodes)}
				paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps, options.RiskScoringConfig)
			}
			for _, upstream := range syntheticActorEdges(finding, hasFinding.FromURN, nodes) {
				steps := []FindingAttackPathStep{typedAttackPathStep(upstream, nodes), typedAttackPathStep(hasFinding, nodes)}
				paths = appendFindingAttackPath(paths, seen, finding, findingURN, steps, options.RiskScoringConfig)
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
	return limitFindingAttackPaths(paths, attackPathOutputLimit(options))
}

func limitFindingAttackPaths(paths []FindingAttackPath, limit int) []FindingAttackPath {
	if limit > 0 && len(paths) > limit {
		return paths[:limit]
	}
	return paths
}

func appendFindingAttackPath(paths []FindingAttackPath, seen map[string]struct{}, finding *ports.FindingRecord, findingURN string, steps []FindingAttackPathStep, config *ports.RiskScoringConfig) []FindingAttackPath {
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
	context := AnalyzeFindingRiskContextWithConfig(finding, time.Time{}, config)
	weightScore, weightReasons := weightedAttackPathScoreWithConfig(steps, config)
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
	return AnalyzeFindingRiskContextWithConfig(finding, now, nil)
}

// AnalyzeFindingRiskContextWithConfig scores one finding with tenant-specific risk scoring overrides.
func AnalyzeFindingRiskContextWithConfig(finding *ports.FindingRecord, now time.Time, config *ports.RiskScoringConfig) FindingRiskContext {
	if finding == nil {
		return FindingRiskContext{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	settings := riskScoringSettingsFromConfig(config)
	attributes := finding.Attributes
	likelihood := 10
	impact := 10
	confidence := 85
	reasons := []string{}
	severity := strings.ToUpper(strings.TrimSpace(firstNonEmpty(attributes[FindingSourceSeverityAttribute], attributes["rule_severity"], finding.Severity)))
	if severityScore := compoundRiskSeverityScore(severity); severityScore > 0 {
		applyRiskScoringFactor(settings, "severity", "severity:"+severity, ports.RiskScoringFactorWeight{Likelihood: severityScore * 6, Impact: severityScore * 8}, &likelihood, &impact, &confidence, &reasons)
	}
	status := strings.ToLower(strings.TrimSpace(finding.Status))
	if status == "" || status == findingStatusOpen {
		applyRiskScoringFactor(settings, "active", "active", ports.RiskScoringFactorWeight{Likelihood: 5}, &likelihood, &impact, &confidence, &reasons)
	}
	if !finding.DueAt.IsZero() && finding.DueAt.Before(now) {
		applyRiskScoringFactor(settings, "overdue", "overdue", ports.RiskScoringFactorWeight{Impact: 5}, &likelihood, &impact, &confidence, &reasons)
	}
	if observedAt := findingObservedAt(finding); !observedAt.IsZero() {
		age := now.Sub(observedAt)
		switch {
		case age >= 0 && age <= 24*time.Hour:
			applyRiskScoringFactor(settings, "recent_24h", "recent_24h", ports.RiskScoringFactorWeight{Likelihood: 5}, &likelihood, &impact, &confidence, &reasons)
		case age >= 0 && age <= 7*24*time.Hour:
			applyRiskScoringFactor(settings, "recent_7d", "recent_7d", ports.RiskScoringFactorWeight{Likelihood: 2}, &likelihood, &impact, &confidence, &reasons)
		}
	}
	if eventCount := len(uniqueSortedStrings(finding.EventIDs)); eventCount > 1 {
		applyRiskScoringFactor(settings, "multiple_events", "multiple_events", ports.RiskScoringFactorWeight{Likelihood: min(eventCount*2, 10), Confidence: 3}, &likelihood, &impact, &confidence, &reasons)
	}
	switch strings.TrimSpace(attributes[FindingConnectorValidationGradeAttribute]) {
	case "fixture_validated":
		applyRiskScoringFactor(settings, "connector_validated", "connector_validated:fixture", ports.RiskScoringFactorWeight{Confidence: 5}, &likelihood, &impact, &confidence, &reasons)
	case "live_validated", "production_observed":
		applyRiskScoringFactor(settings, "connector_validated", "connector_validated:live", ports.RiskScoringFactorWeight{Confidence: 8}, &likelihood, &impact, &confidence, &reasons)
	case "generated_from_docs", "schema_validated":
		applyRiskScoringFactor(settings, "connector_unvalidated", "connector_unvalidated:"+strings.TrimSpace(attributes[FindingConnectorValidationGradeAttribute]), ports.RiskScoringFactorWeight{Confidence: -20}, &likelihood, &impact, &confidence, &reasons)
	}
	if resourceCount := len(uniqueSortedStrings(finding.ResourceURNs)); resourceCount > 1 {
		applyRiskScoringFactor(settings, "multiple_resources", "multiple_resources", ports.RiskScoringFactorWeight{Impact: min(resourceCount*2, 12)}, &likelihood, &impact, &confidence, &reasons)
	}
	if len(finding.ControlRefs) > 0 {
		applyRiskScoringFactor(settings, "mapped_controls", "mapped_controls", ports.RiskScoringFactorWeight{Impact: min(len(finding.ControlRefs)*2, 8)}, &likelihood, &impact, &confidence, &reasons)
	}
	action := strings.ToLower(compoundRiskAction(finding))
	if containsAny(action, "disable", "delete", "destroy", "remove", "revoke", "bypass", "override", "public", "expose") {
		applyRiskScoringFactor(settings, "risky_action", "risky_action", ports.RiskScoringFactorWeight{Likelihood: 12}, &likelihood, &impact, &confidence, &reasons)
	}
	criticality := strings.ToLower(firstNonEmpty(attributes["asset_criticality"], attributes["criticality"], attributes["business_criticality"], attributes["tier"]))
	if containsAny(criticality, "critical", "high", "crown", "tier0", "tier-0") {
		applyRiskScoringFactor(settings, "critical_asset", "critical_asset", ports.RiskScoringFactorWeight{Impact: 35}, &likelihood, &impact, &confidence, &reasons)
	}
	publicExposure := findingAttributeBool(attributes, "internet_exposed", "public", "externally_exposed", "external_exposure", "is_public", "is_internet_facing")
	reachabilityPath := publicExposure || findingAttributeBool(attributes, "reachable", "directly_reachable", "internet_reachable", "can_reach")
	if containsAny(action, "can_reach", "public_network_ingress", "internet_facing") {
		reachabilityPath = true
	}
	if publicExposure {
		applyRiskScoringFactor(settings, "external_exposure", "external_exposure", ports.RiskScoringFactorWeight{Likelihood: 35}, &likelihood, &impact, &confidence, &reasons)
	}
	if findingAttributeBool(attributes, "privileged", "actor_privileged", "admin", "is_admin", "has_admin") {
		applyRiskScoringFactor(settings, "privileged_actor", "privileged_actor", ports.RiskScoringFactorWeight{Likelihood: 10, Impact: 15}, &likelihood, &impact, &confidence, &reasons)
	}
	activeExploit := findingActiveThreatSignal(attributes, action)
	if activeExploit {
		applyRiskScoringFactor(settings, "active_threat", "active_threat", ports.RiskScoringFactorWeight{Likelihood: 25}, &likelihood, &impact, &confidence, &reasons)
	}
	if findingAttributeBool(attributes, "is_kev", "kev", "known_exploited", "known_exploited_vulnerability") {
		applyRiskScoringFactor(settings, "known_exploited", "known_exploited", ports.RiskScoringFactorWeight{Likelihood: 35}, &likelihood, &impact, &confidence, &reasons)
	}
	if epss, ok := findingAttributeFloat(attributes, "epss_score", "epss", "exploit_probability"); ok {
		switch {
		case epss >= settings.config.Signals.EPSSHigh:
			applyRiskScoringFactor(settings, "epss_high", "epss_high", ports.RiskScoringFactorWeight{Likelihood: 25}, &likelihood, &impact, &confidence, &reasons)
		case epss >= settings.config.Signals.EPSSElevated:
			applyRiskScoringFactor(settings, "epss_elevated", "epss_elevated", ports.RiskScoringFactorWeight{Likelihood: 12}, &likelihood, &impact, &confidence, &reasons)
		}
	}
	if findingAttributeBool(attributes, "exploit_available", "public_exploit", "weaponized_exploit") {
		applyRiskScoringFactor(settings, "exploit_available", "exploit_available", ports.RiskScoringFactorWeight{Likelihood: 20}, &likelihood, &impact, &confidence, &reasons)
	}
	exploitMaturity := strings.ToLower(firstNonEmpty(attributes["exploit_maturity"], attributes["exploit_status"]))
	if containsAny(exploitMaturity, "weaponized", "functional", "poc", "proof") {
		applyRiskScoringFactor(settings, "exploit_maturity", "exploit_maturity:"+exploitMaturity, ports.RiskScoringFactorWeight{Likelihood: 15}, &likelihood, &impact, &confidence, &reasons)
	}
	if cvss, ok := findingAttributeFloat(attributes, "cvss_score", "cvss", "base_score"); ok {
		switch {
		case cvss >= settings.config.Signals.CVSSCritical:
			applyRiskScoringFactor(settings, "cvss_critical", "cvss_critical", ports.RiskScoringFactorWeight{Likelihood: 10, Impact: 10}, &likelihood, &impact, &confidence, &reasons)
		case cvss >= settings.config.Signals.CVSSHigh:
			applyRiskScoringFactor(settings, "cvss_high", "cvss_high", ports.RiskScoringFactorWeight{Likelihood: 5, Impact: 5}, &likelihood, &impact, &confidence, &reasons)
		}
	}
	dataClass := strings.ToLower(firstNonEmpty(attributes["data_classification"], attributes["sensitivity"], attributes["data_sensitivity"]))
	if dataClassificationSensitive(dataClass) {
		applyRiskScoringFactor(settings, "sensitive_data", "sensitive_data", ports.RiskScoringFactorWeight{Impact: 25}, &likelihood, &impact, &confidence, &reasons)
	}
	if findingAttributeBool(attributes, "crown_jewel", "contains_secrets") {
		applyRiskScoringFactor(settings, "crown_jewel", "crown_jewel", ports.RiskScoringFactorWeight{Impact: 35}, &likelihood, &impact, &confidence, &reasons)
	}
	if findingAttributeBool(attributes, "contains_pii", "contains_phi", "contains_pci", "has_sensitive_data", "has_sensitive_data_access") {
		applyRiskScoringFactor(settings, "regulated_or_sensitive_data", "regulated_or_sensitive_data", ports.RiskScoringFactorWeight{Impact: 20}, &likelihood, &impact, &confidence, &reasons)
	}
	environment := strings.ToLower(firstNonEmpty(attributes["environment"], attributes["env"], attributes["stage"], attributes["site_name"]))
	if isProductionEnvironment(environment) {
		applyRiskScoringFactor(settings, "production_environment", "production_environment", ports.RiskScoringFactorWeight{Impact: 15}, &likelihood, &impact, &confidence, &reasons)
	}
	if findingAttributeBool(attributes, "can_admin", "admin_reachable", "privileged_access", "has_admin_path") || containsAny(action, "can_admin", "can_assume", "can_impersonate") {
		applyRiskScoringFactor(settings, "privilege_or_control_plane", "privilege_or_control_plane", ports.RiskScoringFactorWeight{Impact: 20}, &likelihood, &impact, &confidence, &reasons)
	}
	if blastRadius, ok := findingAttributeInt(attributes, "blast_radius", "affected_users", "reachable_resource_count", "admin_reachable_count", "sensitive_data_path_count"); ok && blastRadius > 0 {
		applyRiskScoringFactor(settings, "blast_radius", "blast_radius", ports.RiskScoringFactorWeight{Impact: min(blastRadius, 20)}, &likelihood, &impact, &confidence, &reasons)
	}
	networkScope := strings.ToLower(firstNonEmpty(attributes["network_scope"], attributes["cidr_scope"], attributes["ip_scope"], attributes["subnet_scope"], attributes["exposure_scope"]))
	privateNetwork := findingAttributeBool(attributes, "private_network", "private_subnet") || containsAny(networkScope, "private", "rfc1918", "loopback", "link-local", "unique-local")
	if privateNetwork && !reachabilityPath && !activeExploit {
		applyRiskScoringFactor(settings, "private_network_context", "private_network_context", ports.RiskScoringFactorWeight{LikelihoodCap: settings.config.Signals.PrivateNetworkLikelihoodCap}, &likelihood, &impact, &confidence, &reasons)
	}
	if len(finding.GraphEvidenceRows) > 0 {
		applyRiskScoringFactor(settings, "graph_evidence", "graph_evidence", ports.RiskScoringFactorWeight{Confidence: 5}, &likelihood, &impact, &confidence, &reasons)
	}
	if len(finding.ResourceURNs) == 0 && len(finding.EventIDs) == 0 {
		applyRiskScoringFactor(settings, "limited_evidence", "limited_evidence", ports.RiskScoringFactorWeight{Confidence: -15}, &likelihood, &impact, &confidence, &reasons)
	}
	likelihood = clampScore(likelihood)
	impact = clampScore(impact)
	confidence = clampScore(confidence)
	riskScore := productRiskScore(likelihood, impact)
	reasons = uniqueSortedStrings(reasons)
	return FindingRiskContext{
		Score:             riskScore,
		EffectiveSeverity: settings.severity(riskScore),
		LikelihoodScore:   likelihood,
		ImpactScore:       impact,
		ConfidenceScore:   confidence,
		LikelihoodLevel:   settings.level(likelihood),
		ImpactLevel:       settings.level(impact),
		RiskModelVersion:  settings.modelVersion,
		Reasons:           reasons,
		Factors:           riskFactorsFromReasons(reasons, finding, now),
	}
}

func productRiskScore(likelihood int, impact int) int {
	return clampScore(int(math.Round(math.Sqrt(float64(clampScore(likelihood) * clampScore(impact))))))
}

func findingActiveThreatSignal(attributes map[string]string, action string) bool {
	if findingAttributeBool(attributes, "active_exploit", "active_threat", "exploit_detected", "credential_use", "token_exchange", "suspicious_process", "is_infected", "infected") {
		return true
	}
	if count, ok := findingAttributeInt(attributes, "active_threats", "active_threat_count"); ok && count > 0 {
		return true
	}
	evidenceType := strings.ToLower(firstNonEmpty(attributes["evidence_type"], attributes["evidence_kind"], attributes["signal"]))
	if containsAny(evidenceType, "exploit", "secret_access", "credential_use", "token_exchange", "suspicious_process", "active_threat", "infected") {
		return true
	}
	return containsAny(action, "credential_use", "token_exchange", "suspicious_process", "active_threat", "exploit")
}

func isProductionEnvironment(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}
	tokens := strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(tokens) == 0 {
		return false
	}
	for i, token := range tokens {
		switch token {
		case "nonprod", "nonproduction", "preprod", "preproduction", "staging", "stage", "dev", "development", "test", "testing", "qa", "sandbox", "uat":
			return false
		case "prod", "production", "prd", "live":
			if i > 0 {
				switch tokens[i-1] {
				case "non", "not", "pre":
					return false
				}
			}
			return true
		}
	}
	return false
}

func clampScore(score int) int {
	switch {
	case score < 0:
		return 0
	case score > 100:
		return 100
	default:
		return score
	}
}

// RiskLevelFromScoreWithConfig maps a score to a risk level using optional thresholds.
func RiskLevelFromScoreWithConfig(score int, config *ports.RiskScoringConfig) string {
	return riskScoringSettingsFromConfig(config).level(score)
}

func EffectiveSeverityFromRiskScore(score int) string {
	return EffectiveSeverityFromRiskScoreWithConfig(score, nil)
}

// EffectiveSeverityFromRiskScoreWithConfig maps a score to severity using optional thresholds.
func EffectiveSeverityFromRiskScoreWithConfig(score int, config *ports.RiskScoringConfig) string {
	return riskScoringSettingsFromConfig(config).severity(score)
}

func weightedAttackPathScore(steps []FindingAttackPathStep) (int, []string) {
	return weightedAttackPathScoreWithConfig(steps, nil)
}

func weightedAttackPathScoreWithConfig(steps []FindingAttackPathStep, config *ports.RiskScoringConfig) (int, []string) {
	settings := riskScoringSettingsFromConfig(config)
	score := 0
	reasons := make([]string, 0, len(steps))
	for _, step := range steps {
		weight := riskScoringRelationWeight(settings, step.Relation)
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

func riskContextForFindings(findings []*ports.FindingRecord) FindingRiskContext {
	return riskContextForFindingsWithConfig(findings, nil)
}

func riskContextForFindingsWithConfig(findings []*ports.FindingRecord, config *ports.RiskScoringConfig) FindingRiskContext {
	score := 0
	reasons := []string{}
	for _, finding := range findings {
		context := AnalyzeFindingRiskContextWithConfig(finding, time.Time{}, config)
		score += context.Score
		reasons = append(reasons, context.Reasons...)
	}
	reasons = uniqueSortedStrings(reasons)
	return FindingRiskContext{Score: score, Reasons: reasons}
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

func findingAttributeInt(attributes map[string]string, keys ...string) (int, bool) {
	for _, key := range keys {
		raw := strings.TrimSpace(attributes[key])
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			continue
		}
		return value, true
	}
	return 0, false
}

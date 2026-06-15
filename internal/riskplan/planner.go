package riskplan

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

type aggregatedCandidateSeed struct {
	CandidateSeed
	FindingIDs        map[string]struct{}
	RuleIDs           map[string]struct{}
	RuntimeIDs        map[string]struct{}
	ResourceURNs      map[string]struct{}
	Owners            map[string]struct{}
	OwnerSources      map[string]struct{}
	ControlRefs       map[string]struct{}
	Reasons           map[string]struct{}
	RiskFactors       map[string]*riskFactorAggregate
	MaxRiskScore      int
	ConfidenceScore   int
	LatestObservedAt  time.Time
	EvidenceRefCount  int
	EventCount        int
	GraphEvidenceRows int
}

type riskFactorAggregate struct {
	FactorID             string
	Category             string
	SeverityContribution string
	Count                int
	WeightTotal          int
	EvidenceRefs         map[string]struct{}
}

// DefaultGenerators returns the built-in action proposal generators.
func DefaultGenerators() []CandidateGenerator {
	return []CandidateGenerator{
		publicExposureGenerator{},
		privilegeGenerator{},
		vulnerabilityGenerator{},
		ownerAssignmentGenerator{},
		evidenceRefreshGenerator{},
	}
}

// TargetURNs returns candidate graph roots in seed priority order.
func TargetURNs(findings []*ports.FindingRecord, options Options) []string {
	options = normalizeOptions(options)
	seeds := actionPlanSeeds(options.TenantID, findings, options)
	targets := make([]string, 0, len(seeds))
	seen := map[string]struct{}{}
	for _, seed := range seeds {
		targetURN := strings.TrimSpace(seed.TargetURN)
		if targetURN == "" {
			continue
		}
		if _, ok := seen[targetURN]; ok {
			continue
		}
		seen[targetURN] = struct{}{}
		targets = append(targets, targetURN)
	}
	return targets
}

// Analyze builds a ranked plan from already-loaded finding and graph context.
func Analyze(findings []*ports.FindingRecord, options Options) Plan {
	options = normalizeOptions(options)
	seeds := actionPlanSeeds(options.TenantID, findings, options)
	candidates := actionPlanCandidates(findings, seeds, options)
	simulatedCount := 0
	unscoredCount := 0
	for _, candidate := range candidates {
		if candidate.SimulationStatus == SimulationStatusSimulated {
			simulatedCount++
		} else {
			unscoredCount++
		}
	}
	plan := Plan{
		TenantID:                strings.TrimSpace(options.TenantID),
		RuntimeIDs:              append([]string(nil), options.RuntimeIDs...),
		GeneratedAt:             options.Now.UTC().Format(time.RFC3339Nano),
		ModelVersion:            ModelVersion,
		TotalFindings:           countFindings(findings),
		CandidateSeedCount:      len(seeds),
		TotalCandidates:         len(candidates),
		SimulatedCandidateCount: simulatedCount,
		UnscoredCandidateCount:  unscoredCount,
		ActionCandidates:        candidates,
	}
	if len(options.PreviousCandidates) > 0 {
		diff := DiffCandidates(options.PreviousCandidates, candidates)
		plan.Diff = &diff
	}
	return plan
}

// DecodeCandidates decodes prior candidates from a JSON report payload.
func DecodeCandidates(content []byte) ([]Candidate, error) {
	if len(content) == 0 {
		return nil, nil
	}
	var candidates []Candidate
	if err := json.Unmarshal(content, &candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}

func normalizeOptions(options Options) Options {
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.CandidateLimit <= 0 {
		options.CandidateLimit = DefaultCandidateLimit
	}
	if options.CandidateLimit > MaxCandidateLimit {
		options.CandidateLimit = MaxCandidateLimit
	}
	if options.SeedLimit <= 0 {
		options.SeedLimit = MaxSimulationSeedLimit
	}
	if options.SeedLimit > MaxSimulationSeedLimit {
		options.SeedLimit = MaxSimulationSeedLimit
	}
	options.TenantID = strings.TrimSpace(options.TenantID)
	options.RuntimeIDs = normalizeStringSlice(options.RuntimeIDs)
	if options.GraphNeighborhoods == nil {
		options.GraphNeighborhoods = map[string]*ports.EntityNeighborhood{}
	}
	if len(options.Generators) == 0 {
		options.Generators = DefaultGenerators()
	}
	return options
}

func actionPlanSeeds(tenantID string, findings []*ports.FindingRecord, options Options) []aggregatedCandidateSeed {
	byID := map[string]*aggregatedCandidateSeed{}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		context := findinganalysis.AnalyzeFindingRiskContext(finding, options.Now)
		for _, generator := range options.Generators {
			if generator == nil {
				continue
			}
			for _, seed := range generator.Generate(CandidateGeneratorInput{
				TenantID:    tenantID,
				Finding:     finding,
				RiskContext: context,
				Now:         options.Now,
			}) {
				seed = normalizeCandidateSeed(seed)
				if seed.TargetURN == "" {
					continue
				}
				id := strings.TrimSpace(seed.ID)
				if id == "" {
					id = seed.ActionType + "|" + seed.TargetURN
				}
				entry := byID[id]
				if entry == nil {
					entry = newAggregatedSeed(id, seed)
					byID[id] = entry
				}
				entry.addFinding(finding, context, seed)
			}
		}
	}
	seeds := make([]aggregatedCandidateSeed, 0, len(byID))
	for _, seed := range byID {
		seeds = append(seeds, *seed)
	}
	slices.SortFunc(seeds, compareActionSeeds)
	if len(seeds) > options.SeedLimit {
		seeds = seeds[:options.SeedLimit]
	}
	return seeds
}

func normalizeCandidateSeed(seed CandidateSeed) CandidateSeed {
	seed.ID = strings.TrimSpace(seed.ID)
	seed.Title = strings.TrimSpace(seed.Title)
	seed.ActionType = strings.TrimSpace(seed.ActionType)
	seed.ScenarioType = strings.TrimSpace(seed.ScenarioType)
	seed.TargetURN = strings.TrimSpace(seed.TargetURN)
	seed.Reasons = normalizeStringSlice(seed.Reasons)
	return seed
}

func newAggregatedSeed(id string, seed CandidateSeed) *aggregatedCandidateSeed {
	seed.ID = id
	return &aggregatedCandidateSeed{
		CandidateSeed: seed,
		FindingIDs:    map[string]struct{}{},
		RuleIDs:       map[string]struct{}{},
		RuntimeIDs:    map[string]struct{}{},
		ResourceURNs:  map[string]struct{}{},
		Owners:        map[string]struct{}{},
		OwnerSources:  map[string]struct{}{},
		ControlRefs:   map[string]struct{}{},
		Reasons:       map[string]struct{}{},
		RiskFactors:   map[string]*riskFactorAggregate{},
	}
}

func (s *aggregatedCandidateSeed) addFinding(finding *ports.FindingRecord, context findinganalysis.FindingRiskContext, seed CandidateSeed) {
	addStringSetValue(s.FindingIDs, finding.ID)
	addStringSetValue(s.RuleIDs, finding.RuleID)
	addStringSetValue(s.RuntimeIDs, finding.RuntimeID)
	for _, resourceURN := range finding.ResourceURNs {
		addStringSetValue(s.ResourceURNs, resourceURN)
	}
	if primary := primaryResourceURN(finding); primary != "" {
		addStringSetValue(s.ResourceURNs, primary)
	}
	if owner, source := findingOwner(finding); owner != "" {
		addStringSetValue(s.Owners, owner)
		addStringSetValue(s.OwnerSources, source)
	}
	for _, controlRef := range finding.ControlRefs {
		normalized, key := normalizeControlRef(controlRef)
		if key == "" {
			continue
		}
		addStringSetValue(s.ControlRefs, normalized.FrameworkName+":"+normalized.ControlID)
	}
	for _, reason := range seed.Reasons {
		addStringSetValue(s.Reasons, reason)
	}
	for _, reason := range append(append([]string{}, finding.RiskReasons...), context.Reasons...) {
		addStringSetValue(s.Reasons, reason)
	}
	for _, factor := range append(append([]ports.FindingRiskFactor{}, finding.RiskFactors...), context.Factors...) {
		s.addRiskFactor(factor)
	}
	riskScore := finding.RiskScore
	if riskScore == 0 {
		riskScore = context.Score
	}
	if riskScore > s.MaxRiskScore {
		s.MaxRiskScore = riskScore
	}
	confidenceScore := finding.ConfidenceScore
	if confidenceScore == 0 {
		confidenceScore = context.ConfidenceScore
	}
	if confidenceScore > s.ConfidenceScore {
		s.ConfidenceScore = confidenceScore
	}
	if finding.LastObservedAt.After(s.LatestObservedAt) {
		s.LatestObservedAt = finding.LastObservedAt
	}
	s.EventCount += len(finding.EventIDs)
	s.GraphEvidenceRows += len(finding.GraphEvidenceRows)
}

func (s *aggregatedCandidateSeed) addRiskFactor(factor ports.FindingRiskFactor) {
	factorID := strings.TrimSpace(factor.FactorID)
	if factorID == "" {
		return
	}
	entry := s.RiskFactors[factorID]
	if entry == nil {
		entry = &riskFactorAggregate{
			FactorID:             factorID,
			Category:             strings.TrimSpace(factor.Category),
			SeverityContribution: strings.TrimSpace(factor.SeverityContribution),
			EvidenceRefs:         map[string]struct{}{},
		}
		s.RiskFactors[factorID] = entry
	}
	entry.Count++
	entry.WeightTotal += factor.Weight
	for _, ref := range factor.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			entry.EvidenceRefs[strings.TrimSpace(ref)] = struct{}{}
			s.EvidenceRefCount++
		}
	}
}

func actionPlanCandidates(findings []*ports.FindingRecord, seeds []aggregatedCandidateSeed, options Options) []Candidate {
	candidates := make([]Candidate, 0, len(seeds))
	for _, seed := range seeds {
		report := findinganalysis.RiskDeltaSimulationReport{}
		status := SimulationStatusUnsupported
		if seed.SimulationSupported {
			report = findinganalysis.SimulateRiskDelta(findings, findinganalysis.RiskDeltaSimulationOptions{
				ScenarioType:       seed.ScenarioType,
				TargetURN:          seed.TargetURN,
				Limit:              10,
				GraphNeighborhoods: options.GraphNeighborhoods,
				Now:                options.Now,
			})
			if report.RiskScoreReduction <= 0 && report.AttackPathScoreReduction <= 0 && report.AttackPathCountReduction <= 0 {
				status = SimulationStatusNoExpectedRisk
				if !options.IncludeUnscored {
					continue
				}
			} else {
				status = SimulationStatusSimulated
			}
		} else if !options.IncludeUnscored {
			continue
		}
		ownership := ownershipForSeed(seed)
		effort := effortForAction(seed.ActionType)
		evidence := evidenceForSeed(seed, options.Now)
		outcome := outcomeLearningForTarget(seed.TargetURN, options.GraphNeighborhoods)
		breakdown := scoreBreakdown(seed, report, status, effort, ownership, outcome)
		candidate := Candidate{
			CandidateIdentity: CandidateIdentity{
				ID:               actionCandidateID(seed),
				Title:            seed.Title,
				ActionType:       seed.ActionType,
				ScenarioType:     seed.ScenarioType,
				TargetURN:        seed.TargetURN,
				Owner:            ownership.Owner,
				RiskLevel:        riskLevel(seed.MaxRiskScore),
				SimulationStatus: status,
			},
			CandidateScoring: CandidateScoring{
				PriorityScore:                    breakdown.Total,
				ScoreBreakdown:                   breakdown,
				ConfidenceScore:                  seed.ConfidenceScore,
				ExpectedRiskScoreReduction:       report.RiskScoreReduction,
				ExpectedAttackPathScoreReduction: report.AttackPathScoreReduction,
				ExpectedAttackPathCountReduction: report.AttackPathCountReduction,
				ExpectedReduction: ExpectedReduction{
					RiskScore:       report.RiskScoreReduction,
					AttackPathScore: report.AttackPathScoreReduction,
					AttackPathCount: report.AttackPathCountReduction,
				},
				BeforeRiskScore: report.Before.TotalRiskScore,
				AfterRiskScore:  report.After.TotalRiskScore,
			},
			CandidateReferences: CandidateReferences{
				FindingIDs:   sortedStringSetValues(seed.FindingIDs),
				RuleIDs:      sortedStringSetValues(seed.RuleIDs),
				RuntimeIDs:   sortedStringSetValues(seed.RuntimeIDs),
				ResourceURNs: sortedStringSetValues(seed.ResourceURNs),
				ControlRefs:  sortedStringSetValues(seed.ControlRefs),
				RiskFactors:  riskFactorSummaries(seed.RiskFactors),
				Reasons:      sortedStringSetValues(seed.Reasons),
			},
			CandidateExecution: CandidateExecution{
				Effort:          effort,
				Ownership:       ownership,
				Evidence:        evidence,
				OutcomeLearning: outcome,
			},
			RiskDelta: report,
		}
		candidates = append(candidates, candidate)
	}
	slices.SortFunc(candidates, compareCandidates)
	if len(candidates) > options.CandidateLimit {
		candidates = candidates[:options.CandidateLimit]
	}
	return candidates
}

func scoreBreakdown(seed aggregatedCandidateSeed, report findinganalysis.RiskDeltaSimulationReport, status string, effort Effort, ownership Ownership, outcome OutcomeLearning) ScoreBreakdown {
	breakdown := ScoreBreakdown{
		RiskReductionPoints:            report.RiskScoreReduction * 10,
		AttackPathScoreReductionPoints: report.AttackPathScoreReduction * 3,
		AttackPathCountReductionPoints: report.AttackPathCountReduction * 25,
		RiskContextPoints:              seed.MaxRiskScore,
		FindingCoveragePoints:          len(seed.FindingIDs) * 5,
		ConfidencePoints:               seed.ConfidenceScore / 5,
		OutcomePriorPoints:             outcome.PriorityAdjustment,
		EffortCostPoints:               effort.CostPoints,
	}
	if ownership.Missing {
		breakdown.OwnershipPenaltyPoints = 15
	}
	if status != SimulationStatusSimulated {
		breakdown.SimulationPenaltyPoints = 40
	}
	breakdown.Total = breakdown.RiskReductionPoints +
		breakdown.AttackPathScoreReductionPoints +
		breakdown.AttackPathCountReductionPoints +
		breakdown.RiskContextPoints +
		breakdown.FindingCoveragePoints +
		breakdown.ConfidencePoints +
		breakdown.OutcomePriorPoints -
		breakdown.EffortCostPoints -
		breakdown.OwnershipPenaltyPoints -
		breakdown.SimulationPenaltyPoints
	if breakdown.Total < 0 {
		breakdown.Total = 0
	}
	return breakdown
}

func effortForAction(actionType string) Effort {
	switch actionType {
	case findinganalysis.RiskDeltaScenarioRemovePublicExposure:
		return Effort{
			Level:             "medium",
			Estimate:          "hours",
			CostPoints:        20,
			ApprovalRequired:  true,
			ApprovalReason:    "network exposure changes can affect reachability",
			Reversible:        true,
			PrimaryConstraint: "change_window",
		}
	case findinganalysis.RiskDeltaScenarioRemovePrivilege:
		return Effort{
			Level:             "medium",
			Estimate:          "hours",
			CostPoints:        18,
			ApprovalRequired:  true,
			ApprovalReason:    "privilege changes can affect production access",
			Reversible:        true,
			PrimaryConstraint: "access_review",
		}
	case findinganalysis.RiskDeltaScenarioPatchVulnerability:
		return Effort{
			Level:             "medium",
			Estimate:          "hours",
			CostPoints:        15,
			ApprovalRequired:  false,
			Reversible:        true,
			PrimaryConstraint: "release_cycle",
		}
	case ActionTypeAssignOwner:
		return Effort{Level: "small", Estimate: "minutes", CostPoints: 5, ApprovalRequired: false, Reversible: true, PrimaryConstraint: "routing"}
	case ActionTypeRefreshEvidence:
		return Effort{Level: "small", Estimate: "minutes", CostPoints: 5, ApprovalRequired: false, Reversible: true, PrimaryConstraint: "connector_freshness"}
	default:
		return Effort{Level: "medium", Estimate: "hours", CostPoints: 15, ApprovalRequired: true, Reversible: true}
	}
}

func ownershipForSeed(seed aggregatedCandidateSeed) Ownership {
	owners := sortedStringSetValues(seed.Owners)
	sources := sortedStringSetValues(seed.OwnerSources)
	ownership := Ownership{
		Candidates: owners,
		Missing:    len(owners) == 0,
	}
	if len(owners) > 0 {
		ownership.Owner = owners[0]
	}
	if len(sources) > 0 {
		ownership.Source = sources[0]
	}
	return ownership
}

func evidenceForSeed(seed aggregatedCandidateSeed, now time.Time) EvidenceConfidence {
	evidence := EvidenceConfidence{
		ConfidenceScore: seed.ConfidenceScore,
		EvidenceRefs:    seed.EvidenceRefCount + seed.EventCount + seed.GraphEvidenceRows,
	}
	switch {
	case seed.LatestObservedAt.IsZero():
		evidence.Freshness = "unknown"
	case now.Sub(seed.LatestObservedAt) <= 7*24*time.Hour:
		evidence.Freshness = "current"
		evidence.LastObservedAt = seed.LatestObservedAt.UTC().Format(time.RFC3339Nano)
	case now.Sub(seed.LatestObservedAt) <= 30*24*time.Hour:
		evidence.Freshness = "aging"
		evidence.LastObservedAt = seed.LatestObservedAt.UTC().Format(time.RFC3339Nano)
	default:
		evidence.Freshness = "stale"
		evidence.LastObservedAt = seed.LatestObservedAt.UTC().Format(time.RFC3339Nano)
	}
	switch {
	case evidence.EvidenceRefs == 0 || seed.ConfidenceScore < 50:
		evidence.Status = "limited"
	case evidence.Freshness == "stale":
		evidence.Status = "stale"
	default:
		evidence.Status = "ready"
	}
	return evidence
}

func outcomeLearningForTarget(targetURN string, neighborhoods map[string]*ports.EntityNeighborhood) OutcomeLearning {
	targetURN = strings.TrimSpace(targetURN)
	learning := OutcomeLearning{Status: "no_prior_outcomes"}
	if targetURN == "" || len(neighborhoods) == 0 {
		return learning
	}
	seenActions := map[string]struct{}{}
	for _, neighborhood := range neighborhoods {
		if neighborhood == nil {
			continue
		}
		for _, node := range append(append([]*ports.NeighborhoodNode{}, neighborhood.Root), neighborhood.Neighbors...) {
			if node == nil {
				continue
			}
			if !strings.EqualFold(strings.TrimSpace(node.URN), targetURN) && strings.Contains(strings.ToLower(node.EntityType), "action") {
				seenActions[node.URN] = struct{}{}
			}
			if strings.Contains(strings.ToLower(node.EntityType), "outcome") {
				learning.PositiveOutcomeCount++
			}
		}
		for _, relation := range neighborhood.Relations {
			if relation == nil || !relationTouchesTarget(relation, targetURN) {
				continue
			}
			relationName := strings.ToLower(strings.TrimSpace(relation.Relation))
			if strings.Contains(relationName, "action") || strings.Contains(relationName, "remediat") || strings.Contains(relationName, "ticket") {
				addStringSetValue(seenActions, relation.FromURN)
				addStringSetValue(seenActions, relation.ToURN)
			}
			if relationOutcomePositive(relation) {
				learning.PositiveOutcomeCount++
			}
			if relationOutcomeNegative(relation) {
				learning.NegativeOutcomeCount++
			}
		}
	}
	learning.PriorActionCount = len(seenActions)
	learning.PriorityAdjustment = learning.PositiveOutcomeCount*10 - learning.NegativeOutcomeCount*15
	if learning.PriorActionCount > 0 || learning.PositiveOutcomeCount > 0 || learning.NegativeOutcomeCount > 0 {
		learning.Status = "learned_from_prior_outcomes"
	}
	return learning
}

func relationTouchesTarget(relation *ports.NeighborhoodRelation, targetURN string) bool {
	return strings.EqualFold(strings.TrimSpace(relation.FromURN), targetURN) || strings.EqualFold(strings.TrimSpace(relation.ToURN), targetURN)
}

func relationOutcomePositive(relation *ports.NeighborhoodRelation) bool {
	if relation == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(relation.Relation))
	if strings.Contains(value, "resolved") || strings.Contains(value, "completed") || strings.Contains(value, "succeeded") || strings.Contains(value, "effective") {
		return true
	}
	for key, attr := range relation.Attributes {
		combined := strings.ToLower(strings.TrimSpace(key + ":" + attr))
		if strings.Contains(combined, "success") || strings.Contains(combined, "resolved") || strings.Contains(combined, "effective") || strings.Contains(combined, "complete") {
			return true
		}
	}
	return false
}

func relationOutcomeNegative(relation *ports.NeighborhoodRelation) bool {
	if relation == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(relation.Relation))
	if strings.Contains(value, "failed") || strings.Contains(value, "reverted") || strings.Contains(value, "regressed") {
		return true
	}
	for key, attr := range relation.Attributes {
		combined := strings.ToLower(strings.TrimSpace(key + ":" + attr))
		if strings.Contains(combined, "failed") || strings.Contains(combined, "reverted") || strings.Contains(combined, "regressed") {
			return true
		}
	}
	return false
}

func riskFactorSummaries(factors map[string]*riskFactorAggregate) []RiskFactorSummary {
	entries := make([]*riskFactorAggregate, 0, len(factors))
	for _, factor := range factors {
		entries = append(entries, factor)
	}
	slices.SortFunc(entries, func(left *riskFactorAggregate, right *riskFactorAggregate) int {
		switch {
		case left.WeightTotal > right.WeightTotal:
			return -1
		case left.WeightTotal < right.WeightTotal:
			return 1
		case left.Count > right.Count:
			return -1
		case left.Count < right.Count:
			return 1
		case left.FactorID < right.FactorID:
			return -1
		case left.FactorID > right.FactorID:
			return 1
		default:
			return 0
		}
	})
	values := make([]RiskFactorSummary, 0, len(entries))
	for _, entry := range entries {
		values = append(values, RiskFactorSummary{
			FactorID:             entry.FactorID,
			Category:             entry.Category,
			SeverityContribution: entry.SeverityContribution,
			Count:                entry.Count,
			WeightTotal:          entry.WeightTotal,
			EvidenceRefs:         sortedStringSetValues(entry.EvidenceRefs),
		})
	}
	return values
}

func compareActionSeeds(left aggregatedCandidateSeed, right aggregatedCandidateSeed) int {
	switch {
	case left.MaxRiskScore > right.MaxRiskScore:
		return -1
	case left.MaxRiskScore < right.MaxRiskScore:
		return 1
	case len(left.FindingIDs) > len(right.FindingIDs):
		return -1
	case len(left.FindingIDs) < len(right.FindingIDs):
		return 1
	case left.SimulationSupported != right.SimulationSupported:
		if left.SimulationSupported {
			return -1
		}
		return 1
	case left.ActionType < right.ActionType:
		return -1
	case left.ActionType > right.ActionType:
		return 1
	case left.TargetURN < right.TargetURN:
		return -1
	case left.TargetURN > right.TargetURN:
		return 1
	default:
		return 0
	}
}

func compareCandidates(left Candidate, right Candidate) int {
	switch {
	case left.SimulationStatus != right.SimulationStatus:
		if left.SimulationStatus == SimulationStatusSimulated {
			return -1
		}
		if right.SimulationStatus == SimulationStatusSimulated {
			return 1
		}
	case left.PriorityScore > right.PriorityScore:
		return -1
	case left.PriorityScore < right.PriorityScore:
		return 1
	case left.ExpectedRiskScoreReduction > right.ExpectedRiskScoreReduction:
		return -1
	case left.ExpectedRiskScoreReduction < right.ExpectedRiskScoreReduction:
		return 1
	case left.ExpectedAttackPathScoreReduction > right.ExpectedAttackPathScoreReduction:
		return -1
	case left.ExpectedAttackPathScoreReduction < right.ExpectedAttackPathScoreReduction:
		return 1
	case left.ID < right.ID:
		return -1
	case left.ID > right.ID:
		return 1
	default:
		return 0
	}
	return 0
}

func actionCandidateID(seed aggregatedCandidateSeed) string {
	value := strings.ToLower(seed.ActionType + "-" + seed.TargetURN)
	value = strings.NewReplacer(":", "-", "/", "-", "#", "-", "_", "-").Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "risk-action"
	}
	return value
}

func riskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func countFindings(findings []*ports.FindingRecord) int {
	count := 0
	for _, finding := range findings {
		if finding != nil {
			count++
		}
	}
	return count
}

func normalizeControlRef(value ports.FindingControlRef) (ports.FindingControlRef, string) {
	normalized := ports.FindingControlRef{
		FrameworkName: strings.TrimSpace(value.FrameworkName),
		ControlID:     strings.TrimSpace(value.ControlID),
	}
	if normalized.FrameworkName == "" || normalized.ControlID == "" {
		return ports.FindingControlRef{}, ""
	}
	return normalized, normalized.FrameworkName + "|" + normalized.ControlID
}

func primaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if value := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); value != "" {
		return value
	}
	primaryActorURN := strings.TrimSpace(finding.Attributes["primary_actor_urn"])
	for _, resourceURN := range finding.ResourceURNs {
		trimmed := strings.TrimSpace(resourceURN)
		if trimmed == "" || trimmed == primaryActorURN {
			continue
		}
		return trimmed
	}
	return ""
}

func findingOwner(finding *ports.FindingRecord) (string, string) {
	if finding == nil {
		return "", ""
	}
	if owner := strings.TrimSpace(finding.Assignee); owner != "" {
		return owner, "finding_assignee"
	}
	for _, key := range []string{"owner", "team", "service_owner", "resource_owner", "repo_owner"} {
		if owner := strings.TrimSpace(finding.Attributes[key]); owner != "" {
			return owner, "attribute:" + key
		}
	}
	return "", ""
}

func tenantIDFromURN(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func firstTenantScopedURN(tenantID string, values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if tenantIDFromURN(trimmed) == strings.TrimSpace(tenantID) {
			return trimmed
		}
	}
	return ""
}

func normalizeStringSlice(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	slices.Sort(normalized)
	return normalized
}

func addStringSetValue(values map[string]struct{}, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		values[trimmed] = struct{}{}
	}
}

func sortedStringSetValues(values map[string]struct{}) []string {
	if len(values) == 0 {
		return []string{}
	}
	sorted := make([]string, 0, len(values))
	for value := range values {
		sorted = append(sorted, value)
	}
	slices.Sort(sorted)
	return sorted
}

func stringSetContains(values map[string]struct{}, value string) bool {
	_, ok := values[strings.TrimSpace(value)]
	return ok
}

func stringSetContainsPrefix(values map[string]struct{}, prefix string) bool {
	for value := range values {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) {
			return true
		}
	}
	return false
}

func attributePresent(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(attributes[key]) != "" {
			return true
		}
	}
	return false
}

func attributeBool(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(attributes[key])) {
		case "1", "true", "yes", "y", "enabled", "public", "external", "internet", "admin", "privileged":
			return true
		}
	}
	return false
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(needle))) {
			return true
		}
	}
	return false
}

func parseFloatAttribute(attributes map[string]string, keys ...string) float64 {
	for _, key := range keys {
		raw := strings.TrimSpace(attributes[key])
		if raw == "" {
			continue
		}
		value, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			return value
		}
	}
	return 0
}

package reports

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

const (
	reportParameterCandidateLimit      = "candidate_limit"
	defaultRiskActionCandidateLimit    = 10
	maxRiskActionCandidateLimit        = 25
	maxRiskActionSimulationSeedLimit   = 50
	riskActionTypeRemovePublicExposure = "remove_public_exposure"
	riskActionTypeRemovePrivilege      = "remove_privilege"
	riskActionTypePatchVulnerability   = "patch_vulnerability"
)

type riskActionCandidateSeed struct {
	ID              string
	Title           string
	ActionType      string
	ScenarioType    string
	TargetURN       string
	FindingIDs      map[string]struct{}
	RuleIDs         map[string]struct{}
	RuntimeIDs      map[string]struct{}
	ResourceURNs    map[string]struct{}
	Owners          map[string]struct{}
	ControlRefs     map[string]struct{}
	Reasons         map[string]struct{}
	RiskFactors     map[string]*riskActionFactorSummary
	MaxRiskScore    int
	ConfidenceScore int
}

type riskActionFactorSummary struct {
	FactorID             string
	Category             string
	SeverityContribution string
	Count                int
	WeightTotal          int
	EvidenceRefs         map[string]struct{}
}

type riskActionCandidateOutput struct {
	ID                               string                                    `json:"id"`
	Title                            string                                    `json:"title"`
	ActionType                       string                                    `json:"action_type"`
	ScenarioType                     string                                    `json:"scenario_type"`
	TargetURN                        string                                    `json:"target_urn"`
	Owner                            string                                    `json:"owner,omitempty"`
	PriorityScore                    int                                       `json:"priority_score"`
	RiskLevel                        string                                    `json:"risk_level,omitempty"`
	ConfidenceScore                  int                                       `json:"confidence_score,omitempty"`
	ExpectedRiskScoreReduction       int                                       `json:"expected_risk_score_reduction"`
	ExpectedAttackPathScoreReduction int                                       `json:"expected_attack_path_score_reduction"`
	ExpectedAttackPathCountReduction int                                       `json:"expected_attack_path_count_reduction"`
	BeforeRiskScore                  int                                       `json:"before_risk_score"`
	AfterRiskScore                   int                                       `json:"after_risk_score"`
	FindingIDs                       []string                                  `json:"finding_ids,omitempty"`
	RuleIDs                          []string                                  `json:"rule_ids,omitempty"`
	RuntimeIDs                       []string                                  `json:"runtime_ids,omitempty"`
	ResourceURNs                     []string                                  `json:"resource_urns,omitempty"`
	ControlRefs                      []string                                  `json:"control_refs,omitempty"`
	RiskFactors                      []riskActionFactorOutput                  `json:"risk_factors,omitempty"`
	Reasons                          []string                                  `json:"reasons,omitempty"`
	RiskDelta                        findinganalysis.RiskDeltaSimulationReport `json:"risk_delta"`
}

type riskActionFactorOutput struct {
	FactorID             string   `json:"factor_id"`
	Category             string   `json:"category,omitempty"`
	SeverityContribution string   `json:"severity_contribution,omitempty"`
	Count                int      `json:"count"`
	WeightTotal          int      `json:"weight_total"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
}

func (s *Service) runRiskActionPlan(ctx context.Context, parameters map[string]string) (*structpb.Struct, error) {
	tenantID := strings.TrimSpace(parameters[reportParameterTenantID])
	if tenantID == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterTenantID)
	}
	runtimeIDs := normalizeRuntimeIDs(parameters[reportParameterRuntimeIDs])
	if len(runtimeIDs) == 0 {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterRuntimeIDs)
	}
	candidateLimit, err := normalizePositiveLimit(parameters[reportParameterCandidateLimit], defaultRiskActionCandidateLimit, maxRiskActionCandidateLimit, reportParameterCandidateLimit)
	if err != nil {
		return nil, err
	}
	resourceLimit, err := normalizePositiveLimit(parameters[reportParameterResourceLimit], defaultResourceEvidenceLimit, maxResourceEvidenceLimit, reportParameterResourceLimit)
	if err != nil {
		return nil, err
	}
	graphLimit, err := normalizePositiveLimit(parameters[reportParameterGraphLimit], defaultNeighborhoodEvidenceLimit, maxNeighborhoodEvidenceLimit, reportParameterGraphLimit)
	if err != nil {
		return nil, err
	}
	runtimeIDsCSV := strings.Join(runtimeIDs, ",")
	parameters[reportParameterRuntimeIDs] = runtimeIDsCSV
	parameters[reportParameterCandidateLimit] = strconv.Itoa(candidateLimit)
	parameters[reportParameterResourceLimit] = strconv.Itoa(resourceLimit)
	parameters[reportParameterGraphLimit] = strconv.Itoa(graphLimit)
	listRequest := ports.ListFindingsRequest{TenantID: tenantID, Order: ports.FindingOrderRiskScore}
	if len(runtimeIDs) == 1 {
		listRequest.RuntimeID = runtimeIDs[0]
	} else {
		listRequest.RuntimeIDs = runtimeIDs
	}
	findings, err := s.findingStore.ListFindings(ctx, listRequest)
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtimes %q: %w", tenantID, runtimeIDsCSV, err)
	}
	now := time.Now().UTC()
	seeds := riskActionPlanSeeds(tenantID, findings, now)
	graphEvidenceStatus := graphEvidenceStatusUnconfigured
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{}
	if s.graphStore != nil {
		graphEvidenceStatus = graphEvidenceStatusIncluded
		graphNeighborhoods, err = s.riskActionPlanGraphNeighborhoods(ctx, seeds, resourceLimit, graphLimit)
		if err != nil {
			return nil, err
		}
	}
	candidates := riskActionPlanCandidates(findings, seeds, graphNeighborhoods, candidateLimit, now)
	actionCandidates, err := jsonPayload(candidates)
	if err != nil {
		return nil, fmt.Errorf("build risk action plan candidate payload: %w", err)
	}
	result, err := structpb.NewStruct(map[string]any{
		reportParameterTenantID:       tenantID,
		reportParameterRuntimeIDs:     reportStringValues(runtimeIDs),
		reportParameterCandidateLimit: candidateLimit,
		reportParameterResourceLimit:  resourceLimit,
		reportParameterGraphLimit:     graphLimit,
		"total_findings":              len(findings),
		"candidate_seed_count":        len(seeds),
		"total_candidates":            len(candidates),
		"graph_evidence_status":       graphEvidenceStatus,
		"graph_neighborhood_count":    len(graphNeighborhoods),
		"action_candidates":           actionCandidates,
	})
	if err != nil {
		return nil, fmt.Errorf("build risk action plan report result: %w", err)
	}
	return result, nil
}

func riskActionPlanDefinition() *cerebrov1.ReportDefinition {
	return &cerebrov1.ReportDefinition{
		Id:          riskActionPlanReportID,
		Name:        riskActionPlanReportName,
		Description: "Rank next-best remediation actions by simulating expected risk and attack-path reduction from persisted findings and bounded graph neighborhoods without mutating stores.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterTenantID,
				Description: "Tenant identifier whose persisted findings should be planned.",
				Required:    true,
			},
			{
				Id:          reportParameterRuntimeIDs,
				Description: "Required comma-separated stored source runtime identifiers for action planning.",
				Required:    true,
			},
			{
				Id:          reportParameterCandidateLimit,
				Description: "Optional maximum number of ranked remediation candidates to return.",
				Required:    false,
			},
			{
				Id:          reportParameterResourceLimit,
				Description: "Optional maximum number of candidate target roots to include in simulation graph context.",
				Required:    false,
			},
			{
				Id:          reportParameterGraphLimit,
				Description: "Optional maximum neighborhood size to read for each candidate target root.",
				Required:    false,
			},
		},
	}
}

func riskActionPlanSeeds(tenantID string, findings []*ports.FindingRecord, now time.Time) []riskActionCandidateSeed {
	byID := map[string]*riskActionCandidateSeed{}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		context := findinganalysis.AnalyzeFindingRiskContext(finding, now)
		for _, actionType := range []string{riskActionTypeRemovePublicExposure, riskActionTypeRemovePrivilege, riskActionTypePatchVulnerability} {
			if !riskActionFindingSupportsAction(finding, context, actionType) {
				continue
			}
			targetURN := riskActionTargetURN(tenantID, finding, actionType)
			if targetURN == "" {
				continue
			}
			id := actionType + "|" + targetURN
			seed := byID[id]
			if seed == nil {
				seed = newRiskActionCandidateSeed(id, actionType, targetURN, finding)
				byID[id] = seed
			}
			seed.addFinding(finding, context)
		}
	}
	seeds := make([]riskActionCandidateSeed, 0, len(byID))
	for _, seed := range byID {
		seeds = append(seeds, *seed)
	}
	slices.SortFunc(seeds, compareRiskActionSeeds)
	if len(seeds) > maxRiskActionSimulationSeedLimit {
		seeds = seeds[:maxRiskActionSimulationSeedLimit]
	}
	return seeds
}

func newRiskActionCandidateSeed(id string, actionType string, targetURN string, finding *ports.FindingRecord) *riskActionCandidateSeed {
	return &riskActionCandidateSeed{
		ID:           id,
		Title:        riskActionTitle(actionType, riskActionTargetLabel(finding, targetURN)),
		ActionType:   actionType,
		ScenarioType: actionType,
		TargetURN:    targetURN,
		FindingIDs:   map[string]struct{}{},
		RuleIDs:      map[string]struct{}{},
		RuntimeIDs:   map[string]struct{}{},
		ResourceURNs: map[string]struct{}{},
		Owners:       map[string]struct{}{},
		ControlRefs:  map[string]struct{}{},
		Reasons:      map[string]struct{}{},
		RiskFactors:  map[string]*riskActionFactorSummary{},
	}
}

func (s *riskActionCandidateSeed) addFinding(finding *ports.FindingRecord, context findinganalysis.FindingRiskContext) {
	addStringSetValue(s.FindingIDs, finding.ID)
	addStringSetValue(s.RuleIDs, finding.RuleID)
	addStringSetValue(s.RuntimeIDs, finding.RuntimeID)
	for _, resourceURN := range finding.ResourceURNs {
		addStringSetValue(s.ResourceURNs, resourceURN)
	}
	if primary := primaryResourceURN(finding); primary != "" {
		addStringSetValue(s.ResourceURNs, primary)
	}
	if owner := riskActionFindingOwner(finding); owner != "" {
		addStringSetValue(s.Owners, owner)
	}
	for _, controlRef := range finding.ControlRefs {
		normalized, key := normalizeControlRef(controlRef)
		if key == "" {
			continue
		}
		addStringSetValue(s.ControlRefs, normalized.FrameworkName+":"+normalized.ControlID)
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
}

func (s *riskActionCandidateSeed) addRiskFactor(factor ports.FindingRiskFactor) {
	factorID := strings.TrimSpace(factor.FactorID)
	if factorID == "" {
		return
	}
	entry := s.RiskFactors[factorID]
	if entry == nil {
		entry = &riskActionFactorSummary{
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
		addStringSetValue(entry.EvidenceRefs, ref)
	}
}

func (s *Service) riskActionPlanGraphNeighborhoods(ctx context.Context, seeds []riskActionCandidateSeed, resourceLimit int, graphLimit int) (map[string]*ports.EntityNeighborhood, error) {
	neighborhoods := map[string]*ports.EntityNeighborhood{}
	seen := map[string]struct{}{}
	for _, seed := range seeds {
		if len(seen) >= resourceLimit {
			break
		}
		targetURN := strings.TrimSpace(seed.TargetURN)
		if targetURN == "" {
			continue
		}
		if _, ok := seen[targetURN]; ok {
			continue
		}
		seen[targetURN] = struct{}{}
		neighborhood, err := s.graphStore.GetEntityNeighborhood(ctx, targetURN, graphLimit)
		switch {
		case err == nil:
			if neighborhood == nil {
				neighborhood = &ports.EntityNeighborhood{}
			}
			neighborhoods[targetURN] = neighborhood
		case errors.Is(err, ports.ErrGraphEntityNotFound):
			continue
		default:
			return nil, fmt.Errorf("load risk action plan graph neighborhood for %q: %w", targetURN, err)
		}
	}
	return neighborhoods, nil
}

func riskActionPlanCandidates(findings []*ports.FindingRecord, seeds []riskActionCandidateSeed, graphNeighborhoods map[string]*ports.EntityNeighborhood, limit int, now time.Time) []riskActionCandidateOutput {
	candidates := make([]riskActionCandidateOutput, 0, len(seeds))
	for _, seed := range seeds {
		report := findinganalysis.SimulateRiskDelta(findings, findinganalysis.RiskDeltaSimulationOptions{
			ScenarioType:       seed.ScenarioType,
			TargetURN:          seed.TargetURN,
			Limit:              10,
			GraphNeighborhoods: graphNeighborhoods,
			Now:                now,
		})
		if report.RiskScoreReduction <= 0 && report.AttackPathScoreReduction <= 0 && report.AttackPathCountReduction <= 0 {
			continue
		}
		candidates = append(candidates, riskActionCandidateOutput{
			ID:                               riskActionCandidateID(seed),
			Title:                            seed.Title,
			ActionType:                       seed.ActionType,
			ScenarioType:                     seed.ScenarioType,
			TargetURN:                        seed.TargetURN,
			Owner:                            firstSortedSetValue(seed.Owners),
			PriorityScore:                    riskActionPriorityScore(seed, report),
			RiskLevel:                        reportRiskLevel(seed.MaxRiskScore),
			ConfidenceScore:                  seed.ConfidenceScore,
			ExpectedRiskScoreReduction:       report.RiskScoreReduction,
			ExpectedAttackPathScoreReduction: report.AttackPathScoreReduction,
			ExpectedAttackPathCountReduction: report.AttackPathCountReduction,
			BeforeRiskScore:                  report.Before.TotalRiskScore,
			AfterRiskScore:                   report.After.TotalRiskScore,
			FindingIDs:                       sortedStringSetValues(seed.FindingIDs),
			RuleIDs:                          sortedStringSetValues(seed.RuleIDs),
			RuntimeIDs:                       sortedStringSetValues(seed.RuntimeIDs),
			ResourceURNs:                     sortedStringSetValues(seed.ResourceURNs),
			ControlRefs:                      sortedStringSetValues(seed.ControlRefs),
			RiskFactors:                      riskActionFactorOutputs(seed.RiskFactors),
			Reasons:                          sortedStringSetValues(seed.Reasons),
			RiskDelta:                        report,
		})
	}
	slices.SortFunc(candidates, compareRiskActionCandidates)
	if limit > 0 && len(candidates) > limit {
		candidates = candidates[:limit]
	}
	return candidates
}

func riskActionFindingSupportsAction(finding *ports.FindingRecord, context findinganalysis.FindingRiskContext, actionType string) bool {
	attributes := finding.Attributes
	reasons := map[string]struct{}{}
	for _, reason := range append(append([]string{}, finding.RiskReasons...), context.Reasons...) {
		addStringSetValue(reasons, reason)
	}
	for _, factor := range append(append([]ports.FindingRiskFactor{}, finding.RiskFactors...), context.Factors...) {
		addStringSetValue(reasons, factor.FactorID)
	}
	action := strings.ToLower(strings.TrimSpace(attributes["action"]))
	switch actionType {
	case riskActionTypeRemovePublicExposure:
		return stringSetContains(reasons, "external_exposure") ||
			riskActionAttributeBool(attributes, "internet_exposed", "public", "externally_exposed", "external_exposure", "is_public", "is_internet_facing", "reachable", "directly_reachable", "internet_reachable", "can_reach") ||
			riskActionContainsAny(action, "public", "expose", "internet", "can_reach")
	case riskActionTypeRemovePrivilege:
		return stringSetContains(reasons, "privileged_actor") ||
			stringSetContains(reasons, "privilege_or_control_plane") ||
			riskActionAttributeBool(attributes, "privileged", "actor_privileged", "admin", "is_admin", "has_admin", "can_admin", "admin_reachable", "privileged_access", "has_admin_path") ||
			riskActionContainsAny(action, "can_admin", "can_assume", "can_impersonate", "administratoraccess")
	case riskActionTypePatchVulnerability:
		return stringSetContains(reasons, "known_exploited") ||
			stringSetContains(reasons, "epss_high") ||
			stringSetContains(reasons, "epss_elevated") ||
			stringSetContains(reasons, "exploit_available") ||
			stringSetContains(reasons, "cvss_critical") ||
			stringSetContains(reasons, "cvss_high") ||
			riskActionSetContainsPrefix(reasons, "exploit_maturity:") ||
			riskActionAttributePresent(attributes, "vulnerability_urn", "package_urn", "image_urn", "cve", "cve_id", "vulnerability_id", "package", "purl", "cvss_score", "cvss", "epss_score", "epss") ||
			riskActionAttributeBool(attributes, "is_kev", "kev", "known_exploited", "known_exploited_vulnerability", "exploit_available", "public_exploit", "weaponized_exploit")
	default:
		return false
	}
}

func riskActionTargetURN(tenantID string, finding *ports.FindingRecord, actionType string) string {
	attributes := finding.Attributes
	switch actionType {
	case riskActionTypeRemovePublicExposure:
		return firstTenantScopedURN(tenantID, attributes["exposed_resource_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	case riskActionTypeRemovePrivilege:
		return firstTenantScopedURN(tenantID, attributes["principal_urn"], attributes["identity_urn"], attributes["actor_urn"], attributes["permission_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	case riskActionTypePatchVulnerability:
		return firstTenantScopedURN(tenantID, attributes["vulnerability_urn"], attributes["package_urn"], attributes["image_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	default:
		return ""
	}
}

func firstTenantScopedURN(tenantID string, values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if tenantIDFromRiskDeltaTargetURN(trimmed) == strings.TrimSpace(tenantID) {
			return trimmed
		}
	}
	return ""
}

func riskActionTitle(actionType string, targetLabel string) string {
	switch actionType {
	case riskActionTypeRemovePublicExposure:
		return "Remove public exposure from " + targetLabel
	case riskActionTypeRemovePrivilege:
		return "Remove excess privilege from " + targetLabel
	case riskActionTypePatchVulnerability:
		return "Patch exploitable vulnerability on " + targetLabel
	default:
		return "Reduce risk on " + targetLabel
	}
}

func riskActionTargetLabel(finding *ports.FindingRecord, targetURN string) string {
	for _, value := range []string{
		finding.Attributes["resource_label"],
		finding.Attributes["resource_name"],
		finding.Attributes["asset_name"],
		finding.Attributes["repository"],
		finding.Attributes["package"],
		finding.Title,
	} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	targetURN = strings.TrimSpace(targetURN)
	if targetURN == "" {
		return "target"
	}
	parts := strings.FieldsFunc(targetURN, func(r rune) bool {
		return r == ':' || r == '/' || r == '#'
	})
	if len(parts) == 0 {
		return targetURN
	}
	return parts[len(parts)-1]
}

func riskActionFindingOwner(finding *ports.FindingRecord) string {
	for _, value := range []string{
		finding.Assignee,
		finding.Attributes["owner"],
		finding.Attributes["team"],
		finding.Attributes["service_owner"],
		finding.Attributes["resource_owner"],
		finding.Attributes["repo_owner"],
	} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func riskActionPriorityScore(seed riskActionCandidateSeed, report findinganalysis.RiskDeltaSimulationReport) int {
	return report.RiskScoreReduction*10 +
		report.AttackPathScoreReduction*3 +
		report.AttackPathCountReduction*25 +
		seed.MaxRiskScore +
		len(seed.FindingIDs)*5
}

func riskActionCandidateID(seed riskActionCandidateSeed) string {
	value := strings.ToLower(seed.ActionType + "-" + seed.TargetURN)
	value = strings.NewReplacer(":", "-", "/", "-", "#", "-", "_", "-").Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "risk-action"
	}
	return value
}

func riskActionFactorOutputs(factors map[string]*riskActionFactorSummary) []riskActionFactorOutput {
	entries := make([]*riskActionFactorSummary, 0, len(factors))
	for _, factor := range factors {
		entries = append(entries, factor)
	}
	slices.SortFunc(entries, func(left *riskActionFactorSummary, right *riskActionFactorSummary) int {
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
	values := make([]riskActionFactorOutput, 0, len(entries))
	for _, entry := range entries {
		values = append(values, riskActionFactorOutput{
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

func compareRiskActionSeeds(left riskActionCandidateSeed, right riskActionCandidateSeed) int {
	switch {
	case left.MaxRiskScore > right.MaxRiskScore:
		return -1
	case left.MaxRiskScore < right.MaxRiskScore:
		return 1
	case len(left.FindingIDs) > len(right.FindingIDs):
		return -1
	case len(left.FindingIDs) < len(right.FindingIDs):
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

func compareRiskActionCandidates(left riskActionCandidateOutput, right riskActionCandidateOutput) int {
	switch {
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
}

func riskActionAttributePresent(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(attributes[key]) != "" {
			return true
		}
	}
	return false
}

func riskActionAttributeBool(attributes map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(attributes[key])) {
		case "1", "true", "yes", "y", "enabled", "public", "external", "internet", "admin", "privileged":
			return true
		}
	}
	return false
}

func riskActionContainsAny(value string, needles ...string) bool {
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

func riskActionSetContainsPrefix(values map[string]struct{}, prefix string) bool {
	for value := range values {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) {
			return true
		}
	}
	return false
}

func stringSetContains(values map[string]struct{}, value string) bool {
	_, ok := values[strings.TrimSpace(value)]
	return ok
}

func addStringSetValue(values map[string]struct{}, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		values[trimmed] = struct{}{}
	}
}

func firstSortedSetValue(values map[string]struct{}) string {
	sorted := sortedStringSetValues(values)
	if len(sorted) == 0 {
		return ""
	}
	return sorted[0]
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

package findings

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	RiskDeltaScenarioCompromiseIdentity   = "compromise_identity"
	RiskDeltaScenarioPatchVulnerability   = "patch_vulnerability"
	RiskDeltaScenarioRemovePrivilege      = "remove_privilege"
	RiskDeltaScenarioRemovePublicExposure = "remove_public_exposure"
)

type RiskDeltaSimulationOptions struct {
	ScenarioType       string
	TargetURN          string
	Limit              int
	GraphNeighborhoods map[string]*ports.EntityNeighborhood
	Now                time.Time
	RiskScoringConfig  *ports.RiskScoringConfig
}

type RiskDeltaSimulationReport struct {
	ScenarioType             string                   `json:"scenario_type"`
	TargetURN                string                   `json:"target_urn"`
	Before                   RiskDeltaSnapshot        `json:"before"`
	After                    RiskDeltaSnapshot        `json:"after"`
	RiskScoreChange          int                      `json:"risk_score_change"`
	AttackPathScoreChange    int                      `json:"attack_path_score_change"`
	AttackPathCountChange    int                      `json:"attack_path_count_change"`
	RiskScoreReduction       int                      `json:"risk_score_reduction"`
	AttackPathScoreReduction int                      `json:"attack_path_score_reduction"`
	AttackPathCountReduction int                      `json:"attack_path_count_reduction"`
	AffectedFindings         []RiskDeltaFindingImpact `json:"affected_findings"`
	AddedAttackPaths         []FindingAttackPath      `json:"added_attack_paths,omitempty"`
	RemovedAttackPaths       []FindingAttackPath      `json:"removed_attack_paths,omitempty"`
	RemainingAttackPaths     []FindingAttackPath      `json:"remaining_attack_paths,omitempty"`
	Reasons                  []string                 `json:"reasons,omitempty"`
}

type RiskDeltaSnapshot struct {
	FindingCount         int `json:"finding_count"`
	TotalRiskScore       int `json:"total_risk_score"`
	AttackPathCount      int `json:"attack_path_count"`
	TotalAttackPathScore int `json:"total_attack_path_score"`
}

type RiskDeltaFindingImpact struct {
	FindingID       string   `json:"finding_id"`
	RuleID          string   `json:"rule_id,omitempty"`
	ResourceURNs    []string `json:"resource_urns,omitempty"`
	BeforeRiskScore int      `json:"before_risk_score"`
	AfterRiskScore  int      `json:"after_risk_score"`
	Reduction       int      `json:"reduction"`
	AddedReasons    []string `json:"added_reasons,omitempty"`
	RemovedReasons  []string `json:"removed_reasons,omitempty"`
}

func SimulateRiskDelta(records []*ports.FindingRecord, options RiskDeltaSimulationOptions) RiskDeltaSimulationReport {
	scenarioType := strings.TrimSpace(options.ScenarioType)
	targetURN := strings.TrimSpace(options.TargetURN)
	limit := options.Limit
	if limit <= 0 {
		limit = 10
	}
	beforeRecords := cloneRiskDeltaFindings(records)
	beforeNeighborhoods := cloneRiskDeltaNeighborhoods(options.GraphNeighborhoods)
	beforeAllPaths := AnalyzeFindingAttackPaths(beforeRecords, beforeNeighborhoods, FindingExposureAnalysisOptions{GraphNeighborhoods: beforeNeighborhoods, RiskScoringConfig: options.RiskScoringConfig})
	before := riskDeltaSnapshot(beforeRecords, beforeAllPaths, options.Now, options.RiskScoringConfig)

	afterRecords, findingReasons := applyRiskDeltaFindingScenario(beforeRecords, scenarioType, targetURN, beforeNeighborhoods)
	afterNeighborhoods, graphReasons := applyRiskDeltaGraphScenario(beforeNeighborhoods, scenarioType, targetURN)
	afterAllPaths := AnalyzeFindingAttackPaths(afterRecords, afterNeighborhoods, FindingExposureAnalysisOptions{GraphNeighborhoods: afterNeighborhoods, RiskScoringConfig: options.RiskScoringConfig})
	afterPaths := limitRiskDeltaAttackPaths(afterAllPaths, limit)
	after := riskDeltaSnapshot(afterRecords, afterAllPaths, options.Now, options.RiskScoringConfig)

	riskScoreReduction := before.TotalRiskScore - after.TotalRiskScore
	attackPathScoreReduction := before.TotalAttackPathScore - after.TotalAttackPathScore
	attackPathCountReduction := before.AttackPathCount - after.AttackPathCount
	return RiskDeltaSimulationReport{
		ScenarioType:             scenarioType,
		TargetURN:                targetURN,
		Before:                   before,
		After:                    after,
		RiskScoreChange:          -riskScoreReduction,
		AttackPathScoreChange:    -attackPathScoreReduction,
		AttackPathCountChange:    -attackPathCountReduction,
		RiskScoreReduction:       riskScoreReduction,
		AttackPathScoreReduction: attackPathScoreReduction,
		AttackPathCountReduction: attackPathCountReduction,
		AffectedFindings:         riskDeltaFindingImpacts(beforeRecords, afterRecords, options.Now, options.RiskScoringConfig),
		AddedAttackPaths:         addedRiskDeltaAttackPaths(beforeAllPaths, afterAllPaths),
		RemovedAttackPaths:       removedRiskDeltaAttackPaths(beforeAllPaths, afterAllPaths),
		RemainingAttackPaths:     afterPaths,
		Reasons:                  uniqueSortedStrings(append(findingReasons, graphReasons...)),
	}
}

func limitRiskDeltaAttackPaths(paths []FindingAttackPath, limit int) []FindingAttackPath {
	if limit <= 0 || len(paths) <= limit {
		return paths
	}
	return paths[:limit]
}

func riskDeltaSnapshot(records []*ports.FindingRecord, paths []FindingAttackPath, now time.Time, config *ports.RiskScoringConfig) RiskDeltaSnapshot {
	totalRisk := 0
	for _, record := range records {
		totalRisk += AnalyzeFindingRiskContextWithConfig(record, now, config).Score
	}
	totalPathScore := 0
	for _, path := range paths {
		totalPathScore += path.Score
	}
	return RiskDeltaSnapshot{
		FindingCount:         len(nonNilFindings(records)),
		TotalRiskScore:       totalRisk,
		AttackPathCount:      len(paths),
		TotalAttackPathScore: totalPathScore,
	}
}

func applyRiskDeltaFindingScenario(records []*ports.FindingRecord, scenarioType string, targetURN string, neighborhoods map[string]*ports.EntityNeighborhood) ([]*ports.FindingRecord, []string) {
	after := cloneRiskDeltaFindings(records)
	reasons := []string{}
	identityBlastRadius := riskDeltaCompromiseIdentityBlastRadius(neighborhoods, targetURN)
	for _, record := range after {
		if record == nil {
			continue
		}
		matchesTarget := riskDeltaFindingMatchesTarget(record, targetURN)
		switch scenarioType {
		case RiskDeltaScenarioRemovePublicExposure:
			if !matchesTarget {
				continue
			}
			if removeRiskDeltaAttributes(record.Attributes, "internet_exposed", "public", "externally_exposed", "external_exposure", "is_public", "is_internet_facing", "reachable", "directly_reachable", "internet_reachable", "can_reach") {
				reasons = append(reasons, "removed_public_exposure_signals")
			}
		case RiskDeltaScenarioRemovePrivilege:
			if !matchesTarget {
				continue
			}
			if removeRiskDeltaAttributes(record.Attributes, "privileged", "actor_privileged", "admin", "is_admin", "has_admin", "can_admin", "admin_reachable", "privileged_access", "has_admin_path") {
				reasons = append(reasons, "removed_privilege_signals")
			}
		case RiskDeltaScenarioPatchVulnerability:
			if !matchesTarget {
				continue
			}
			if removeRiskDeltaAttributes(record.Attributes, "is_kev", "kev", "known_exploited", "known_exploited_vulnerability", "epss_score", "epss", "exploit_probability", "exploit_available", "public_exploit", "weaponized_exploit", "cvss_score", "cvss", "base_score", "exploit_maturity", "exploit_status") {
				reasons = append(reasons, "removed_vulnerability_exploitability_signals")
			}
		case RiskDeltaScenarioCompromiseIdentity:
			if !matchesTarget && !riskDeltaFindingMatchesAnyTarget(record, identityBlastRadius.resourceURNs) {
				continue
			}
			if record.Attributes == nil {
				record.Attributes = map[string]string{}
			}
			record.Attributes["active_threat"] = "true"
			record.Attributes["actor_urn"] = targetURN
			record.Attributes["compromised_identity_urn"] = targetURN
			record.Attributes["blast_radius"] = riskDeltaMaxIntString(record.Attributes["blast_radius"], len(identityBlastRadius.resourceURNs))
			if identityBlastRadius.privileged {
				record.Attributes["privileged_access"] = "true"
			}
			reasons = append(reasons, "modeled_compromised_identity")
			if len(identityBlastRadius.resourceURNs) > 0 {
				reasons = append(reasons, "modeled_identity_blast_radius")
			}
			if identityBlastRadius.privileged {
				reasons = append(reasons, "modeled_privileged_identity_path")
			}
		}
	}
	return after, reasons
}

func applyRiskDeltaGraphScenario(neighborhoods map[string]*ports.EntityNeighborhood, scenarioType string, targetURN string) (map[string]*ports.EntityNeighborhood, []string) {
	after := cloneRiskDeltaNeighborhoods(neighborhoods)
	reasons := []string{}
	for _, neighborhood := range after {
		if neighborhood == nil {
			continue
		}
		filtered := make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations))
		for _, relation := range neighborhood.Relations {
			if relation == nil {
				continue
			}
			if riskDeltaRelationRemoved(relation, scenarioType, targetURN) {
				reasons = append(reasons, "removed_graph_relation:"+strings.TrimSpace(relation.Relation))
				continue
			}
			filtered = append(filtered, relation)
		}
		neighborhood.Relations = filtered
	}
	return after, reasons
}

func riskDeltaRelationRemoved(relation *ports.NeighborhoodRelation, scenarioType string, targetURN string) bool {
	if relation == nil || !riskDeltaRelationTouchesTarget(relation, targetURN) {
		return false
	}
	switch scenarioType {
	case RiskDeltaScenarioRemovePublicExposure:
		return relation.Relation == "can_reach"
	case RiskDeltaScenarioRemovePrivilege:
		switch relation.Relation {
		case "can_admin", "can_assume", "can_impersonate", "can_perform":
			return true
		}
	case RiskDeltaScenarioPatchVulnerability:
		switch relation.Relation {
		case "affected_by", "found_vulnerability":
			return true
		}
	}
	return false
}

type riskDeltaIdentityBlastRadius struct {
	resourceURNs map[string]struct{}
	privileged   bool
}

func riskDeltaCompromiseIdentityBlastRadius(neighborhoods map[string]*ports.EntityNeighborhood, targetURN string) riskDeltaIdentityBlastRadius {
	targetURN = strings.TrimSpace(targetURN)
	result := riskDeltaIdentityBlastRadius{resourceURNs: map[string]struct{}{}}
	if targetURN == "" || len(neighborhoods) == 0 {
		return result
	}
	adjacency := map[string][]*ports.NeighborhoodRelation{}
	for _, neighborhood := range neighborhoods {
		if neighborhood == nil {
			continue
		}
		for _, relation := range neighborhood.Relations {
			if relation == nil || !riskDeltaCompromiseIdentityTraversalRelation(relation.Relation) {
				continue
			}
			copyRelation := cloneRiskDeltaRelation(relation)
			adjacency[copyRelation.FromURN] = append(adjacency[copyRelation.FromURN], copyRelation)
			if copyRelation.Relation == "owned_by" || copyRelation.Relation == "represents_identity" {
				reversed := cloneRiskDeltaRelation(copyRelation)
				reversed.FromURN, reversed.ToURN = reversed.ToURN, reversed.FromURN
				adjacency[reversed.FromURN] = append(adjacency[reversed.FromURN], reversed)
			}
		}
	}
	visited := map[string]struct{}{targetURN: {}}
	frontier := []string{targetURN}
	for depth := 0; depth < 3 && len(frontier) > 0 && len(result.resourceURNs) < 250; depth++ {
		next := []string{}
		for _, urn := range frontier {
			for _, relation := range adjacency[urn] {
				if relation == nil || relation.ToURN == "" {
					continue
				}
				if riskDeltaCompromiseIdentityPrivilegedRelation(relation.Relation) {
					result.privileged = true
				}
				if relation.ToURN != targetURN {
					result.resourceURNs[relation.ToURN] = struct{}{}
				}
				if _, ok := visited[relation.ToURN]; ok {
					continue
				}
				visited[relation.ToURN] = struct{}{}
				next = append(next, relation.ToURN)
			}
		}
		frontier = next
	}
	return result
}

func riskDeltaCompromiseIdentityTraversalRelation(relation string) bool {
	switch strings.TrimSpace(relation) {
	case "assigned_to", "can_admin", "can_assume", "can_impersonate", "can_perform", "can_reach", "member_of", "owned_by", "represents_identity", "runs_as":
		return true
	default:
		return false
	}
}

func riskDeltaCompromiseIdentityPrivilegedRelation(relation string) bool {
	switch strings.TrimSpace(relation) {
	case "can_admin", "can_assume", "can_impersonate", "can_perform":
		return true
	default:
		return false
	}
}

func riskDeltaRelationTouchesTarget(relation *ports.NeighborhoodRelation, targetURN string) bool {
	targetURN = strings.TrimSpace(targetURN)
	if targetURN == "" || relation == nil {
		return false
	}
	return relation.FromURN == targetURN || relation.ToURN == targetURN
}

func riskDeltaFindingImpacts(before []*ports.FindingRecord, after []*ports.FindingRecord, now time.Time, config *ports.RiskScoringConfig) []RiskDeltaFindingImpact {
	afterByID := map[string]*ports.FindingRecord{}
	for _, record := range after {
		if record != nil {
			afterByID[record.ID] = record
		}
	}
	impacts := []RiskDeltaFindingImpact{}
	for _, beforeRecord := range before {
		if beforeRecord == nil {
			continue
		}
		afterRecord := afterByID[beforeRecord.ID]
		if afterRecord == nil {
			continue
		}
		beforeContext := AnalyzeFindingRiskContextWithConfig(beforeRecord, now, config)
		afterContext := AnalyzeFindingRiskContextWithConfig(afterRecord, now, config)
		if beforeContext.Score == afterContext.Score {
			continue
		}
		impacts = append(impacts, RiskDeltaFindingImpact{
			FindingID:       strings.TrimSpace(beforeRecord.ID),
			RuleID:          strings.TrimSpace(beforeRecord.RuleID),
			ResourceURNs:    uniqueSortedStrings(beforeRecord.ResourceURNs),
			BeforeRiskScore: beforeContext.Score,
			AfterRiskScore:  afterContext.Score,
			Reduction:       beforeContext.Score - afterContext.Score,
			AddedReasons:    addedRiskDeltaReasons(beforeContext.Reasons, afterContext.Reasons),
			RemovedReasons:  removedRiskDeltaReasons(beforeContext.Reasons, afterContext.Reasons),
		})
	}
	sort.Slice(impacts, func(i int, j int) bool {
		left := impacts[i]
		right := impacts[j]
		switch {
		case left.Reduction != right.Reduction:
			return left.Reduction > right.Reduction
		default:
			return left.FindingID < right.FindingID
		}
	})
	return impacts
}

func addedRiskDeltaAttackPaths(before []FindingAttackPath, after []FindingAttackPath) []FindingAttackPath {
	beforeKeys := map[string]struct{}{}
	for _, path := range before {
		beforeKeys[riskDeltaAttackPathKey(path)] = struct{}{}
	}
	added := []FindingAttackPath{}
	for _, path := range after {
		if _, ok := beforeKeys[riskDeltaAttackPathKey(path)]; !ok {
			added = append(added, path)
		}
	}
	return added
}

func removedRiskDeltaAttackPaths(before []FindingAttackPath, after []FindingAttackPath) []FindingAttackPath {
	afterKeys := map[string]struct{}{}
	for _, path := range after {
		afterKeys[riskDeltaAttackPathKey(path)] = struct{}{}
	}
	removed := []FindingAttackPath{}
	for _, path := range before {
		if _, ok := afterKeys[riskDeltaAttackPathKey(path)]; !ok {
			removed = append(removed, path)
		}
	}
	return removed
}

func riskDeltaAttackPathKey(path FindingAttackPath) string {
	parts := make([]string, 0, len(path.Steps)+1)
	parts = append(parts, strings.TrimSpace(path.FindingID))
	for _, step := range path.Steps {
		parts = append(parts, step.FromURN+"|"+step.Relation+"|"+step.ToURN)
	}
	return strings.Join(parts, "\n")
}

func removedRiskDeltaReasons(before []string, after []string) []string {
	afterSet := map[string]struct{}{}
	for _, reason := range after {
		afterSet[reason] = struct{}{}
	}
	removed := []string{}
	for _, reason := range before {
		if _, ok := afterSet[reason]; !ok {
			removed = append(removed, reason)
		}
	}
	return uniqueSortedStrings(removed)
}

func addedRiskDeltaReasons(before []string, after []string) []string {
	beforeSet := map[string]struct{}{}
	for _, reason := range before {
		beforeSet[reason] = struct{}{}
	}
	added := []string{}
	for _, reason := range after {
		if _, ok := beforeSet[reason]; !ok {
			added = append(added, reason)
		}
	}
	return uniqueSortedStrings(added)
}

func riskDeltaFindingMatchesTarget(record *ports.FindingRecord, targetURN string) bool {
	targetURN = strings.TrimSpace(targetURN)
	if targetURN == "" || record == nil {
		return false
	}
	for _, resourceURN := range record.ResourceURNs {
		if strings.TrimSpace(resourceURN) == targetURN {
			return true
		}
	}
	for _, key := range []string{"primary_resource_urn", "resource_urn", "target_urn", "asset_urn", "exposed_resource_urn", "principal_urn", "permission_urn", "vulnerability_urn", "package_urn", "image_urn"} {
		if strings.TrimSpace(record.Attributes[key]) == targetURN {
			return true
		}
	}
	return false
}

func riskDeltaFindingMatchesAnyTarget(record *ports.FindingRecord, targetURNs map[string]struct{}) bool {
	if record == nil || len(targetURNs) == 0 {
		return false
	}
	for targetURN := range targetURNs {
		if riskDeltaFindingMatchesTarget(record, targetURN) {
			return true
		}
	}
	return false
}

func removeRiskDeltaAttributes(attributes map[string]string, keys ...string) bool {
	removed := false
	for _, key := range keys {
		if _, ok := attributes[key]; ok {
			delete(attributes, key)
			removed = true
		}
	}
	return removed
}

func riskDeltaMaxIntString(current string, candidate int) string {
	if candidate < 0 {
		candidate = 0
	}
	currentValue := 0
	if trimmed := strings.TrimSpace(current); trimmed != "" {
		for _, r := range trimmed {
			if r < '0' || r > '9' {
				currentValue = 0
				break
			}
			currentValue = currentValue*10 + int(r-'0')
		}
	}
	if currentValue > candidate {
		candidate = currentValue
	}
	return strconv.Itoa(candidate)
}

func cloneRiskDeltaFindings(records []*ports.FindingRecord) []*ports.FindingRecord {
	cloned := make([]*ports.FindingRecord, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		copyRecord := *record
		copyRecord.ResourceURNs = append([]string(nil), record.ResourceURNs...)
		copyRecord.EventIDs = append([]string(nil), record.EventIDs...)
		copyRecord.ObservedPolicyIDs = append([]string(nil), record.ObservedPolicyIDs...)
		copyRecord.ControlRefs = append([]ports.FindingControlRef(nil), record.ControlRefs...)
		copyRecord.RiskReasons = append([]string(nil), record.RiskReasons...)
		copyRecord.Attributes = map[string]string{}
		for key, value := range record.Attributes {
			copyRecord.Attributes[key] = value
		}
		cloned = append(cloned, &copyRecord)
	}
	return cloned
}

func cloneRiskDeltaNeighborhoods(neighborhoods map[string]*ports.EntityNeighborhood) map[string]*ports.EntityNeighborhood {
	cloned := make(map[string]*ports.EntityNeighborhood, len(neighborhoods))
	for key, neighborhood := range neighborhoods {
		if neighborhood == nil {
			continue
		}
		copyNeighborhood := &ports.EntityNeighborhood{
			Root:      cloneRiskDeltaNode(neighborhood.Root),
			Neighbors: make([]*ports.NeighborhoodNode, 0, len(neighborhood.Neighbors)),
			Relations: make([]*ports.NeighborhoodRelation, 0, len(neighborhood.Relations)),
		}
		for _, node := range neighborhood.Neighbors {
			copyNeighborhood.Neighbors = append(copyNeighborhood.Neighbors, cloneRiskDeltaNode(node))
		}
		for _, relation := range neighborhood.Relations {
			copyNeighborhood.Relations = append(copyNeighborhood.Relations, cloneRiskDeltaRelation(relation))
		}
		cloned[key] = copyNeighborhood
	}
	return cloned
}

func cloneRiskDeltaNode(node *ports.NeighborhoodNode) *ports.NeighborhoodNode {
	if node == nil {
		return nil
	}
	copyNode := *node
	return &copyNode
}

func cloneRiskDeltaRelation(relation *ports.NeighborhoodRelation) *ports.NeighborhoodRelation {
	if relation == nil {
		return nil
	}
	copyRelation := *relation
	copyRelation.Attributes = map[string]string{}
	for key, value := range relation.Attributes {
		copyRelation.Attributes[key] = value
	}
	return &copyRelation
}

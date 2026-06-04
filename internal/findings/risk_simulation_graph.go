package findings

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// SimulateRiskDeltaWithGraph computes graph-heavy attack-path deltas in Neo4j and
// keeps only finding attribute scoring in process.
func SimulateRiskDeltaWithGraph(ctx context.Context, records []*ports.FindingRecord, graphStore ports.GraphQueryStore, options RiskDeltaSimulationOptions) (RiskDeltaSimulationReport, error) {
	if graphStore == nil {
		return SimulateRiskDelta(records, options), nil
	}
	scenarioType := strings.TrimSpace(options.ScenarioType)
	targetURN := strings.TrimSpace(options.TargetURN)
	limit := options.Limit
	if limit <= 0 {
		limit = 10
	}
	tenantID := riskDeltaTenantID(options.TenantID, targetURN, records)
	beforeRecords := cloneRiskDeltaFindings(records)

	beforeRows, err := queryRiskDeltaGraphAttackPathRows(ctx, graphStore, tenantID, targetURN, nil, normalizeRiskDeltaGraphPathLimit(options.GraphPathLimit))
	if err != nil {
		return RiskDeltaSimulationReport{}, fmt.Errorf("query before graph risk delta paths: %w", err)
	}
	beforeAllPaths := riskDeltaGraphAttackPathsFromRows(beforeRows, tenantID, beforeRecords)
	before := riskDeltaSnapshot(beforeRecords, beforeAllPaths, options.Now)

	afterRecords, findingReasons, err := applyRiskDeltaGraphFindingScenario(ctx, graphStore, tenantID, beforeRecords, scenarioType, targetURN)
	if err != nil {
		return RiskDeltaSimulationReport{}, err
	}
	afterRows, err := queryRiskDeltaGraphAttackPathRows(ctx, graphStore, tenantID, targetURN, riskDeltaGraphRemovedRelations(scenarioType), normalizeRiskDeltaGraphPathLimit(options.GraphPathLimit))
	if err != nil {
		return RiskDeltaSimulationReport{}, fmt.Errorf("query after graph risk delta paths: %w", err)
	}
	afterAllPaths := riskDeltaGraphAttackPathsFromRows(afterRows, tenantID, afterRecords)
	afterPaths := limitRiskDeltaAttackPaths(afterAllPaths, limit)
	after := riskDeltaSnapshot(afterRecords, afterAllPaths, options.Now)

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
		AffectedFindings:         riskDeltaFindingImpacts(beforeRecords, afterRecords, options.Now),
		AddedAttackPaths:         addedRiskDeltaAttackPaths(beforeAllPaths, afterAllPaths),
		RemovedAttackPaths:       removedRiskDeltaAttackPaths(beforeAllPaths, afterAllPaths),
		RemainingAttackPaths:     afterPaths,
		Reasons:                  uniqueSortedStrings(append(findingReasons, "graph_query_risk_delta_paths")),
	}, nil
}

const riskDeltaGraphAttackPathQuery = `CALL {
  MATCH (resource:Entity {tenant_id: $tenant_id, urn: $target_urn})-[has_finding:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id})
  RETURN '' AS upstream_urn,
         '' AS upstream_entity_type,
         '' AS upstream_relation,
         resource.urn AS resource_urn,
         resource.entity_type AS resource_entity_type,
         finding.id AS finding_id,
         finding.urn AS finding_urn,
         finding.entity_type AS finding_entity_type
  UNION ALL
  MATCH (resource:Entity {tenant_id: $tenant_id})-[has_finding:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, urn: $target_urn})
  RETURN '' AS upstream_urn,
         '' AS upstream_entity_type,
         '' AS upstream_relation,
         resource.urn AS resource_urn,
         resource.entity_type AS resource_entity_type,
         finding.id AS finding_id,
         finding.urn AS finding_urn,
         finding.entity_type AS finding_entity_type
  UNION ALL
  MATCH (upstream:Entity {tenant_id: $tenant_id, urn: $target_urn})-[upstream_relation:RELATION]->(resource:Entity {tenant_id: $tenant_id})-[has_finding:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id})
  WHERE upstream_relation.relation <> 'has_finding'
    AND upstream.urn <> finding.urn
    AND (size($removed_relations) = 0 OR NOT (upstream_relation.relation IN $removed_relations))
  RETURN upstream.urn AS upstream_urn,
         upstream.entity_type AS upstream_entity_type,
         upstream_relation.relation AS upstream_relation,
         resource.urn AS resource_urn,
         resource.entity_type AS resource_entity_type,
         finding.id AS finding_id,
         finding.urn AS finding_urn,
         finding.entity_type AS finding_entity_type
  UNION ALL
  MATCH (upstream:Entity {tenant_id: $tenant_id})-[upstream_relation:RELATION]->(resource:Entity {tenant_id: $tenant_id, urn: $target_urn})-[has_finding:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id})
  WHERE upstream_relation.relation <> 'has_finding'
    AND upstream.urn <> finding.urn
    AND (size($removed_relations) = 0 OR NOT (upstream_relation.relation IN $removed_relations))
  RETURN upstream.urn AS upstream_urn,
         upstream.entity_type AS upstream_entity_type,
         upstream_relation.relation AS upstream_relation,
         resource.urn AS resource_urn,
         resource.entity_type AS resource_entity_type,
         finding.id AS finding_id,
         finding.urn AS finding_urn,
         finding.entity_type AS finding_entity_type
}
RETURN upstream_urn,
       upstream_entity_type,
       upstream_relation,
       resource_urn,
       resource_entity_type,
       finding_id,
       finding_urn,
       finding_entity_type
ORDER BY finding_urn, resource_urn, upstream_urn, upstream_relation
LIMIT $path_limit`

const riskDeltaIdentityBlastRadiusQuery = `MATCH (identity:Entity {tenant_id: $tenant_id, urn: $target_urn})-[path:RELATION*1..3]->(resource:Entity {tenant_id: $tenant_id})
WHERE all(edge IN path WHERE edge.relation IN ['assigned_to', 'can_admin', 'can_assume', 'can_impersonate', 'can_perform', 'can_reach', 'member_of', 'owned_by', 'represents_identity', 'runs_as'])
RETURN DISTINCT resource.urn AS resource_urn,
       any(edge IN path WHERE edge.relation IN ['can_admin', 'can_assume', 'can_impersonate', 'can_perform']) AS privileged
ORDER BY resource_urn
LIMIT $path_limit`

func queryRiskDeltaGraphAttackPathRows(ctx context.Context, graphStore ports.GraphQueryStore, tenantID string, targetURN string, removedRelations []string, limit int) ([]ports.CypherRow, error) {
	if removedRelations == nil {
		removedRelations = []string{}
	}
	return graphStore.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: riskDeltaGraphAttackPathQuery,
		Params: map[string]any{
			"path_limit":        int64(limit),
			"removed_relations": removedRelations,
			"target_urn":        strings.TrimSpace(targetURN),
			"tenant_id":         strings.TrimSpace(tenantID),
		},
		RowLimit: limit,
	})
}

func applyRiskDeltaGraphFindingScenario(ctx context.Context, graphStore ports.GraphQueryStore, tenantID string, records []*ports.FindingRecord, scenarioType string, targetURN string) ([]*ports.FindingRecord, []string, error) {
	if scenarioType != RiskDeltaScenarioCompromiseIdentity {
		afterRecords, reasons := applyRiskDeltaFindingScenario(records, scenarioType, targetURN, nil)
		return afterRecords, reasons, nil
	}
	blastRadius, err := riskDeltaGraphCompromiseIdentityBlastRadius(ctx, graphStore, tenantID, targetURN)
	if err != nil {
		return nil, nil, fmt.Errorf("query identity compromise blast radius: %w", err)
	}
	after := cloneRiskDeltaFindings(records)
	reasons := []string{}
	for _, record := range after {
		if record == nil {
			continue
		}
		if !riskDeltaFindingMatchesTarget(record, targetURN) && !riskDeltaFindingMatchesAnyTarget(record, blastRadius.resourceURNs) {
			continue
		}
		if record.Attributes == nil {
			record.Attributes = map[string]string{}
		}
		record.Attributes["active_threat"] = "true"
		record.Attributes["blast_radius"] = "true"
		if blastRadius.privileged {
			record.Attributes["privileged"] = "true"
		}
		reasons = append(reasons, "modeled_identity_blast_radius")
	}
	return after, uniqueSortedStrings(reasons), nil
}

func riskDeltaGraphCompromiseIdentityBlastRadius(ctx context.Context, graphStore ports.GraphQueryStore, tenantID string, targetURN string) (riskDeltaIdentityBlastRadius, error) {
	rows, err := graphStore.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: riskDeltaIdentityBlastRadiusQuery,
		Params: map[string]any{
			"path_limit": int64(normalizeRiskDeltaGraphPathLimit(0)),
			"target_urn": strings.TrimSpace(targetURN),
			"tenant_id":  strings.TrimSpace(tenantID),
		},
		RowLimit: normalizeRiskDeltaGraphPathLimit(0),
	})
	if err != nil {
		return riskDeltaIdentityBlastRadius{}, err
	}
	result := riskDeltaIdentityBlastRadius{resourceURNs: map[string]struct{}{}}
	for _, row := range rows {
		resourceURN := riskDeltaCypherString(row, "resource_urn")
		if resourceURN == "" || resourceURN == targetURN {
			continue
		}
		result.resourceURNs[resourceURN] = struct{}{}
		if riskDeltaCypherBool(row, "privileged") {
			result.privileged = true
		}
	}
	return result, nil
}

func riskDeltaGraphAttackPathsFromRows(rows []ports.CypherRow, tenantID string, records []*ports.FindingRecord) []FindingAttackPath {
	recordsByID, recordsByURN := riskDeltaFindingLookups(tenantID, records)
	paths := make([]FindingAttackPath, 0, len(rows))
	seen := map[string]struct{}{}
	for _, row := range rows {
		resourceURN := riskDeltaCypherString(row, "resource_urn")
		findingURN := riskDeltaCypherString(row, "finding_urn")
		if resourceURN == "" || findingURN == "" {
			continue
		}
		finding := recordsByURN[findingURN]
		if finding == nil {
			finding = recordsByID[riskDeltaCypherString(row, "finding_id")]
		}
		if finding == nil {
			continue
		}
		steps := []FindingAttackPathStep{}
		if upstreamURN := riskDeltaCypherString(row, "upstream_urn"); upstreamURN != "" {
			steps = append(steps, FindingAttackPathStep{
				FromURN:  upstreamURN,
				FromType: riskDeltaCypherString(row, "upstream_entity_type"),
				Relation: riskDeltaCypherString(row, "upstream_relation"),
				ToURN:    resourceURN,
				ToType:   riskDeltaCypherString(row, "resource_entity_type"),
			})
		}
		steps = append(steps, FindingAttackPathStep{
			FromURN:  resourceURN,
			FromType: riskDeltaCypherString(row, "resource_entity_type"),
			Relation: "has_finding",
			ToURN:    findingURN,
			ToType:   riskDeltaCypherString(row, "finding_entity_type"),
		})
		key := riskDeltaAttackPathKey(FindingAttackPath{FindingURN: findingURN, Steps: steps})
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		context := AnalyzeFindingRiskContext(finding, time.Time{})
		weightScore, weightReasons := weightedAttackPathScore(steps)
		paths = append(paths, FindingAttackPath{
			Pattern:    attackPathPattern(steps),
			Score:      context.Score + weightScore,
			FindingID:  strings.TrimSpace(finding.ID),
			FindingURN: findingURN,
			Steps:      steps,
			Evidence:   newFindingEvidenceBundle([]*ports.FindingRecord{finding}),
			Reasons:    uniqueSortedStrings(append(append([]string{"graph_path", "pattern:" + attackPathPattern(steps)}, context.Reasons...), weightReasons...)),
		})
	}
	slices.SortFunc(paths, func(left FindingAttackPath, right FindingAttackPath) int {
		switch {
		case left.Score != right.Score:
			return right.Score - left.Score
		case len(left.Steps) != len(right.Steps):
			return len(right.Steps) - len(left.Steps)
		case left.Pattern < right.Pattern:
			return -1
		case left.Pattern > right.Pattern:
			return 1
		case left.FindingURN < right.FindingURN:
			return -1
		case left.FindingURN > right.FindingURN:
			return 1
		default:
			return 0
		}
	})
	return paths
}

func riskDeltaFindingLookups(tenantID string, records []*ports.FindingRecord) (map[string]*ports.FindingRecord, map[string]*ports.FindingRecord) {
	byID := map[string]*ports.FindingRecord{}
	byURN := map[string]*ports.FindingRecord{}
	for _, record := range records {
		if record == nil {
			continue
		}
		id := strings.TrimSpace(record.ID)
		if id == "" {
			continue
		}
		byID[id] = record
		byURN[findingGraphFindingURN(tenantID, record)] = record
	}
	return byID, byURN
}

func riskDeltaGraphRemovedRelations(scenarioType string) []string {
	switch strings.TrimSpace(scenarioType) {
	case RiskDeltaScenarioRemovePublicExposure:
		return []string{"can_reach"}
	case RiskDeltaScenarioRemovePrivilege:
		return []string{"can_admin", "can_assume", "can_impersonate", "can_perform"}
	case RiskDeltaScenarioPatchVulnerability:
		return []string{"affected_by", "found_vulnerability"}
	default:
		return nil
	}
}

func normalizeRiskDeltaGraphPathLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	limit *= 100
	switch {
	case limit < 100:
		return 100
	case limit > ports.MaxCypherQueryRows:
		return ports.MaxCypherQueryRows
	default:
		return limit
	}
}

func riskDeltaTenantID(tenantID string, targetURN string, records []*ports.FindingRecord) string {
	if trimmed := strings.TrimSpace(tenantID); trimmed != "" {
		return trimmed
	}
	if trimmed := tenantIDFromCerebroURN(targetURN); trimmed != "" {
		return trimmed
	}
	for _, record := range records {
		if record != nil && strings.TrimSpace(record.TenantID) != "" {
			return strings.TrimSpace(record.TenantID)
		}
	}
	return ""
}

func tenantIDFromCerebroURN(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) >= 3 && parts[0] == "urn" && parts[1] == "cerebro" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func riskDeltaCypherString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	switch value := row.Values[key].(type) {
	case string:
		return strings.TrimSpace(value)
	case fmt.Stringer:
		return strings.TrimSpace(value.String())
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func riskDeltaCypherBool(row ports.CypherRow, key string) bool {
	if row.Values == nil {
		return false
	}
	switch value := row.Values[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "t", "true", "yes", "y":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

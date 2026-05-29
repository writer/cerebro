package graphagent

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	IntentRawCypher                 = "raw_cypher"
	IntentAggregateFindingsBySource = "aggregate_findings_by_source"
	IntentTopRiskFindings           = "top_risk_findings"
	IntentExplainFinding            = "explain_finding"
	IntentIdentityBridge            = "identity_bridge"
	IntentConnectorHealth           = "connector_health"
)

type AskQueryPlan struct {
	Intent     string            `json:"intent"`
	Confidence float64           `json:"confidence,omitempty"`
	ScopeURN   string            `json:"scope_urn,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Filters    map[string]string `json:"filters,omitempty"`
	GroupBy    string            `json:"group_by,omitempty"`
}

type ConversionDiagnostic struct {
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type conversionResult struct {
	Plan          AskQueryPlan
	Cypher        string
	Diagnostics   []ConversionDiagnostic
	Source        string
	Deterministic bool
	Corrected     bool
}

var (
	upperRelationPattern  = regexp.MustCompile(`:\s*([A-Z][A-Z0-9_]+)\b`)
	nonEntityLabelPattern = regexp.MustCompile(`\([^){}]*:\s*(Finding|FINDING|finding|repo|repository|identity|connector)\b`)
	apocUsagePattern      = regexp.MustCompile(`(?i)\bapoc\.`)
)

func convertDraftToQuery(request AskRequest, draft *DraftResponse, maxRows int) conversionResult {
	cypher := strings.TrimSpace(draft.Cypher)
	if cypher == "" && strings.TrimSpace(draft.Refusal) != "" {
		plan := normalizePlanWithoutInference(draft.Plan, request, maxRows)
		return conversionResult{
			Plan:      plan,
			Cypher:    "",
			Source:    "llm_refusal",
			Corrected: false,
			Diagnostics: []ConversionDiagnostic{{
				Level:   "info",
				Code:    "llm_refusal_preserved",
				Message: "The LLM explicitly refused to produce Cypher, so deterministic conversion was skipped.",
			}},
		}
	}
	plan := normalizePlan(draft.Plan, request, cypher, maxRows)
	result := conversionResult{
		Plan:      plan,
		Cypher:    cypher,
		Source:    "llm",
		Corrected: false,
	}
	if rendered, ok := renderDeterministicPlan(plan, maxRows); ok {
		result.Cypher = rendered
		result.Source = "deterministic_template"
		result.Deterministic = true
		result.Corrected = strings.TrimSpace(cypher) != "" && normalizeCypherForCompare(cypher) != normalizeCypherForCompare(rendered)
		if result.Corrected {
			result.Diagnostics = append(result.Diagnostics, ConversionDiagnostic{
				Level:   "info",
				Code:    "canonicalized_to_template",
				Message: fmt.Sprintf("Converted LLM draft into canonical %s template.", plan.Intent),
			})
		}
	} else if cypher != "" {
		limited, diagnostic, changed := enforceCypherLimit(cypher, maxRows)
		if changed {
			result.Cypher = limited
			result.Corrected = true
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
	}
	result.Diagnostics = append(result.Diagnostics, ontologyDiagnostics(cypher)...)
	if result.Deterministic {
		result.Diagnostics = append(result.Diagnostics, ConversionDiagnostic{
			Level:   "info",
			Code:    "deterministic_query_plan",
			Message: "Graph access used a deterministic Cerebro query template; LLM variance is limited to intent extraction and summary text.",
		})
	}
	return result
}

func normalizePlan(plan *AskQueryPlan, request AskRequest, cypher string, maxRows int) AskQueryPlan {
	var out AskQueryPlan
	if plan != nil {
		out = *plan
	}
	out.Intent = canonicalIntent(out.Intent)
	if out.Intent == "" || out.Intent == IntentRawCypher {
		out.Intent = inferIntent(request.Question, cypher)
	}
	out.ScopeURN = firstNonEmpty(out.ScopeURN, strings.TrimSpace(request.ScopeURN))
	out.Limit = boundedLimit(out.Limit, maxRows)
	if out.Confidence == 0 && out.Intent != IntentRawCypher {
		out.Confidence = 0.85
	}
	if out.Filters == nil {
		out.Filters = map[string]string{}
	}
	for key, value := range out.Filters {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			delete(out.Filters, key)
			continue
		}
		if strings.EqualFold(key, "entity_type") {
			out.Filters[key] = canonicalEntityType(trimmed)
			continue
		}
		if strings.EqualFold(key, "relation") {
			if canonical, ok := canonicalRelation(trimmed); ok {
				out.Filters[key] = canonical
				continue
			}
		}
		out.Filters[key] = trimmed
	}
	return out
}

func normalizePlanWithoutInference(plan *AskQueryPlan, request AskRequest, maxRows int) AskQueryPlan {
	out := AskQueryPlan{Intent: IntentRawCypher}
	if plan != nil {
		out = *plan
	}
	out.Intent = canonicalIntent(out.Intent)
	if out.Intent == "" {
		out.Intent = IntentRawCypher
	}
	out.ScopeURN = firstNonEmpty(out.ScopeURN, strings.TrimSpace(request.ScopeURN))
	out.Limit = boundedLimit(out.Limit, maxRows)
	if out.Filters == nil {
		out.Filters = map[string]string{}
	}
	return out
}

func canonicalIntent(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "raw", "cypher", "raw_cypher":
		return IntentRawCypher
	case "aggregate_findings_by_source", "finding_source_counts", "findings_by_source", "source_breakdown":
		return IntentAggregateFindingsBySource
	case "top_risk_findings", "high_risk_findings", "findings":
		return IntentTopRiskFindings
	case "explain_finding", "finding_explanation":
		return IntentExplainFinding
	case "identity_bridge", "identity_bridges":
		return IntentIdentityBridge
	case "connector_health", "source_health", "runtime_health":
		return IntentConnectorHealth
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func inferIntent(question string, cypher string) string {
	haystack := strings.ToLower(question + "\n" + cypher)
	switch {
	case strings.Contains(haystack, "source") && strings.Contains(haystack, "finding") && (strings.Contains(haystack, "count") || strings.Contains(haystack, "breakdown") || strings.Contains(haystack, "group") || strings.Contains(haystack, "top")):
		return IntentAggregateFindingsBySource
	case strings.Contains(haystack, "has_source") || strings.Contains(haystack, "belongs_to_source") || strings.Contains(haystack, "source_family"):
		return IntentAggregateFindingsBySource
	case strings.Contains(haystack, "connector") || strings.Contains(haystack, "runtime health") || strings.Contains(haystack, "source health"):
		return IntentConnectorHealth
	case strings.Contains(haystack, "bridge") && (strings.Contains(haystack, "identity") || strings.Contains(haystack, "okta") || strings.Contains(haystack, "github")):
		return IntentIdentityBridge
	case strings.Contains(haystack, "explain") && strings.Contains(haystack, "finding"):
		return IntentExplainFinding
	case (strings.Contains(haystack, "high risk") || strings.Contains(haystack, "top risk") || strings.Contains(haystack, "critical")) && strings.Contains(haystack, "finding"):
		return IntentTopRiskFindings
	default:
		return IntentRawCypher
	}
}

func renderDeterministicPlan(plan AskQueryPlan, maxRows int) (string, bool) {
	if hasUnsupportedDeterministicModifiers(plan) {
		return "", false
	}
	limit := boundedLimit(plan.Limit, maxRows)
	switch plan.Intent {
	case IntentAggregateFindingsBySource:
		if limit > 10 {
			limit = 10
		}
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(f:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR resource.urn = $scope_urn OR f.urn = $scope_urn
WITH DISTINCT f,
     coalesce(
       CASE WHEN coalesce(f.attributes_json, '') CONTAINS '"source_family":"' THEN split(split(f.attributes_json, '"source_family":"')[1], '"')[0] END,
       CASE WHEN coalesce(f.attributes_json, '') CONTAINS '"sourceFamily":"' THEN split(split(f.attributes_json, '"sourceFamily":"')[1], '"')[0] END,
       CASE WHEN coalesce(f.attributes_json, '') CONTAINS '"source_system":"' THEN split(split(f.attributes_json, '"source_system":"')[1], '"')[0] END,
       f.source_id,
       'Unknown'
     ) AS source_family
RETURN source_family, count(DISTINCT f) AS finding_count
ORDER BY finding_count DESC, source_family
LIMIT %d`, limit), true
	case IntentTopRiskFindings:
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn
WITH resource, r, finding,
     coalesce(
       CASE WHEN coalesce(r.attributes_json, '') CONTAINS '"risk_score":"' THEN toInteger(split(split(r.attributes_json, '"risk_score":"')[1], '"')[0]) END,
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"risk_score":"' THEN toInteger(split(split(finding.attributes_json, '"risk_score":"')[1], '"')[0]) END,
       0
     ) AS risk_score,
     coalesce(
       CASE WHEN coalesce(r.attributes_json, '') CONTAINS '"effective_severity":"' THEN split(split(r.attributes_json, '"effective_severity":"')[1], '"')[0] END,
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"effective_severity":"' THEN split(split(finding.attributes_json, '"effective_severity":"')[1], '"')[0] END,
       CASE WHEN coalesce(r.attributes_json, '') CONTAINS '"severity":"' THEN split(split(r.attributes_json, '"severity":"')[1], '"')[0] END,
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"severity":"' THEN split(split(finding.attributes_json, '"severity":"')[1], '"')[0] END,
       ''
     ) AS severity
WITH resource, finding, risk_score, severity,
     CASE toUpper(severity)
       WHEN 'CRITICAL' THEN 4
       WHEN 'HIGH' THEN 3
       WHEN 'MEDIUM' THEN 2
       WHEN 'LOW' THEN 1
       ELSE 0
     END AS severity_rank
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       resource.urn AS resource_urn,
       coalesce(resource.label, resource.urn) AS resource_label,
       risk_score,
       severity
ORDER BY risk_score DESC, severity_rank DESC, finding_urn
LIMIT %d`, limit), true
	case IntentExplainFinding:
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR finding.urn = $scope_urn OR resource.urn = $scope_urn
WITH resource, r, finding,
     coalesce(
       CASE WHEN coalesce(r.attributes_json, '') CONTAINS '"risk_score":"' THEN toInteger(split(split(r.attributes_json, '"risk_score":"')[1], '"')[0]) END,
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"risk_score":"' THEN toInteger(split(split(finding.attributes_json, '"risk_score":"')[1], '"')[0]) END,
       0
     ) AS risk_score,
     coalesce(
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"severity":"' THEN split(split(finding.attributes_json, '"severity":"')[1], '"')[0] END,
       ''
     ) AS severity,
     coalesce(
       CASE WHEN coalesce(finding.attributes_json, '') CONTAINS '"status":"' THEN split(split(finding.attributes_json, '"status":"')[1], '"')[0] END,
       ''
     ) AS status,
     '' AS summary
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       severity,
       status,
       summary,
       resource.urn AS resource_urn,
       coalesce(resource.label, resource.urn) AS resource_label,
       risk_score,
       coalesce(finding.attributes_json, '') AS finding_attributes_json_internal
ORDER BY risk_score DESC, finding_urn
LIMIT %d`, limit), true
	case IntentIdentityBridge:
		return fmt.Sprintf(`MATCH (left:Entity {tenant_id: $tenant_id})-[leftRel:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})
MATCH (right:Entity {tenant_id: $tenant_id})-[rightRel:RELATION {relation: 'represents_identity'}]->(identity)
WHERE left.urn < right.urn
  AND left.entity_type <> right.entity_type
  AND NOT left.entity_type STARTS WITH 'identity'
  AND NOT right.entity_type STARTS WITH 'identity'
  AND coalesce(leftRel.attributes_json, '') CONTAINS '"at":"'
  AND coalesce(rightRel.attributes_json, '') CONTAINS '"at":"'
WITH left, right, identity,
     split(split(leftRel.attributes_json, '"at":"')[1], '"')[0] AS left_seen_at,
     split(split(rightRel.attributes_json, '"at":"')[1], '"')[0] AS right_seen_at
WHERE datetime(left_seen_at) >= datetime() - duration('P90D')
  AND datetime(right_seen_at) >= datetime() - duration('P90D')
RETURN left.urn AS left_urn,
       coalesce(left.label, left.urn) AS left_label,
       left.entity_type AS left_type,
       right.urn AS right_urn,
       coalesce(right.label, right.urn) AS right_label,
       right.entity_type AS right_type,
       identity.urn AS identity_urn,
       coalesce(identity.label, identity.urn) AS identity_label,
       left_seen_at,
       right_seen_at
ORDER BY identity_label, left_urn, right_urn
LIMIT %d`, limit), true
	case IntentConnectorHealth:
		return fmt.Sprintf(`MATCH (source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
RETURN source.urn AS source_urn,
       coalesce(source.label, source.urn) AS source_label,
       source.source_id AS source_id,
       source.runtime_id AS runtime_id,
       coalesce(source.attributes_json, '') AS source_attributes_json
ORDER BY source_label, source_urn
LIMIT %d`, limit), true
	default:
		return "", false
	}
}

func hasUnsupportedDeterministicModifiers(plan AskQueryPlan) bool {
	if len(plan.Filters) > 0 {
		return true
	}
	groupBy := strings.ToLower(strings.TrimSpace(plan.GroupBy))
	if groupBy == "" {
		return false
	}
	return plan.Intent != IntentAggregateFindingsBySource || groupBy != "source_family"
}

func ontologyDiagnostics(cypher string) []ConversionDiagnostic {
	if strings.TrimSpace(cypher) == "" {
		return nil
	}
	var diagnostics []ConversionDiagnostic
	if nonEntityLabelPattern.MatchString(cypher) {
		diagnostics = append(diagnostics, ConversionDiagnostic{
			Level:   "warn",
			Code:    "non_canonical_entity_label",
			Message: "Draft used domain labels like :Finding/:repo; Cerebro graph nodes must use :Entity with entity_type filters.",
		})
	}
	for _, match := range upperRelationPattern.FindAllStringSubmatch(cypher, -1) {
		if len(match) < 2 {
			continue
		}
		if _, ok := canonicalRelation(match[1]); ok {
			diagnostics = append(diagnostics, ConversionDiagnostic{
				Level:   "warn",
				Code:    "relation_alias_canonicalized",
				Message: fmt.Sprintf("Draft used relationship alias %s; Cerebro stores lowercase relation values on :RELATION.", match[1]),
			})
		}
	}
	if apocUsagePattern.MatchString(cypher) {
		diagnostics = append(diagnostics, ConversionDiagnostic{
			Level:   "warn",
			Code:    "apoc_not_allowed",
			Message: "Draft used APOC; Ask Cerebro does not depend on APOC for read-only graph answers.",
		})
	}
	return diagnostics
}

func enforceCypherLimit(cypher string, maxRows int) (string, ConversionDiagnostic, bool) {
	limit := boundedLimit(maxRows, maxRows)
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cypher), ";"))
	if trimmed == "" {
		return cypher, ConversionDiagnostic{}, false
	}
	matches := limitPattern.FindAllStringSubmatchIndex(trimmed, -1)
	if len(matches) == 0 {
		return trimmed + fmt.Sprintf("\nLIMIT %d", limit), ConversionDiagnostic{
			Level:   "info",
			Code:    "limit_injected",
			Message: fmt.Sprintf("Added LIMIT %d to LLM fallback Cypher.", limit),
		}, true
	}
	valueStart, valueEnd := matches[len(matches)-1][2], matches[len(matches)-1][3]
	current, ok := queryLimit(trimmed)
	if !ok || current <= limit {
		return cypher, ConversionDiagnostic{}, false
	}
	return trimmed[:valueStart] + fmt.Sprintf("%d", limit) + trimmed[valueEnd:], ConversionDiagnostic{
		Level:   "info",
		Code:    "limit_capped",
		Message: fmt.Sprintf("Capped LLM fallback Cypher LIMIT from %d to %d.", current, limit),
	}, true
}

func boundedLimit(limit int, maxRows int) int {
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}
	if limit <= 0 {
		if maxRows < 25 {
			return maxRows
		}
		return 25
	}
	if limit > maxRows {
		return maxRows
	}
	return limit
}

func normalizeCypherForCompare(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

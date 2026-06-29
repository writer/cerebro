package graphagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	IntentRawCypher                 = "raw_cypher"
	IntentAggregateFindingsBySource = "aggregate_findings_by_source"
	IntentTopRiskFindings           = "top_risk_findings"
	IntentFailingControls           = "failing_controls"
	IntentExplainFinding            = "explain_finding"
	IntentIdentityBridge            = "identity_bridge"
	IntentConnectorHealth           = "connector_health"

	postProcessingCandidateRowLimit = ports.MaxCypherQueryRows
	confidentPlanThreshold          = 0.70
)

type AskQueryPlan struct {
	Intent     string            `json:"intent"`
	Confidence float64           `json:"confidence,omitempty"`
	ScopeURN   string            `json:"scope_urn,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Filters    map[string]string `json:"filters,omitempty"`
	GroupBy    string            `json:"group_by,omitempty"`
}

func (p *AskQueryPlan) UnmarshalJSON(data []byte) error {
	var raw struct {
		Intent     string         `json:"intent"`
		Confidence float64        `json:"confidence,omitempty"`
		ScopeURN   string         `json:"scope_urn,omitempty"`
		Limit      int            `json:"limit,omitempty"`
		Filters    map[string]any `json:"filters,omitempty"`
		GroupBy    string         `json:"group_by,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Intent = raw.Intent
	p.Confidence = raw.Confidence
	p.ScopeURN = raw.ScopeURN
	p.Limit = raw.Limit
	p.GroupBy = raw.GroupBy
	if raw.Filters == nil {
		p.Filters = nil
		return nil
	}
	p.Filters = make(map[string]string, len(raw.Filters))
	for key, value := range raw.Filters {
		filterValue := stringifyPlanFilter(value)
		if filterValue != "" {
			p.Filters[key] = filterValue
		}
	}
	return nil
}

func stringifyPlanFilter(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case float64, bool:
		return strings.TrimSpace(fmt.Sprint(typed))
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return strings.TrimSpace(fmt.Sprint(typed))
		}
		return string(raw)
	}
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
	Refusal       string
	Deterministic bool
	Corrected     bool
}

var (
	upperRelationPattern  = regexp.MustCompile(`:\s*([A-Z][A-Z0-9_]+)\b`)
	nonEntityLabelPattern = regexp.MustCompile(`\([^){}]*:\s*(Finding|FINDING|finding|repo|repository|identity|connector)\b`)
	apocUsagePattern      = regexp.MustCompile(`(?i)\bapoc\.[A-Za-z0-9_.]+\s*\(`)
	cypherLimitPattern    = regexp.MustCompile(`(?i)\bLIMIT\s+(\d+)\b`)
)

func convertDraftToQuery(request AskRequest, draft *DraftResponse) conversionResult {
	cypher := strings.TrimSpace(draft.Cypher)
	if cypher == "" && strings.TrimSpace(draft.Refusal) != "" {
		plan := normalizePlanWithoutInference(draft.Plan, request, defaultMaxRows)
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
	plan := normalizePlan(draft.Plan, request, cypher, defaultMaxRows)
	result := conversionResult{
		Plan:      plan,
		Cypher:    cypher,
		Source:    "llm",
		Corrected: false,
	}
	if rendered, ok := renderDeterministicPlan(plan, defaultMaxRows); ok {
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
		limited, diagnostic, changed := enforceCypherLimit(cypher, defaultMaxRows)
		if changed {
			result.Cypher = limited
			result.Corrected = true
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
	} else if plan.Intent != IntentRawCypher {
		result.Source = "conversion_refusal"
		result.Refusal = fmt.Sprintf("Ask query plan %q could not be converted to Cypher and no fallback Cypher was provided.", plan.Intent)
		result.Diagnostics = append(result.Diagnostics, ConversionDiagnostic{
			Level:   "warn",
			Code:    "query_plan_conversion_failed",
			Message: result.Refusal,
		})
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

func deterministicFastPathConversion(request AskRequest, enabled bool) (conversionResult, string, bool) {
	if !enabled {
		return conversionResult{}, "", false
	}
	plan, ok := deterministicFastPathPlan(request)
	if !ok {
		return conversionResult{}, "", false
	}
	cypher, ok := renderDeterministicPlan(plan, defaultMaxRows)
	if !ok || strings.TrimSpace(cypher) == "" {
		return conversionResult{}, "", false
	}
	result := conversionResult{
		Plan:          plan,
		Cypher:        cypher,
		Source:        "deterministic_fast_path",
		Deterministic: true,
		Diagnostics: []ConversionDiagnostic{{
			Level:   "info",
			Code:    "deterministic_query_plan",
			Message: "Graph access used a deterministic Cerebro query template and skipped LLM Cypher drafting.",
		}},
	}
	return result, "Using a deterministic Cerebro query template for this common read-only graph question.", true
}

func deterministicFastPathPlan(request AskRequest) (AskQueryPlan, bool) {
	question := strings.TrimSpace(request.Question)
	if question == "" || questionLooksUnsafe(question) {
		return AskQueryPlan{}, false
	}
	intent := inferIntent(strings.ReplaceAll(question, "-", " "), "")
	if intent == IntentRawCypher {
		return AskQueryPlan{}, false
	}
	plan := AskQueryPlan{
		Intent:     intent,
		Confidence: 0.95,
		ScopeURN:   strings.TrimSpace(request.ScopeURN),
		Limit:      25,
	}
	switch intent {
	case IntentTopRiskFindings:
		plan.Filters = fastPathTopRiskFilters(question)
	case IntentFailingControls:
		plan.Filters = map[string]string{}
	case IntentAggregateFindingsBySource, IntentConnectorHealth, IntentIdentityBridge:
		plan.Filters = map[string]string{}
	case IntentExplainFinding:
		if plan.ScopeURN == "" {
			return AskQueryPlan{}, false
		}
		plan.Filters = map[string]string{}
	default:
		return AskQueryPlan{}, false
	}
	return normalizePlan(&plan, request, "", defaultMaxRows), true
}

func questionLooksUnsafe(question string) bool {
	lower := strings.ToLower(question)
	for _, token := range []string{"delete", "drop", "detach", "remove", "write", "update", "merge ", "create "} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func fastPathTopRiskFilters(question string) map[string]string {
	lower := strings.ToLower(question)
	filters := map[string]string{}
	switch {
	case containsWord(lower, "open"):
		filters["status"] = "open"
	case containsWord(lower, "resolved"):
		filters["status"] = "resolved"
	case containsWord(lower, "suppressed"):
		filters["status"] = "suppressed"
	}
	if strings.Contains(lower, "repository") || containsWord(lower, "repo") || strings.Contains(lower, "code repo") {
		filters["resource_type"] = "repository"
	}
	return filters
}

func containsWord(haystack string, needle string) bool {
	if strings.TrimSpace(needle) == "" {
		return false
	}
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(strings.ToLower(needle)) + `\b`)
	return pattern.MatchString(strings.ToLower(haystack))
}

func normalizePlan(plan *AskQueryPlan, request AskRequest, cypher string, defaultMaxRows int) AskQueryPlan {
	var out AskQueryPlan
	if plan != nil {
		out = *plan
	}
	out.Intent = canonicalIntent(out.Intent)
	requestIntent := inferIntent(request.Question, cypher)
	if requestIntent == IntentFailingControls && out.Intent != IntentFailingControls && out.Confidence < confidentPlanThreshold {
		out.Intent = IntentFailingControls
		out.Filters = map[string]string{}
	}
	if out.Intent == "" || out.Intent == IntentRawCypher {
		out.Intent = requestIntent
	}
	out.ScopeURN = firstNonEmpty(out.ScopeURN, strings.TrimSpace(request.ScopeURN))
	out.Limit = boundedLimit(out.Limit, defaultMaxRows)
	if out.Confidence == 0 && out.Intent != IntentRawCypher {
		out.Confidence = 0.85
	}
	if out.Filters == nil {
		out.Filters = map[string]string{}
	}
	if out.Intent == IntentFailingControls {
		out.Filters = map[string]string{}
		return out
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

func normalizePlanWithoutInference(plan *AskQueryPlan, request AskRequest, defaultMaxRows int) AskQueryPlan {
	out := AskQueryPlan{Intent: IntentRawCypher}
	if plan != nil {
		out = *plan
	}
	out.Intent = canonicalIntent(out.Intent)
	if out.Intent == "" {
		out.Intent = IntentRawCypher
	}
	out.ScopeURN = firstNonEmpty(out.ScopeURN, strings.TrimSpace(request.ScopeURN))
	out.Limit = boundedLimit(out.Limit, defaultMaxRows)
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
	case "failing_controls", "failed_controls", "control_failures":
		return IntentFailingControls
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
	case (strings.Contains(haystack, "high risk") || strings.Contains(haystack, "top risk") || strings.Contains(haystack, "critical")) && strings.Contains(haystack, "finding"):
		return IntentTopRiskFindings
	case (strings.Contains(haystack, "control") || strings.Contains(haystack, "controls")) && (containsWord(haystack, "failing") || containsWord(haystack, "failed") || containsWord(haystack, "fail") || strings.Contains(haystack, "not passing")):
		return IntentFailingControls
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
	default:
		return IntentRawCypher
	}
}

func renderDeterministicPlan(plan AskQueryPlan, defaultMaxRows int) (string, bool) {
	if hasUnsupportedDeterministicModifiers(plan) {
		return "", false
	}
	limit := boundedLimit(plan.Limit, defaultMaxRows)
	switch plan.Intent {
	case IntentAggregateFindingsBySource:
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'has_finding'}]->(f:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR resource.urn = $scope_urn OR f.urn = $scope_urn
WITH DISTINCT f
RETURN f.urn AS finding_urn,
       f.source_id AS source_id,
       coalesce(f.attributes_json, '') AS finding_attributes_json_internal
ORDER BY finding_urn
LIMIT %d`, postProcessingCandidateRowLimit), true
	case IntentTopRiskFindings:
		filterProjection, filterPredicate := topRiskFilterClauses(plan.Filters)
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn
WITH resource, r, finding%s
%s
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       resource.urn AS resource_urn,
       coalesce(resource.label, resource.urn) AS resource_label,
       resource.entity_type AS resource_type,
       coalesce(r.attributes_json, '') AS relation_attributes_json_internal,
       coalesce(finding.attributes_json, '') AS finding_attributes_json_internal
ORDER BY finding_urn, resource_urn
LIMIT %d`, filterProjection, filterPredicate, postProcessingCandidateRowLimit), true
	case IntentFailingControls:
		return fmt.Sprintf(`MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn
WITH resource, r, finding,
     coalesce(
       %s,
       ''
     ) AS filter_status,
     coalesce(
       %s,
       ''
     ) AS filter_control_refs
WHERE (filter_status = '' OR toLower(filter_status) = 'open')
  AND filter_control_refs <> ''
RETURN finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       resource.urn AS resource_urn,
       coalesce(resource.label, resource.urn) AS resource_label,
       resource.entity_type AS resource_type,
       coalesce(r.attributes_json, '') AS relation_attributes_json_internal,
       coalesce(finding.attributes_json, '') AS finding_attributes_json_internal
ORDER BY finding_urn, resource_urn
LIMIT %d`, strings.Join([]string{
			cypherJSONStringAttributes("r.attributes_json", "status"),
			cypherJSONStringAttributes("finding.attributes_json", "status"),
		}, ",\n       "), strings.Join([]string{
			cypherJSONStringAttributes("r.attributes_json", "control_refs"),
			cypherJSONStringAttributes("finding.attributes_json", "control_refs"),
		}, ",\n       "), postProcessingCandidateRowLimit), true
	case IntentExplainFinding:
		return fmt.Sprintf(`MATCH (finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE $scope_urn = ''
   OR finding.urn = $scope_urn
   OR EXISTS {
     MATCH (scopedResource:Entity {tenant_id: $tenant_id, urn: $scope_urn})-[:RELATION {relation: 'has_finding'}]->(finding)
   }
OPTIONAL MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding)
WITH resource, r, finding,
     coalesce(
       %s,
       0
     ) AS risk_score,
     coalesce(
       %s,
       ''
     ) AS severity,
     coalesce(
       %s,
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
LIMIT %d`, strings.Join([]string{
			cypherJSONIntegerAttribute("r.attributes_json", "risk_score"),
			cypherJSONIntegerAttribute("finding.attributes_json", "risk_score"),
		}, ",\n       "), cypherJSONStringAttributes("finding.attributes_json", "severity"), cypherJSONStringAttributes("finding.attributes_json", "status"), limit), true
	case IntentIdentityBridge:
		return fmt.Sprintf(`MATCH (left:Entity {tenant_id: $tenant_id})-[leftRel:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})
MATCH (right:Entity {tenant_id: $tenant_id})-[rightRel:RELATION {relation: 'represents_identity'}]->(identity2:Entity {tenant_id: $tenant_id})
WHERE left.urn < right.urn
  AND identity2.urn = identity.urn
  AND left.entity_type <> right.entity_type
  AND CASE
        WHEN $scope_urn = '' THEN true
        WHEN left.urn = $scope_urn THEN true
        WHEN right.urn = $scope_urn THEN true
        WHEN identity.urn = $scope_urn THEN true
        ELSE false
      END
  AND NOT left.entity_type STARTS WITH 'identity'
  AND NOT right.entity_type STARTS WITH 'identity'
  AND NOT left.entity_type STARTS WITH 'identifier'
  AND NOT right.entity_type STARTS WITH 'identifier'
WITH left, right, identity,
     coalesce(%s, '') AS left_seen_at,
     coalesce(%s, '') AS right_seen_at
WHERE left_seen_at =~ '^\\d{4}-\\d{2}-\\d{2}T.*'
  AND right_seen_at =~ '^\\d{4}-\\d{2}-\\d{2}T.*'
  AND datetime(left_seen_at) >= datetime() - duration('P90D')
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
LIMIT %d`, cypherJSONStringAttributes("leftRel.attributes_json", "at"), cypherJSONStringAttributes("rightRel.attributes_json", "at"), limit), true
	case IntentConnectorHealth:
		return fmt.Sprintf(`MATCH (source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
WHERE $scope_urn = '' OR source.urn = $scope_urn
RETURN source.urn AS source_urn,
       coalesce(source.label, source.urn) AS source_label,
       source.source_id AS source_id,
       source.runtime_id AS runtime_id,
       coalesce(source.attributes_json, '') AS source_attributes_json_internal
ORDER BY source_label, source_urn
LIMIT %d`, limit), true
	default:
		return "", false
	}
}

func cypherJSONStringAttributes(expression string, keys ...string) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("CASE WHEN coalesce(%s, '') CONTAINS '%s' THEN %s END", expression, cypherJSONQuotedStringToken(key), cypherJSONRawStringAttribute(expression, key)))
	}
	return strings.Join(parts, ",\n       ")
}

func cypherJSONIntegerAttribute(expression string, key string) string {
	return fmt.Sprintf("CASE WHEN coalesce(%s, '') CONTAINS '%s' THEN toInteger(%s) END", expression, cypherJSONQuotedStringToken(key), cypherJSONRawStringAttribute(expression, key))
}

func cypherJSONRawStringAttribute(expression string, key string) string {
	token := cypherJSONQuotedStringToken(key)
	return fmt.Sprintf(`split(split(%s, '%s')[1], '"')[0]`, expression, token)
}

func cypherJSONQuotedStringToken(key string) string {
	return fmt.Sprintf(`"%s":"`, key)
}

func topRiskFilterClauses(filters map[string]string) (string, string) {
	var projection []string
	var predicates []string
	if severity := planFilterValue(filters, "severity"); severity != "" {
		projection = append(projection, fmt.Sprintf("coalesce(\n       %s,\n       ''\n     ) AS filter_severity", strings.Join([]string{
			cypherJSONStringAttributes("r.attributes_json", "effective_severity", "severity"),
			cypherJSONStringAttributes("finding.attributes_json", "effective_severity", "severity"),
		}, ",\n       ")))
		predicates = append(predicates, "toUpper(filter_severity) = "+cypherStringLiteral(strings.ToUpper(severity)))
	}
	if status := planFilterValue(filters, "status"); status != "" {
		projection = append(projection, fmt.Sprintf("coalesce(\n       %s,\n       ''\n     ) AS filter_status", strings.Join([]string{
			cypherJSONStringAttributes("r.attributes_json", "status"),
			cypherJSONStringAttributes("finding.attributes_json", "status"),
		}, ",\n       ")))
		predicates = append(predicates, "toLower(filter_status) = "+cypherStringLiteral(strings.ToLower(status)))
	}
	if resourceType := firstNonEmpty(planFilterValue(filters, "resource_type"), planFilterValue(filters, "entity_type")); resourceType != "" {
		predicates = append(predicates, resourceTypePredicate(resourceType))
	}
	if len(predicates) == 0 {
		return "", ""
	}
	if len(projection) == 0 {
		return "", "WHERE " + strings.Join(predicates, "\n  AND ")
	}
	return ",\n     " + strings.Join(projection, ",\n     "), "WHERE " + strings.Join(predicates, "\n  AND ")
}

func resourceTypePredicate(value string) string {
	canonical := canonicalEntityType(value)
	switch canonical {
	case "github.code.repository":
		return "resource.entity_type = 'github.code.repository'"
	default:
		return "resource.entity_type = " + cypherStringLiteral(canonical)
	}
}

func planFilterValue(filters map[string]string, key string) string {
	for filterKey, value := range filters {
		if strings.EqualFold(filterKey, key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cypherStringLiteral(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "'", "\\'")
	return "'" + escaped + "'"
}

func hasUnsupportedDeterministicModifiers(plan AskQueryPlan) bool {
	groupBy := strings.ToLower(strings.TrimSpace(plan.GroupBy))
	if groupBy != "" && (plan.Intent != IntentAggregateFindingsBySource || groupBy != "source_family") {
		return true
	}
	for key := range plan.Filters {
		normalized := strings.ToLower(strings.TrimSpace(key))
		switch plan.Intent {
		case IntentTopRiskFindings:
			if normalized != "severity" && normalized != "status" && normalized != "resource_type" && normalized != "entity_type" {
				return true
			}
		case IntentFailingControls:
			return true
		default:
			return true
		}
	}
	return false
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

func enforceCypherLimit(cypher string, defaultMaxRows int) (string, ConversionDiagnostic, bool) {
	limit := boundedLimit(defaultMaxRows, defaultMaxRows)
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cypher), ";"))
	if trimmed == "" {
		return cypher, ConversionDiagnostic{}, false
	}
	matches := cypherLimitPattern.FindAllStringSubmatchIndex(trimmed, -1)
	if len(matches) == 0 {
		return trimmed + fmt.Sprintf("\nLIMIT %d", limit), ConversionDiagnostic{
			Level:   "info",
			Code:    "limit_injected",
			Message: fmt.Sprintf("Added LIMIT %d to LLM fallback Cypher.", limit),
		}, true
	}
	valueStart, valueEnd := matches[len(matches)-1][2], matches[len(matches)-1][3]
	current, ok := queryLimit(lexCypher(trimmed))
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

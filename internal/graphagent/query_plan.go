package graphagent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
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
	IntentOktaPrivilegedWeakMFA     = "okta_privileged_weak_mfa"
	IntentOktaDormantAccess         = "okta_dormant_access"
	IntentOktaGroupAccessRisk       = "okta_group_access_risk"
	IntentQuestionnaireEvidence     = "questionnaire_evidence_answer"
	IntentMITREAttackCoverage       = "mitre_attack_coverage"

	postProcessingCandidateRowLimit        = ports.MaxCypherQueryRows
	questionnaireEvidenceCandidateRowLimit = postProcessingCandidateRowLimit
	confidentPlanThreshold                 = 0.70
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
	case IntentFailingControls, IntentAggregateFindingsBySource, IntentConnectorHealth, IntentIdentityBridge, IntentOktaPrivilegedWeakMFA, IntentOktaDormantAccess, IntentOktaGroupAccessRisk:
		plan.Filters = map[string]string{}
	case IntentMITREAttackCoverage:
		plan.Filters = fastPathMITREAttackCoverageFilters(question)
	case IntentQuestionnaireEvidence:
		plan.Filters = fastPathQuestionnaireEvidenceFilters(question)
		if planFilterValue(plan.Filters, "topic") == "" {
			return AskQueryPlan{}, false
		}
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

func looksLikeQuestionnaireEvidenceQuestion(haystack string) bool {
	return planFilterValue(fastPathQuestionnaireEvidenceFilters(haystack), "topic") != ""
}

func fastPathMITREAttackCoverageFilters(question string) map[string]string {
	filters := map[string]string{}
	lower := strings.ToLower(question)
	if containsAny(lower, "gap", "gaps", "missing", "uncovered", "unsupported", "unconfigured", "failed", "stale") {
		filters["coverage_state"] = "gap"
	}
	return filters
}

func fastPathQuestionnaireEvidenceFilters(question string) map[string]string {
	filters := map[string]string{"answer_mode": "bounded_graph_evidence"}
	if topic := questionnaireEvidenceTopic(question); topic != "" {
		filters["topic"] = topic
	}
	return filters
}

func questionnaireEvidenceTopic(question string) string {
	terms := newQuestionnaireEvidenceTerms(question)
	if terms.hasFindingRetrievalContext() || terms.hasInventoryContext() {
		return ""
	}
	answerContext := terms.hasQuestionnaireAnswerContext()
	oktaContext := answerContext || terms.startsWith("show")
	evidencePacketCoverageContext := terms.hasPhrase("evidence packet") &&
		(terms.has("coverage") || terms.has("gap") || terms.has("gaps") || terms.has("control") || terms.has("controls"))
	switch {
	case terms.has("okta") && (terms.has("mfa") || terms.hasPhrase("multi factor") || terms.has("multifactor")) && oktaContext:
		return "okta_mfa"
	case terms.has("okta") && terms.has("lifecycle") && oktaContext:
		return "okta_lifecycle"
	case terms.has("okta") && terms.has("access") && oktaContext:
		return "okta_access"
	case (terms.has("mfa") || terms.hasPhrase("multi factor") || terms.has("multifactor")) && answerContext:
		return "identity_mfa"
	case (terms.hasPhrase("access review") ||
		terms.has("sso") ||
		terms.has("permission") ||
		terms.has("permissions") ||
		terms.has("provision") ||
		terms.has("deprovision") ||
		(terms.has("access") && terms.hasAnswerContext())) && answerContext:
		return "access_review"
	case (terms.has("encrypt") || terms.has("encryption") || terms.has("encrypted") || terms.has("key") || terms.has("keys") || terms.has("kms") || terms.has("tls")) && answerContext:
		return "encryption"
	case (terms.has("incident") || terms.has("breach") || terms.hasPhrase("incident response")) && answerContext:
		return "incident_response"
	case (terms.has("vendor") || terms.has("vendors") || terms.hasPhrase("third party")) && (terms.hasPhrase("due diligence") || terms.has("diligence") || terms.has("assurance") || terms.has("review")) && (answerContext || terms.startsWith("show")):
		return "vendor_due_diligence"
	case (terms.has("subprocessor") || terms.has("subprocessors") || terms.hasPhrase("third party")) && answerContext:
		return "subprocessors"
	case (terms.has("soc") || terms.has("soc2") || terms.hasPhrase("soc 2") || terms.has("iso") || terms.has("audit") || terms.has("assurance")) && (terms.has("report") || terms.has("reports") || answerContext):
		return "audit_report"
	case (terms.hasPhrase("policy doc") || terms.hasPhrase("policy document")) && terms.hasAnswerContext():
		return "policy_documents"
	case (terms.has("policy") || terms.has("policies") || terms.has("document") || terms.has("documents")) && answerContext:
		return "policy_documents"
	case (terms.has("ai") || terms.has("model") || terms.has("models") || terms.has("training") || terms.hasPhrase("data use") || terms.has("retention")) && answerContext:
		return "ai_data_use"
	case (terms.hasPhrase("control coverage") ||
		terms.hasPhrase("coverage gap") ||
		terms.hasPhrase("evidence gap") ||
		evidencePacketCoverageContext ||
		terms.hasPhrase("mapped control")) &&
		(terms.hasAnswerContext() || terms.has("show")):
		return "control_coverage"
	default:
		return ""
	}
}

type questionnaireEvidenceTerms struct {
	normalized string
	tokens     map[string]struct{}
	firstToken string
}

var questionnaireEvidenceTokenPattern = regexp.MustCompile(`[a-z0-9]+`)

func newQuestionnaireEvidenceTerms(question string) questionnaireEvidenceTerms {
	normalized := strings.ToLower(strings.NewReplacer("-", " ", "_", " ", "/", " ").Replace(question))
	tokenValues := questionnaireEvidenceTokenPattern.FindAllString(normalized, -1)
	tokens := make(map[string]struct{}, len(tokenValues))
	for _, token := range tokenValues {
		tokens[token] = struct{}{}
	}
	firstToken := ""
	if len(tokenValues) > 0 {
		firstToken = tokenValues[0]
	}
	return questionnaireEvidenceTerms{
		normalized: " " + strings.Join(tokenValues, " ") + " ",
		tokens:     tokens,
		firstToken: firstToken,
	}
}

func (terms questionnaireEvidenceTerms) has(token string) bool {
	_, ok := terms.tokens[strings.ToLower(strings.TrimSpace(token))]
	return ok
}

func (terms questionnaireEvidenceTerms) hasPhrase(phrase string) bool {
	phraseTerms := questionnaireEvidenceTokenPattern.FindAllString(strings.ToLower(phrase), -1)
	if len(phraseTerms) == 0 {
		return false
	}
	return strings.Contains(terms.normalized, " "+strings.Join(phraseTerms, " ")+" ")
}

func (terms questionnaireEvidenceTerms) startsWith(tokens ...string) bool {
	for _, token := range tokens {
		if terms.firstToken == strings.ToLower(strings.TrimSpace(token)) {
			return true
		}
	}
	return false
}

func (terms questionnaireEvidenceTerms) hasAnswerContext() bool {
	return terms.has("answer") ||
		terms.has("answers") ||
		terms.has("audit") ||
		terms.has("auditor") ||
		terms.has("compliance") ||
		terms.has("question") ||
		terms.has("questionnaire")
}

func (terms questionnaireEvidenceTerms) hasQuestionnaireAnswerContext() bool {
	return terms.hasAnswerContext() ||
		terms.has("evidence") ||
		terms.has("proof") ||
		terms.has("review") ||
		terms.startsWith("does", "can", "do", "is", "are", "provide", "explain")
}

func (terms questionnaireEvidenceTerms) hasFindingRetrievalContext() bool {
	return (terms.has("finding") || terms.has("findings")) &&
		(terms.has("show") || terms.has("list") || terms.has("source") || terms.has("evidence"))
}

func (terms questionnaireEvidenceTerms) hasInventoryContext() bool {
	return terms.has("inventory") ||
		terms.has("catalog") ||
		terms.has("count") ||
		terms.has("counts") ||
		terms.hasPhrase("list all")
}

func containsWord(haystack string, needle string) bool {
	if strings.TrimSpace(needle) == "" {
		return false
	}
	pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(strings.ToLower(needle)) + `\b`)
	return pattern.MatchString(strings.ToLower(haystack))
}

func containsAny(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if fragment != "" && strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func mentionsOktaMFAPosture(haystack string) bool {
	return strings.Contains(haystack, "mfa") || strings.Contains(haystack, "factor") || strings.Contains(haystack, "phishing resistant")
}

func lacksOktaMFAPosture(haystack string) bool {
	if !mentionsOktaMFAPosture(haystack) {
		return false
	}
	return containsWord(haystack, "lack") || containsWord(haystack, "lacks") || containsWord(haystack, "lacking") || containsWord(haystack, "missing") || strings.Contains(haystack, "without mfa")
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
	if isOktaDeterministicIntent(out.Intent) {
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

func isOktaDeterministicIntent(intent string) bool {
	switch intent {
	case IntentOktaPrivilegedWeakMFA, IntentOktaDormantAccess, IntentOktaGroupAccessRisk:
		return true
	default:
		return false
	}
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
	case "okta_privileged_weak_mfa", "okta_privileged_without_strong_mfa", "okta_admin_weak_mfa":
		return IntentOktaPrivilegedWeakMFA
	case "okta_dormant_access", "okta_dormant_users_with_access":
		return IntentOktaDormantAccess
	case "okta_group_access_risk", "okta_risky_group_memberships":
		return IntentOktaGroupAccessRisk
	case "questionnaire_evidence_answer", "questionnaire_answer", "compliance_answer", "control_coverage":
		return IntentQuestionnaireEvidence
	case "mitre_attack_coverage", "attack_coverage", "mitre_coverage", "attack_coverage_gaps", "mitre_coverage_gaps":
		return IntentMITREAttackCoverage
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func inferIntent(question string, cypher string) string {
	haystack := strings.ToLower(question + "\n" + cypher)
	switch {
	case (strings.Contains(haystack, "high risk") || strings.Contains(haystack, "top risk") || strings.Contains(haystack, "critical")) && strings.Contains(haystack, "finding"):
		return IntentTopRiskFindings
	case strings.Contains(haystack, "connector") || strings.Contains(haystack, "runtime health") || strings.Contains(haystack, "source health"):
		return IntentConnectorHealth
	case (strings.Contains(haystack, "control") || strings.Contains(haystack, "controls")) && (containsWord(haystack, "failing") || containsWord(haystack, "failed") || containsWord(haystack, "fail") || containsWord(haystack, "failure") || containsWord(haystack, "failures") || strings.Contains(haystack, "not passing")):
		return IntentFailingControls
	case strings.Contains(haystack, "source") && strings.Contains(haystack, "finding") && (strings.Contains(haystack, "count") || strings.Contains(haystack, "breakdown") || strings.Contains(haystack, "group") || strings.Contains(haystack, "top")):
		return IntentAggregateFindingsBySource
	case strings.Contains(haystack, "has_source") || strings.Contains(haystack, "belongs_to_source") || strings.Contains(haystack, "source_family"):
		return IntentAggregateFindingsBySource
	case strings.Contains(haystack, "bridge") && (strings.Contains(haystack, "identity") || strings.Contains(haystack, "okta") || strings.Contains(haystack, "github")):
		return IntentIdentityBridge
	case strings.Contains(haystack, "okta") && containsWord(haystack, "privileged") && (strings.Contains(haystack, "strong mfa") || strings.Contains(haystack, "weak mfa") || strings.Contains(haystack, "phishing resistant") || lacksOktaMFAPosture(haystack)):
		return IntentOktaPrivilegedWeakMFA
	case strings.Contains(haystack, "okta") && strings.Contains(haystack, "dormant") && (strings.Contains(haystack, "access") || strings.Contains(haystack, "admin") || strings.Contains(haystack, "app")):
		return IntentOktaDormantAccess
	case strings.Contains(haystack, "okta") && strings.Contains(haystack, "group") && (strings.Contains(haystack, "risk") || strings.Contains(haystack, "membership") || strings.Contains(haystack, "access")):
		return IntentOktaGroupAccessRisk
	case looksLikeMITREAttackCoverageQuestion(haystack):
		return IntentMITREAttackCoverage
	case strings.Contains(haystack, "explain") && strings.Contains(haystack, "finding"):
		return IntentExplainFinding
	case looksLikeQuestionnaireEvidenceQuestion(haystack):
		return IntentQuestionnaireEvidence
	default:
		return IntentRawCypher
	}
}

func looksLikeMITREAttackCoverageQuestion(haystack string) bool {
	if !containsAny(haystack, "mitre", "att&ck", "attack", "d3fend", "defend") {
		return false
	}
	return containsAny(haystack, "coverage", "gap", "gaps", "technique", "techniques", "tactic", "tactics", "data component", "data source", "defense", "defensive")
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
			cypherJSONStringAttributes("r.attributes_json", "control_refs", "controlRefs"),
			cypherJSONStringAttributes("finding.attributes_json", "control_refs", "controlRefs"),
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
	case IntentOktaPrivilegedWeakMFA:
		return fmt.Sprintf(`MATCH (user:Entity {tenant_id: $tenant_id, entity_type: 'okta.user'})-[admin:RELATION {relation: 'can_admin'}]->(role:Entity {tenant_id: $tenant_id, entity_type: 'okta.admin_role'})
WHERE admin.tenant_id = $tenant_id
WITH user, admin, role,
     coalesce(%s, '') AS status,
     coalesce(%s, '') AS mfa_enrolled,
     coalesce(%s, '') AS mfa_factor_count,
     coalesce(%s, '') AS mfa_factor_types,
     coalesce(%s, '') AS mfa_phishing_resistant,
     coalesce(%s, '') AS user_source_event_id,
     coalesce(%s, '') AS observed_at,
     coalesce(%s, '') AS admin_event_id,
     coalesce(%s, '') AS admin_at
WHERE user.mfa_disabled = true OR toLower(mfa_phishing_resistant) = 'false'
RETURN user.urn AS user_urn,
       coalesce(user.label, user.urn) AS user_label,
       status,
       mfa_enrolled,
       mfa_factor_count,
       mfa_factor_types,
       mfa_phishing_resistant,
       role.urn AS admin_role_urn,
       coalesce(role.label, role.urn) AS admin_role_label,
       admin_event_id,
       admin_at,
       user_source_event_id,
       observed_at,
       'Okta factor summary only; missing factor detail is not treated as weak MFA.' AS overclaim_guard
ORDER BY user_label, admin_role_label
LIMIT %d`, cypherJSONStringAttributes("user.attributes_json", "status"), cypherJSONStringAttributes("user.attributes_json", "mfa_enrolled"), cypherJSONStringAttributes("user.attributes_json", "mfa_factor_count"), cypherJSONStringAttributes("user.attributes_json", "mfa_factor_types"), cypherJSONStringAttributes("user.attributes_json", "mfa_phishing_resistant"), cypherJSONStringAttributes("user.attributes_json", "source_event_id"), cypherJSONStringAttributes("user.attributes_json", "observed_at"), cypherJSONStringAttributes("admin.attributes_json", "event_id", "source_event_id"), cypherJSONStringAttributes("admin.attributes_json", "at", "observed_at"), limit), true
	case IntentOktaDormantAccess:
		return fmt.Sprintf(`MATCH (user:Entity {tenant_id: $tenant_id, entity_type: 'okta.user'})
WITH user,
     coalesce(%s, '') AS status,
     coalesce(%s, '') AS last_login_at,
     coalesce(%s, '') AS user_source_event_id,
     coalesce(%s, '') AS observed_at
WHERE toUpper(status) IN ['ACTIVE','PROVISIONED','STAGED','PASSWORD_EXPIRED','RECOVERY']
  AND (
    last_login_at = ''
    OR (last_login_at =~ '^\\d{4}-\\d{2}-\\d{2}T.*' AND datetime(last_login_at) < datetime() - duration('P90D'))
  )
CALL {
  WITH user
  MATCH (user)-[access:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE access.tenant_id = $tenant_id AND target.entity_type = 'okta.application'
  RETURN target, null AS mediator, access, 'direct_app_assignment' AS assignment_kind, '' AS membership_event_id
  UNION
  WITH user
  MATCH (user)-[membership:RELATION {relation: 'member_of'}]->(mediator:Entity {tenant_id: $tenant_id})-[access:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE membership.tenant_id = $tenant_id AND access.tenant_id = $tenant_id AND target.entity_type = 'okta.application'
  WITH target, mediator, access, coalesce(%s, '') AS membership_event_id
  RETURN target, mediator, access, 'group_app_assignment' AS assignment_kind, membership_event_id
  UNION
  WITH user
  MATCH (user)-[access:RELATION {relation: 'can_admin'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE access.tenant_id = $tenant_id AND target.entity_type = 'okta.admin_role'
  RETURN target, null AS mediator, access, 'admin_role_assignment' AS assignment_kind, '' AS membership_event_id
}
WITH user, status, last_login_at, user_source_event_id, observed_at, target, mediator, access, assignment_kind, membership_event_id,
     coalesce(%s, '') AS access_event_id,
     coalesce(%s, '') AS access_at
RETURN user.urn AS user_urn,
       coalesce(user.label, user.urn) AS user_label,
       status,
       last_login_at,
       assignment_kind,
       coalesce(mediator.urn, '') AS mediator_urn,
       coalesce(mediator.label, '') AS mediator_label,
       target.urn AS access_target_urn,
       coalesce(target.label, target.urn) AS access_target_label,
       target.entity_type AS access_target_type,
       membership_event_id,
       access_event_id,
       access_at,
       user_source_event_id,
       observed_at,
       'Dormant means active Okta user with last_login_at older than 90 days or no last_login_at in the projected Okta user record.' AS overclaim_guard
ORDER BY user_label, assignment_kind, access_target_label
LIMIT %d`, cypherJSONStringAttributes("user.attributes_json", "status"), cypherJSONStringAttributes("user.attributes_json", "last_login_at"), cypherJSONStringAttributes("user.attributes_json", "source_event_id"), cypherJSONStringAttributes("user.attributes_json", "observed_at"), cypherJSONStringAttributes("membership.attributes_json", "event_id", "source_event_id"), cypherJSONStringAttributes("access.attributes_json", "event_id", "source_event_id"), cypherJSONStringAttributes("access.attributes_json", "at", "observed_at"), limit), true
	case IntentOktaGroupAccessRisk:
		return fmt.Sprintf(`MATCH (group:Entity {tenant_id: $tenant_id, entity_type: 'okta.group'})-[assignment:RELATION {relation: 'assigned_to'}]->(app:Entity {tenant_id: $tenant_id, entity_type: 'okta.application'})
WHERE assignment.tenant_id = $tenant_id
OPTIONAL MATCH (app)-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
WHERE grant.tenant_id = $tenant_id AND confers.tenant_id = $tenant_id
OPTIONAL MATCH (member:Entity {tenant_id: $tenant_id, entity_type: 'okta.user'})-[membership:RELATION {relation: 'member_of'}]->(group)
WHERE membership.tenant_id = $tenant_id
WITH group, assignment, app, entitlement, capability,
     count(DISTINCT member.urn) AS direct_member_count,
     coalesce(%s, '') AS assignment_event_id,
     coalesce(%s, '') AS assignment_at
RETURN group.urn AS group_urn,
       coalesce(group.label, group.urn) AS group_label,
       direct_member_count,
       app.urn AS app_urn,
       coalesce(app.label, app.urn) AS app_label,
       coalesce(entitlement.urn, '') AS entitlement_urn,
       coalesce(entitlement.label, '') AS entitlement_label,
       coalesce(capability.urn, '') AS capability_urn,
       coalesce(capability.label, '') AS capability_label,
       assignment_event_id,
       assignment_at,
       CASE
         WHEN coalesce(capability.urn, '') ENDS WITH ':cloud_admin' OR coalesce(capability.urn, '') ENDS WITH ':identity_admin' THEN 'privileged_group_app_access'
         ELSE 'group_app_access'
       END AS risk_signal,
       'Group risk is derived from Okta group-to-application assignments and projected entitlement capability edges; enumerate members from member_of edges or okta.group_membership events, not group attributes.' AS overclaim_guard
ORDER BY risk_signal DESC, group_label, app_label
LIMIT %d`, cypherJSONStringAttributes("assignment.attributes_json", "event_id", "source_event_id"), cypherJSONStringAttributes("assignment.attributes_json", "at", "observed_at"), limit), true
	case IntentQuestionnaireEvidence:
		topicPredicate := questionnaireEvidenceTopicPredicate(plan.Filters)
		if topicPredicate == "" {
			return "", false
		}
		return renderQuestionnaireEvidenceQuery(topicPredicate), true
	case IntentMITREAttackCoverage:
		return renderMITREAttackCoverageQuery(plan, limit), true
	default:
		return "", false
	}
}

func renderMITREAttackCoverageQuery(plan AskQueryPlan, limit int) string {
	coverageStateFilter := strings.ToLower(strings.TrimSpace(planFilterValue(plan.Filters, "coverage_state")))
	coverageStatePredicate := ""
	if coverageStateFilter != "" {
		coverageStatePredicate = "\nWHERE toLower(coverage_state) = " + cypherStringLiteral(coverageStateFilter)
	}
	return fmt.Sprintf(`MATCH (anchor:Entity {tenant_id: $tenant_id})-[ctx:RELATION {relation: 'has_context'}]->(coverage:Entity {tenant_id: $tenant_id, entity_type: 'mitre.attack.coverage'})
WHERE ctx.tenant_id = $tenant_id
  AND (
    $scope_urn = ''
    OR anchor.urn = $scope_urn
    OR coverage.urn = $scope_urn
  )
MATCH (coverage)-[coverageTechnique:RELATION {relation: 'supports'}]->(technique:Entity {tenant_id: $tenant_id, entity_type: 'mitre.attack.technique'})
WHERE coverageTechnique.tenant_id = $tenant_id
WITH anchor, coverage, technique,
     coalesce(%s, '') AS coverage_state,
     coalesce(%s, '') AS coverage_status,
     coalesce(%s, '') AS evidence_surface%s
OPTIONAL MATCH (coverage)-[evidenceRel:RELATION {relation: 'has_evidence'}]->(component:Entity {tenant_id: $tenant_id, entity_type: 'mitre.attack.data_component'})
WHERE evidenceRel.tenant_id = $tenant_id
OPTIONAL MATCH (component)-[sourceRel:RELATION {relation: 'belongs_to'}]->(dataSource:Entity {tenant_id: $tenant_id, entity_type: 'mitre.attack.data_source'})
WHERE sourceRel.tenant_id = $tenant_id
OPTIONAL MATCH (defend:Entity {tenant_id: $tenant_id, entity_type: 'mitre.defend.technique'})-[defends:RELATION {relation: 'supports'}]->(technique)
WHERE defends.tenant_id = $tenant_id
RETURN anchor.urn AS anchor_urn,
       coalesce(anchor.label, anchor.urn) AS anchor_label,
       anchor.entity_type AS anchor_type,
       coverage.urn AS coverage_urn,
       coalesce(coverage.label, coverage.urn) AS coverage_label,
       coverage_state,
       coverage_status,
       evidence_surface,
       technique.urn AS technique_urn,
       coalesce(technique.label, technique.urn) AS technique_label,
       component.urn AS data_component_urn,
       coalesce(component.label, component.urn) AS data_component_label,
       dataSource.urn AS data_source_urn,
       coalesce(dataSource.label, dataSource.urn) AS data_source_label,
       defend.urn AS defend_technique_urn,
       coalesce(defend.label, defend.urn) AS defend_technique_label,
       'MITRE coverage rows are projected graph context; treat missing data components as missing projected evidence, not proof no telemetry exists.' AS overclaim_guard
ORDER BY coverage_state DESC, technique_label, anchor_label, data_component_label
LIMIT %d`, cypherJSONStringAttributes("coverage.attributes_json", "coverage_state"), cypherJSONStringAttributes("coverage.attributes_json", "coverage_status"), cypherJSONStringAttributes("coverage.attributes_json", "evidence_surface"), coverageStatePredicate, limit)
}

var questionnaireEvidenceQueryFragments = []string{
	`MATCH (control:Entity {tenant_id: $tenant_id, entity_type: 'policy'})
WITH control,
     coalesce(__CONTROL_POLICY_TYPE__, '') AS control_policy_type,
     coalesce(__CONTROL_REF__, '') AS control_ref
WHERE control_policy_type = 'control'
  AND CASE
        WHEN $scope_urn = '' THEN true
        WHEN control.urn = $scope_urn THEN true
        ELSE false
      END`,
	`OPTIONAL MATCH (support:Entity {tenant_id: $tenant_id})-[supportRel:RELATION {relation: 'supports'}]->(control)
WHERE CASE
        WHEN $scope_urn = '' THEN true
        WHEN support.urn = $scope_urn THEN true
        WHEN control.urn = $scope_urn THEN true
        ELSE false
      END
OPTIONAL MATCH (support)-[supportEvidenceRel:RELATION {relation: 'has_evidence'}]->(supportEvidence:Entity {tenant_id: $tenant_id})
WITH DISTINCT control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel`,
	`OPTIONAL MATCH (control)-[controlEvidenceRel:RELATION {relation: 'has_evidence'}]->(controlEvidence:Entity {tenant_id: $tenant_id})
WITH DISTINCT control, control_ref, support, supportRel,
     supportEvidence,
     supportEvidenceRel,
     controlEvidence,
     controlEvidenceRel,
     coalesce(supportEvidence, controlEvidence) AS evidence,
     coalesce(supportEvidenceRel, controlEvidenceRel) AS evidenceRel
WHERE evidence IS NOT NULL OR support IS NOT NULL`,
	`OPTIONAL MATCH (support)-[findingRel:RELATION]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
WHERE findingRel.relation IN ['associated_with', 'supports', 'has_finding'] OR finding IS NULL
WITH DISTINCT control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel, controlEvidence, controlEvidenceRel, evidence, evidenceRel, finding, findingRel
OPTIONAL MATCH (exception:Entity {tenant_id: $tenant_id})-[exceptionRel:RELATION]->(control)
WHERE exception IS NULL OR exception.entity_type CONTAINS 'exception' OR exception.urn CONTAINS 'exception'
WITH DISTINCT control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel, controlEvidence, controlEvidenceRel, evidence, evidenceRel, finding, findingRel, exception, exceptionRel`,
	`WITH control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel, controlEvidence, controlEvidenceRel, evidence, evidenceRel, finding, findingRel, exception, exceptionRel,
     coalesce(__CONTROL_MATCH_ATTRIBUTES__, '') AS control_match_attributes,
     coalesce(__SUPPORT_MATCH_ATTRIBUTES__, '') AS support_match_attributes,
     coalesce(__EVIDENCE_MATCH_ATTRIBUTES__, '') AS evidence_match_attributes,
     coalesce(__DIRECT_EVIDENCE_MATCH_ATTRIBUTES__, '') AS direct_evidence_match_attributes
WITH control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel, controlEvidence, controlEvidenceRel, evidence, evidenceRel, finding, findingRel, exception, exceptionRel,
     toLower(coalesce(control.label, '') + ' ' +
             coalesce(control.source_id, '') + ' ' +
             coalesce(control_ref, '') + ' ' +
             control_match_attributes + ' ' +
             coalesce(support.label, '') + ' ' +
             coalesce(support.source_id, '') + ' ' +
             support_match_attributes + ' ' +
             coalesce(evidence.label, '') + ' ' +
             coalesce(evidence.source_id, '') + ' ' +
             evidence_match_attributes + ' ' +
             coalesce(controlEvidence.label, '') + ' ' +
             coalesce(controlEvidence.source_id, '') + ' ' +
             direct_evidence_match_attributes) AS questionnaire_match_text,
     coalesce(evidence.source_id, support.source_id, control.source_id, '') AS evidence_source_id
__TOPIC_PREDICATE__
OPTIONAL MATCH (source:Entity {tenant_id: $tenant_id, entity_type: 'source'})
WHERE evidence_source_id <> '' AND source.source_id = evidence_source_id`,
	`RETURN DISTINCT control.urn AS control_urn,
       coalesce(control.label, control_ref, control.urn) AS control_label,
       control_ref,
       coalesce(control.attributes_json, '') AS control_attributes_json_internal,
       support.urn AS support_urn,
       coalesce(support.label, support.urn) AS support_label,
       support.entity_type AS support_type,
       support.source_id AS support_source_id,
       supportRel.relation AS support_relation,
       coalesce(support.attributes_json, '') AS support_attributes_json_internal,
       evidence.urn AS evidence_urn,
       coalesce(evidence.label, evidence.urn) AS evidence_label,
       evidence.entity_type AS evidence_type,
       evidence_source_id,
       evidenceRel.relation AS evidence_relation,
       coalesce(evidence.attributes_json, '') AS evidence_attributes_json_internal,
       controlEvidence.urn AS direct_evidence_urn,
       coalesce(controlEvidence.label, controlEvidence.urn) AS direct_evidence_label,
       controlEvidence.entity_type AS direct_evidence_type,
       controlEvidence.source_id AS direct_evidence_source_id,
       controlEvidenceRel.relation AS direct_evidence_relation,
       coalesce(controlEvidence.attributes_json, '') AS direct_evidence_attributes_json_internal,
       finding.urn AS finding_urn,
       coalesce(finding.label, finding.urn) AS finding_label,
       findingRel.relation AS finding_relation,
       coalesce(finding.attributes_json, '') AS finding_attributes_json_internal,
       exception.urn AS exception_urn,
       coalesce(exception.label, exception.urn) AS exception_label,
       exception.entity_type AS exception_type,
       exceptionRel.relation AS exception_relation,
       coalesce(exception.attributes_json, '') AS exception_attributes_json_internal,
       source.urn AS source_urn,
       coalesce(source.label, source.urn) AS source_label,
       coalesce(source.attributes_json, '') AS source_attributes_json_internal
ORDER BY control_label, support_label, evidence_label
LIMIT __CANDIDATE_LIMIT__`,
}

func renderQuestionnaireEvidenceQuery(topicPredicate string) string {
	return replaceQuestionnaireEvidencePlaceholders(strings.Join(questionnaireEvidenceQueryFragments, "\n"), map[string]string{
		"__CONTROL_POLICY_TYPE__":              cypherJSONStringAttributes("control.attributes_json", "policy_type"),
		"__CONTROL_REF__":                      cypherJSONStringAttributes("control.attributes_json", "control_external_id", "control_id", "policy_id"),
		"__CONTROL_MATCH_ATTRIBUTES__":         cypherJSONStringAttributes("control.attributes_json", "control_external_id", "control_id", "policy_id"),
		"__SUPPORT_MATCH_ATTRIBUTES__":         cypherJSONStringAttributes("support.attributes_json", "evidence_type", "document_type", "policy_document_type", "policy_type", "questionnaire_type", "source_system"),
		"__EVIDENCE_MATCH_ATTRIBUTES__":        cypherJSONStringAttributes("evidence.attributes_json", "evidence_type", "document_type", "policy_document_type", "policy_type", "questionnaire_type", "source_system"),
		"__DIRECT_EVIDENCE_MATCH_ATTRIBUTES__": cypherJSONStringAttributes("controlEvidence.attributes_json", "evidence_type", "document_type", "policy_document_type", "policy_type", "questionnaire_type", "source_system"),
		"__TOPIC_PREDICATE__":                  topicPredicate,
		"__CANDIDATE_LIMIT__":                  fmt.Sprint(questionnaireEvidenceCandidateRowLimit),
	})
}

func replaceQuestionnaireEvidencePlaceholders(template string, values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	replacements := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		replacements = append(replacements, key, values[key])
	}
	return strings.NewReplacer(replacements...).Replace(template)
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

func questionnaireEvidenceTopicPredicate(filters map[string]string) string {
	switch strings.ToLower(planFilterValue(filters, "topic")) {
	case "okta_mfa":
		return `WHERE CASE
        WHEN NOT ` + questionnaireMatchWordPredicate("okta") + ` THEN false
        WHEN ` + questionnaireMatchWordPredicate("mfa") + ` THEN true
        WHEN questionnaire_match_text CONTAINS 'multi factor' THEN true
        WHEN questionnaire_match_text CONTAINS 'multi-factor' THEN true
        WHEN ` + questionnaireMatchWordPredicate("multifactor") + ` THEN true
        ELSE false
      END`
	case "okta_lifecycle":
		return `WHERE CASE
        WHEN NOT ` + questionnaireMatchWordPredicate("okta") + ` THEN false
        WHEN ` + questionnaireMatchWordPredicate("lifecycle") + ` THEN true
        WHEN ` + questionnaireMatchWordPredicate("deprovision") + ` THEN true
        WHEN ` + questionnaireMatchWordPredicate("provision") + ` THEN true
        ELSE false
      END`
	case "okta_access":
		return `WHERE CASE
        WHEN NOT ` + questionnaireMatchWordPredicate("okta") + ` THEN false
        WHEN ` + questionnaireMatchWordPredicate("access") + ` THEN true
        WHEN ` + questionnaireMatchWordPredicate("sso") + ` THEN true
        WHEN ` + questionnaireMatchWordPredicate("group") + ` THEN true
        ELSE false
      END`
	case "identity_mfa":
		return "WHERE " + questionnaireAnyMatchPredicate(
			questionnaireMatchWordPredicate("mfa"),
			"questionnaire_match_text CONTAINS 'multi factor'",
			"questionnaire_match_text CONTAINS 'multi-factor'",
			questionnaireMatchWordPredicate("multifactor"),
		)
	case "access_review":
		return "WHERE " + questionnaireAnyMatchPredicate(
			"questionnaire_match_text CONTAINS 'access review'",
			questionnaireMatchWordPredicate("access"),
			questionnaireMatchWordPredicate("sso"),
			questionnaireMatchWordPredicate("permission"),
			questionnaireMatchWordPredicate("permissions"),
			questionnaireMatchWordPredicate("provision"),
			questionnaireMatchWordPredicate("deprovision"),
		)
	case "encryption":
		return "WHERE " + questionnaireAnyMatchPredicate(
			questionnaireMatchWordPredicate("encrypt"),
			questionnaireMatchWordPredicate("encryption"),
			questionnaireMatchWordPredicate("encrypted"),
			questionnaireMatchWordPredicate("key"),
			questionnaireMatchWordPredicate("keys"),
			questionnaireMatchWordPredicate("kms"),
			questionnaireMatchWordPredicate("tls"),
		)
	case "incident_response":
		return "WHERE " + questionnaireAnyMatchPredicate(
			"questionnaire_match_text CONTAINS 'incident response'",
			questionnaireMatchWordPredicate("incident"),
			questionnaireMatchWordPredicate("breach"),
			questionnaireMatchWordPredicate("response"),
		)
	case "subprocessors":
		return "WHERE " + questionnaireAnyMatchPredicate(
			questionnaireMatchWordPredicate("subprocessor"),
			questionnaireMatchWordPredicate("subprocessors"),
			"questionnaire_match_text CONTAINS 'third party'",
			"questionnaire_match_text CONTAINS 'third-party'",
		)
	case "audit_report":
		return "WHERE " + questionnaireAnyMatchPredicate(
			questionnaireMatchWordPredicate("soc"),
			questionnaireMatchWordPredicate("soc2"),
			"questionnaire_match_text CONTAINS 'soc 2'",
			questionnaireMatchWordPredicate("iso"),
			questionnaireMatchWordPredicate("audit"),
			questionnaireMatchWordPredicate("assurance"),
			questionnaireMatchWordPredicate("report"),
		)
	case "policy_documents":
		return "WHERE questionnaire_match_text CONTAINS 'policy document' OR questionnaire_match_text CONTAINS 'policy_document' OR " + questionnaireMatchWordPredicate("document")
	case "ai_data_use":
		return "WHERE " + questionnaireAnyMatchPredicate(
			questionnaireMatchWordPredicate("ai"),
			questionnaireMatchWordPredicate("model"),
			questionnaireMatchWordPredicate("models"),
			questionnaireMatchWordPredicate("training"),
			"questionnaire_match_text CONTAINS 'data use'",
			"questionnaire_match_text CONTAINS 'data-use'",
			questionnaireMatchWordPredicate("retention"),
		)
	case "vendor_due_diligence":
		return "WHERE " + questionnaireAnyMatchPredicate(
			"questionnaire_match_text CONTAINS 'due diligence'",
			questionnaireMatchWordPredicate("vendor"),
			questionnaireMatchWordPredicate("vendors"),
			questionnaireMatchWordPredicate("assurance"),
			questionnaireMatchWordPredicate("subprocessor"),
			"questionnaire_match_text CONTAINS 'third party'",
			"questionnaire_match_text CONTAINS 'third-party'",
		)
	case "control_coverage":
		return "WHERE " + questionnaireMatchWordPredicate("coverage") + " OR questionnaire_match_text CONTAINS 'coverage_gap' OR " + questionnaireMatchWordPredicate("gap") + " OR " + questionnaireMatchWordPredicate("missing")
	default:
		return ""
	}
}

func questionnaireAnyMatchPredicate(predicates ...string) string {
	nonEmpty := make([]string, 0, len(predicates))
	for _, predicate := range predicates {
		if strings.TrimSpace(predicate) != "" {
			nonEmpty = append(nonEmpty, predicate)
		}
	}
	return strings.Join(nonEmpty, " OR ")
}

func questionnaireMatchWordPredicate(word string) string {
	return "questionnaire_match_text =~ '(?s).*\\\\b" + regexp.QuoteMeta(strings.ToLower(word)) + "\\\\b.*'"
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
		case IntentQuestionnaireEvidence:
			if normalized != "topic" && normalized != "answer_mode" {
				return true
			}
		case IntentMITREAttackCoverage:
			if normalized != "coverage_state" {
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

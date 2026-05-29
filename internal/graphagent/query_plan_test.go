package graphagent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOntologyCanonicalizesAliases(t *testing.T) {
	if got := canonicalEntityType("Finding"); got != "finding" {
		t.Fatalf("canonicalEntityType(Finding) = %q, want finding", got)
	}
	if got, ok := canonicalRelation("BELONGS_TO_SOURCE"); !ok || got != "belongs_to" {
		t.Fatalf("canonicalRelation(BELONGS_TO_SOURCE) = %q, %v; want belongs_to, true", got, ok)
	}
}

func TestAskQueryPlanUnmarshalCoercesFilterValues(t *testing.T) {
	var plan AskQueryPlan
	if err := json.Unmarshal([]byte(`{"intent":"top_risk_findings","filters":{"risk_score":50,"active":true,"source":"github"}}`), &plan); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := plan.Filters["risk_score"]; got != "50" {
		t.Fatalf("risk_score filter = %q, want 50", got)
	}
	if got := plan.Filters["active"]; got != "true" {
		t.Fatalf("active filter = %q, want true", got)
	}
	if got := plan.Filters["source"]; got != "github" {
		t.Fatalf("source filter = %q, want github", got)
	}
}

func TestConvertDraftToQueryUsesDeterministicFindingSourceTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Count findings by source",
	}, &DraftResponse{
		Cypher: `MATCH (f:Entity {tenant_id: $tenant_id}) WHERE f.entity_type = 'Finding'
OPTIONAL MATCH (f)-[:HAS_SOURCE]->(src:Entity {tenant_id: $tenant_id})
RETURN apoc.convert.fromJsonMap(f.attributes_json).source_family AS source_family, count(f) LIMIT 10`,
	}, 100)

	if result.Plan.Intent != IntentAggregateFindingsBySource || !result.Deterministic || !result.Corrected {
		t.Fatalf("conversion result = %#v, want deterministic corrected source aggregation", result)
	}
	if strings.Contains(result.Cypher, "apoc.") || strings.Contains(result.Cypher, "HAS_SOURCE") || strings.Contains(result.Cypher, "'Finding'") {
		t.Fatalf("converted cypher is not canonical:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "f.source_id") || !strings.Contains(result.Cypher, "LIMIT 10") {
		t.Fatalf("converted cypher missing source_id fallback/limit:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "WHERE $scope_urn = '' OR resource.urn = $scope_urn OR f.urn = $scope_urn") {
		t.Fatalf("converted cypher missing scope predicate:\n%s", result.Cypher)
	}
	sourceFamilyIndex := strings.Index(result.Cypher, `"source_family":"`)
	sourceIDIndex := strings.Index(result.Cypher, "f.source_id")
	if sourceFamilyIndex < 0 || sourceIDIndex < 0 || sourceFamilyIndex > sourceIDIndex {
		t.Fatalf("converted cypher should prefer source_family before source_id:\n%s", result.Cypher)
	}
	if len(result.Diagnostics) == 0 {
		t.Fatalf("expected conversion diagnostics")
	}
}

func TestConvertDraftToQueryPreservesExplicitRefusal(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Delete risky nodes and show top finding sources",
	}, &DraftResponse{
		Plan:    &AskQueryPlan{Intent: IntentRawCypher},
		Refusal: "Read-only graph questions only.",
	}, 100)

	if result.Cypher != "" || result.Deterministic {
		t.Fatalf("conversion result = %#v, want preserved refusal without deterministic cypher", result)
	}
	if result.Plan.Intent != IntentRawCypher || result.Source != "llm_refusal" {
		t.Fatalf("conversion result = %#v, want raw llm refusal plan", result)
	}
}

func TestConvertDraftToQueryScopesTopRiskAndReturnsOnlyScalarFields(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show top risk findings for this repo",
		ScopeURN: "urn:cerebro:writer:repo:alpha",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentTopRiskFindings, Limit: 25},
	}, 100)

	if result.Plan.Intent != IntentTopRiskFindings || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic top risk template", result)
	}
	for _, want := range []string{
		"WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn",
		"CASE toUpper(severity)",
		"WHEN 'CRITICAL' THEN 4",
		"collect(DISTINCT resource.urn) AS resource_urns",
		"max(risk_score) AS risk_score",
		"ORDER BY risk_score DESC, severity_rank DESC, finding_urn",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	for _, forbidden := range []string{"finding_attributes_json", "relation_attributes_json", " AS attributes_json"} {
		if strings.Contains(result.Cypher, forbidden) {
			t.Fatalf("converted cypher returns raw attributes %q:\n%s", forbidden, result.Cypher)
		}
	}
}

func TestConvertDraftToQuerySkipsTemplateForUnsupportedFilters(t *testing.T) {
	draftCypher := `MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
RETURN finding.urn AS finding_urn
LIMIT 25`
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show high findings",
	}, &DraftResponse{
		Plan:   &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"severity": "HIGH"}},
		Cypher: draftCypher,
	}, 100)

	if result.Deterministic || result.Source != "llm" {
		t.Fatalf("conversion result = %#v, want LLM fallback for filtered plan", result)
	}
	if result.Cypher != draftCypher {
		t.Fatalf("cypher = %q, want unmodified draft", result.Cypher)
	}
}

func TestConvertDraftToQueryExplainFindingAvoidsBrittleSummaryExtraction(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Explain this finding",
		ScopeURN: "urn:cerebro:writer:finding:alpha",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentExplainFinding, Limit: 25},
	}, 100)

	if result.Plan.Intent != IntentExplainFinding || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic explain finding template", result)
	}
	if strings.Contains(result.Cypher, `"summary":"`) || strings.Contains(result.Cypher, "split(split(finding.attributes_json, '\"summary\"") {
		t.Fatalf("converted cypher should not split raw JSON summary values:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "MATCH (finding:Entity") || !strings.Contains(result.Cypher, "OPTIONAL MATCH (resource:Entity") {
		t.Fatalf("converted cypher should start from the finding anchor and optional-match resources:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "finding_attributes_json_internal") {
		t.Fatalf("converted cypher should expose internal attributes for server-side summary extraction:\n%s", result.Cypher)
	}
}

func TestConvertDraftToQueryScopesConnectorHealthTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show this source health",
		ScopeURN: "urn:cerebro:writer:source:github",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentConnectorHealth, Limit: 25},
	}, 100)

	if result.Plan.Intent != IntentConnectorHealth || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic connector health", result)
	}
	if !strings.Contains(result.Cypher, "WHERE $scope_urn = '' OR source.urn = $scope_urn") {
		t.Fatalf("converted cypher missing connector scope predicate:\n%s", result.Cypher)
	}
}

func TestConvertDraftToQueryUsesCanonicalIdentityBridgeTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Which identities bridge Okta and GitHub?",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentIdentityBridge, Limit: 25},
	}, 100)

	if result.Plan.Intent != IntentIdentityBridge || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic identity bridge", result)
	}
	for _, want := range []string{
		"relation: 'represents_identity'",
		"left.entity_type <> right.entity_type",
		"NOT left.entity_type STARTS WITH 'identifier'",
		"datetime(left_seen_at) >= datetime() - duration('P90D')",
		"identity.urn AS identity_urn",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	if strings.Contains(result.Cypher, "relation: 'has_identifier'") {
		t.Fatalf("converted cypher should not bridge concrete identities via identifier anchors:\n%s", result.Cypher)
	}
}

func TestOntologyDiagnosticsTreatsAPOCVariableAsSafe(t *testing.T) {
	diagnostics := ontologyDiagnostics(`MATCH (apoc:Entity {tenant_id: $tenant_id})
RETURN apoc.urn AS urn
LIMIT 25`)
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == "apoc_not_allowed" {
			t.Fatalf("ontologyDiagnostics() emitted APOC warning for variable property access: %#v", diagnostics)
		}
	}
}

func TestConvertDraftToQueryInjectsFallbackLimit(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "show entities"}, &DraftResponse{
		Cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn`,
	}, 100)

	if result.Plan.Intent != IntentRawCypher || !result.Corrected {
		t.Fatalf("conversion result = %#v, want corrected raw cypher", result)
	}
	if !strings.Contains(result.Cypher, "LIMIT 100") {
		t.Fatalf("converted cypher missing injected limit:\n%s", result.Cypher)
	}
}

func TestConvertDraftToQueryCapsFallbackLimit(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "show entities"}, &DraftResponse{
		Cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn LIMIT 500`,
	}, 100)

	if !result.Corrected || !strings.Contains(result.Cypher, "LIMIT 100") || strings.Contains(result.Cypher, "LIMIT 500") {
		t.Fatalf("converted cypher did not cap limit:\n%s", result.Cypher)
	}
}

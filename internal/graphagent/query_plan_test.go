package graphagent

import (
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

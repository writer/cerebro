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
	if got := canonicalEntityType("email identity"); got != "identity.email" {
		t.Fatalf("canonicalEntityType(email identity) = %q, want identity.email", got)
	}
	if got, ok := canonicalRelation("BELONGS_TO_SOURCE"); !ok || got != "belongs_to" {
		t.Fatalf("canonicalRelation(BELONGS_TO_SOURCE) = %q, %v; want belongs_to, true", got, ok)
	}
	if got, ok := canonicalRelation("repository context"); !ok || got != "has_context" {
		t.Fatalf("canonicalRelation(repository context) = %q, %v; want has_context, true", got, ok)
	}
}

func TestOntologyAliasesRoundTripToCanonicalValues(t *testing.T) {
	for _, entity := range canonicalGraphOntology.Entities {
		for _, alias := range append([]string{entity.Type}, entity.Aliases...) {
			if got := canonicalEntityType(alias); got != entity.Type {
				t.Fatalf("canonicalEntityType(%q) = %q, want %q", alias, got, entity.Type)
			}
		}
	}
	for _, relation := range canonicalGraphOntology.Relations {
		for _, alias := range append([]string{relation.Relation}, relation.Aliases...) {
			got, ok := canonicalRelation(alias)
			if !ok || got != relation.Relation {
				t.Fatalf("canonicalRelation(%q) = %q, %v; want %q, true", alias, got, ok, relation.Relation)
			}
		}
	}
}

func TestOntologyPromptUsesProjectedIdentityShape(t *testing.T) {
	hint := canonicalGraphOntology.PromptHint()
	for _, want := range []string{
		"identity.email",
		"identity.login",
		"there is no generic `identity` entity_type or top-level `email` property",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("PromptHint() missing %q:\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "Entity `identity`:") || strings.Contains(hint, "Useful properties: email, source_id") {
		t.Fatalf("PromptHint() still advertises generic identity shape:\n%s", hint)
	}
}

func TestOntologyPromptMentionsCanonicalRepositoryShape(t *testing.T) {
	hint := canonicalGraphOntology.PromptHint()
	for _, want := range []string{
		"Entity `github.code.repository`",
		"GitHub repository metadata such as `owner_login`, `repository`, `visibility`, and `default_branch` is stored in `attributes_json`",
		"urn:cerebro:writer:github_code_repository:1",
		"Relation `has_context`",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("PromptHint() missing %q:\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "Useful properties: owner_login") {
		t.Fatalf("PromptHint() still advertises repository metadata as top-level properties:\n%s", hint)
	}
}

func TestOntologyPromptStoresFindingMetadataInAttributesJSON(t *testing.T) {
	hint := canonicalGraphOntology.PromptHint()
	if !strings.Contains(hint, "Finding metadata such as `severity`, `effective_severity`, `status`, `risk_score`, `summary`, and `primary_resource_urn` is stored in `attributes_json`") {
		t.Fatalf("PromptHint() missing finding attributes_json guidance:\n%s", hint)
	}
	if strings.Contains(hint, "Useful properties: finding_id, severity, status, risk_score") {
		t.Fatalf("PromptHint() still advertises finding metadata as top-level properties:\n%s", hint)
	}
}

func TestOntologyEntityPropertiesStayWithinProjectedContract(t *testing.T) {
	projected := map[string]struct{}{}
	for _, property := range canonicalGraphOntology.Properties {
		projected[property] = struct{}{}
	}
	for _, entity := range canonicalGraphOntology.Entities {
		for _, property := range entity.Properties {
			if _, ok := projected[property]; !ok {
				t.Fatalf("ontology entity %q advertises non-projected top-level property %q", entity.Type, property)
			}
		}
	}
}

func TestOntologyPromptUsesProjectedSourceShape(t *testing.T) {
	hint := canonicalGraphOntology.PromptHint()
	for _, want := range []string{
		"Entity `source`",
		"Connector/source health nodes use `entity_type: 'source'`",
		"there is no `connector` entity_type and no top-level `status` or `last_sync_minutes` property",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("PromptHint() missing %q:\n%s", want, hint)
		}
	}
	if strings.Contains(hint, "Entity `connector`:") || strings.Contains(hint, "Useful properties: source_id, runtime_id, status, last_sync_minutes") {
		t.Fatalf("PromptHint() still advertises connector node shape:\n%s", hint)
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

func TestInferIntentPrefersTopRiskOverSourceBreakdown(t *testing.T) {
	if got := inferIntent("show top risk findings from the GitHub source", ""); got != IntentTopRiskFindings {
		t.Fatalf("inferIntent() = %q, want %q", got, IntentTopRiskFindings)
	}
	if got := inferIntent("show top finding sources", ""); got != IntentAggregateFindingsBySource {
		t.Fatalf("inferIntent(top finding sources) = %q, want %q", got, IntentAggregateFindingsBySource)
	}
}

func TestInferIntentDetectsFailingControls(t *testing.T) {
	for _, question := range []string{
		"Which controls are failing?",
		"show failed controls",
		"controls not passing",
	} {
		if got := inferIntent(question, ""); got != IntentFailingControls {
			t.Fatalf("inferIntent(%q) = %q, want %q", question, got, IntentFailingControls)
		}
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
	})

	if result.Plan.Intent != IntentAggregateFindingsBySource || !result.Deterministic || !result.Corrected {
		t.Fatalf("conversion result = %#v, want deterministic corrected source aggregation", result)
	}
	if strings.Contains(result.Cypher, "apoc.") || strings.Contains(result.Cypher, "HAS_SOURCE") || strings.Contains(result.Cypher, "'Finding'") {
		t.Fatalf("converted cypher is not canonical:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "f.source_id AS source_id") || !strings.Contains(result.Cypher, "finding_attributes_json_internal") || !strings.Contains(result.Cypher, "LIMIT 3000") {
		t.Fatalf("converted cypher missing candidate source fields/limit:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "WHERE $scope_urn = '' OR resource.urn = $scope_urn OR f.urn = $scope_urn") {
		t.Fatalf("converted cypher missing scope predicate:\n%s", result.Cypher)
	}
	if strings.Contains(result.Cypher, "split(split") || strings.Contains(result.Cypher, "count(DISTINCT f)") {
		t.Fatalf("converted cypher should leave JSON parsing and aggregation to Go:\n%s", result.Cypher)
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
	})

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
	})

	if result.Plan.Intent != IntentTopRiskFindings || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic top risk template", result)
	}
	for _, want := range []string{
		"WHERE $scope_urn = '' OR resource.urn = $scope_urn OR finding.urn = $scope_urn",
		"resource.urn AS resource_urn",
		"coalesce(r.attributes_json, '') AS relation_attributes_json_internal",
		"coalesce(finding.attributes_json, '') AS finding_attributes_json_internal",
		"ORDER BY finding_urn, resource_urn",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	for _, forbidden := range []string{"split(split", "CASE toUpper", "max(risk_score)", " AS attributes_json"} {
		if strings.Contains(result.Cypher, forbidden) {
			t.Fatalf("converted cypher still performs JSON ranking/unsafe attribute return %q:\n%s", forbidden, result.Cypher)
		}
	}
}

func TestConvertDraftToQueryRendersSupportedTopRiskFilters(t *testing.T) {
	draftCypher := `MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
RETURN finding.urn AS finding_urn
LIMIT 25`
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show high findings",
	}, &DraftResponse{
		Plan:   &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"severity": "HIGH", "status": "open", "resource_type": "repository"}},
		Cypher: draftCypher,
	})

	if !result.Deterministic || result.Source != "deterministic_template" {
		t.Fatalf("conversion result = %#v, want deterministic filtered template", result)
	}
	for _, want := range []string{
		"toUpper(filter_severity) = 'HIGH'",
		"toLower(filter_status) = 'open'",
		"resource.entity_type = 'github.code.repository'",
		"resource.entity_type AS resource_type",
		"relation_attributes_json_internal",
		"finding_attributes_json_internal",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("filtered cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	for _, forbidden := range []string{"max(risk_score)", "CASE toUpper"} {
		if strings.Contains(result.Cypher, forbidden) {
			t.Fatalf("filtered cypher should leave ranking to Go; found %q:\n%s", forbidden, result.Cypher)
		}
	}
}

func TestConvertDraftToQueryUsesFailingControlsTemplate(t *testing.T) {
	draftCypher := `MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
RETURN finding.urn AS finding_urn
LIMIT 25`
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Which controls are failing?",
	}, &DraftResponse{
		Plan:   &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"status": "fail"}},
		Cypher: draftCypher,
	})

	if result.Plan.Intent != IntentFailingControls || !result.Deterministic || result.Source != "deterministic_template" {
		t.Fatalf("conversion result = %#v, want deterministic failing controls template", result)
	}
	for _, want := range []string{
		`"control_refs":"`,
		"filter_control_refs <> ''",
		"toLower(filter_status) = 'open'",
		"finding_attributes_json_internal",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	if strings.Contains(result.Cypher, "'fail'") || strings.Contains(result.Cypher, "'failing'") {
		t.Fatalf("converted cypher should not filter finding status as fail/failing:\n%s", result.Cypher)
	}
}

func TestPostProcessFailingControlRowsGroupsOpenFindings(t *testing.T) {
	rows := []map[string]any{
		{
			"finding_urn":                       "urn:cerebro:writer:finding:f1",
			"finding_label":                     "Critical finding",
			"resource_urn":                      "urn:cerebro:writer:asset:a",
			"resource_label":                    "Asset A",
			"relation_attributes_json_internal": `{"status":"open"}`,
			"finding_attributes_json_internal":  `{"status":"open","effective_severity":"CRITICAL","risk_score":"91","control_refs":"SOC 2:CC6.1,ISO 27001:2022:A.8.9"}`,
		},
		{
			"finding_urn":                       "urn:cerebro:writer:finding:f2",
			"finding_label":                     "Resolved finding",
			"resource_urn":                      "urn:cerebro:writer:asset:b",
			"relation_attributes_json_internal": `{"status":"resolved"}`,
			"finding_attributes_json_internal":  `{"status":"resolved","effective_severity":"HIGH","risk_score":"80","control_refs":"SOC 2:CC6.2"}`,
		},
	}

	result := postProcessFailingControlRows(AskQueryPlan{Intent: IntentFailingControls, Limit: 25}, rows)
	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2: %#v", len(result), result)
	}
	first := result[0]
	if first["framework_name"] != "ISO 27001:2022" || first["control_id"] != "A.8.9" {
		t.Fatalf("first control = %#v, want ISO 27001:2022 A.8.9", first)
	}
	if first["status"] != "failing" || first["open_findings"] != 1 || first["critical_findings"] != 1 || first["risk_score"] != 91 {
		t.Fatalf("first control posture = %#v", first)
	}
	second := result[1]
	if second["framework_name"] != "SOC 2" || second["control_id"] != "CC6.1" {
		t.Fatalf("second control = %#v, want SOC 2 CC6.1", second)
	}
}

func TestCypherStringLiteralEscapesBackslashBeforeQuote(t *testing.T) {
	got := cypherStringLiteral(`open\' OR true`)
	want := `'open\\\' OR true'`
	if got != want {
		t.Fatalf("cypherStringLiteral() = %q, want %q", got, want)
	}
}

func TestConvertDraftToQueryRefusesUnsupportedPlanOnlyDraft(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show high risk findings",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"owner": "security"}},
	})

	if result.Cypher != "" || result.Source != "conversion_refusal" {
		t.Fatalf("conversion result = %#v, want conversion refusal without cypher", result)
	}
	if !strings.Contains(result.Refusal, "could not be converted") {
		t.Fatalf("refusal = %q, want backend conversion failure", result.Refusal)
	}
	if len(result.Diagnostics) == 0 || result.Diagnostics[0].Code != "query_plan_conversion_failed" {
		t.Fatalf("diagnostics = %#v, want query_plan_conversion_failed", result.Diagnostics)
	}
}

func TestConvertDraftToQueryExplainFindingAvoidsBrittleSummaryExtraction(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Explain this finding",
		ScopeURN: "urn:cerebro:writer:finding:alpha",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentExplainFinding, Limit: 25},
	})

	if result.Plan.Intent != IntentExplainFinding || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic explain finding template", result)
	}
	if strings.Contains(result.Cypher, `"summary":"`) || strings.Contains(result.Cypher, "split(split(finding.attributes_json, '\"summary\"") {
		t.Fatalf("converted cypher should not split raw JSON summary values:\n%s", result.Cypher)
	}
	for _, want := range []string{
		"MATCH (finding:Entity",
		"OR finding.urn = $scope_urn",
		"EXISTS {",
		"scopedResource:Entity {tenant_id: $tenant_id, urn: $scope_urn}",
		"OPTIONAL MATCH (resource:Entity",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	if strings.Contains(result.Cypher, "WHERE $scope_urn = '' OR finding.urn = $scope_urn OR resource.urn = $scope_urn") {
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
	})

	if result.Plan.Intent != IntentConnectorHealth || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic connector health", result)
	}
	if !strings.Contains(result.Cypher, "WHERE $scope_urn = '' OR source.urn = $scope_urn") {
		t.Fatalf("converted cypher missing connector scope predicate:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "source_attributes_json_internal") || strings.Contains(result.Cypher, " AS source_attributes_json\n") {
		t.Fatalf("converted cypher should keep raw source attributes internal:\n%s", result.Cypher)
	}
}

func TestConvertDraftToQueryUsesCanonicalIdentityBridgeTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Which identities bridge Okta and GitHub?",
		ScopeURN: "urn:cerebro:writer:github_user:alice",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentIdentityBridge, Limit: 25},
	})

	if result.Plan.Intent != IntentIdentityBridge || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic identity bridge", result)
	}
	for _, want := range []string{
		"relation: 'represents_identity'",
		"left.entity_type <> right.entity_type",
		"WHEN identity.urn = $scope_urn THEN true",
		"NOT left.entity_type STARTS WITH 'identifier'",
		"left_seen_at =~ '^\\\\d{4}-\\\\d{2}-\\\\d{2}T.*'",
		"datetime(left_seen_at) >= datetime() - duration('P90D')",
		"datetime(right_seen_at) >= datetime() - duration('P90D')",
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

func TestDeterministicTemplatesUseProjectedGraphContract(t *testing.T) {
	for _, tt := range []struct {
		name   string
		intent string
		scope  string
	}{
		{name: "source aggregation", intent: IntentAggregateFindingsBySource, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "top risk", intent: IntentTopRiskFindings, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "failing controls", intent: IntentFailingControls, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "explain finding", intent: IntentExplainFinding, scope: "urn:cerebro:writer:finding:alpha"},
		{name: "identity bridge", intent: IntentIdentityBridge, scope: "urn:cerebro:writer:github_user:alice"},
		{name: "connector health", intent: IntentConnectorHealth, scope: "urn:cerebro:writer:source:github"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := convertDraftToQuery(AskRequest{
				TenantID: "writer",
				Question: tt.name,
				ScopeURN: tt.scope,
			}, &DraftResponse{Plan: &AskQueryPlan{Intent: tt.intent, Limit: 25}})
			if !result.Deterministic {
				t.Fatalf("conversion result = %#v, want deterministic template", result)
			}
			if !strings.Contains(result.Cypher, "$scope_urn") {
				t.Fatalf("deterministic template ignores scope_urn:\n%s", result.Cypher)
			}
			for _, forbidden := range []string{
				"finding.status",
				"finding.summary",
				"finding.risk_score",
				"finding.effective_severity",
				"source.status",
				"source.last_sync_minutes",
				"source.last_sync_at",
				"repository.owner_login",
				"repository.visibility",
			} {
				if strings.Contains(result.Cypher, forbidden) {
					t.Fatalf("deterministic template references non-projected top-level field %q:\n%s", forbidden, result.Cypher)
				}
			}
		})
	}
}

func TestOntologyMutationDiagnosticsCatchNonCanonicalDrafts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cypher string
		want   string
	}{
		{
			name:   "domain finding label",
			cypher: "MATCH (f:Finding {tenant_id: $tenant_id}) RETURN f LIMIT 10",
			want:   "non_canonical_entity_label",
		},
		{
			name:   "uppercase relationship alias",
			cypher: "MATCH (f:Entity)-[:BELONGS_TO_SOURCE]->(s:Entity) RETURN f LIMIT 10",
			want:   "relation_alias_canonicalized",
		},
		{
			name:   "apoc call",
			cypher: "MATCH (f:Entity) RETURN apoc.convert.fromJsonMap(f.attributes_json) LIMIT 10",
			want:   "apoc_not_allowed",
		},
		{
			name:   "connector label",
			cypher: "MATCH (c:connector {tenant_id: $tenant_id}) RETURN c LIMIT 10",
			want:   "non_canonical_entity_label",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !containsDiagnosticCode(ontologyDiagnostics(tt.cypher), tt.want) {
				t.Fatalf("ontologyDiagnostics(%q) missing %q", tt.cypher, tt.want)
			}
		})
	}
}

func TestUnsupportedPlanOnlyMutationsAreRefused(t *testing.T) {
	for _, tt := range []struct {
		name string
		plan AskQueryPlan
	}{
		{name: "unsupported top risk owner filter", plan: AskQueryPlan{Intent: IntentTopRiskFindings, Filters: map[string]string{"owner": "security"}}},
		{name: "unsupported source runtime filter", plan: AskQueryPlan{Intent: IntentConnectorHealth, Filters: map[string]string{"entity_type": "runtime"}}},
		{name: "unsupported identity bridge group", plan: AskQueryPlan{Intent: IntentIdentityBridge, GroupBy: "email"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: tt.name}, &DraftResponse{Plan: &tt.plan})
			if result.Cypher != "" || result.Source != "conversion_refusal" {
				t.Fatalf("conversion result = %#v, want conversion refusal", result)
			}
			if !containsDiagnosticCode(result.Diagnostics, "query_plan_conversion_failed") {
				t.Fatalf("diagnostics = %#v, want query_plan_conversion_failed", result.Diagnostics)
			}
		})
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

func containsDiagnosticCode(diagnostics []ConversionDiagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func TestConvertDraftToQueryInjectsFallbackLimit(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "show entities"}, &DraftResponse{
		Cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn`,
	})

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
	})

	if !result.Corrected || !strings.Contains(result.Cypher, "LIMIT 100") || strings.Contains(result.Cypher, "LIMIT 500") {
		t.Fatalf("converted cypher did not cap limit:\n%s", result.Cypher)
	}
}

package graphagent

import (
	"encoding/json"
	"strconv"
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

func TestOntologyEntityTypesAreUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for _, entity := range canonicalGraphOntology.Entities {
		if _, ok := seen[entity.Type]; ok {
			t.Fatalf("ontology entity type %q is documented more than once", entity.Type)
		}
		seen[entity.Type] = struct{}{}
	}
}

func TestOntologyRelationEndpointTypesAreDocumented(t *testing.T) {
	entityTypes := map[string]struct{}{"*": {}}
	for _, entity := range canonicalGraphOntology.Entities {
		entityTypes[entity.Type] = struct{}{}
	}
	for _, relation := range canonicalGraphOntology.Relations {
		for _, entityType := range append(relation.FromTypes, relation.ToTypes...) {
			if _, ok := entityTypes[entityType]; !ok {
				t.Fatalf("relation %q references undocumented entity type %q", relation.Relation, entityType)
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

func TestOntologyPromptDocumentsOktaAccessReviewGraphShape(t *testing.T) {
	hint := canonicalGraphOntology.PromptHint()
	for _, want := range []string{
		"Entity `okta.user`",
		"Entity `okta.role`",
		"Okta access-review evidence is graph-shaped",
		"`okta.user` -> `okta.group` via `member_of`",
		"`mfa_phishing_resistant`",
		"do not treat missing factor detail as proof of weak MFA",
	} {
		if !strings.Contains(hint, want) {
			t.Fatalf("PromptHint() missing %q:\n%s", want, hint)
		}
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
	if got := inferIntent("show high risk findings from failed access control", ""); got != IntentTopRiskFindings {
		t.Fatalf("inferIntent(high risk failed access control findings) = %q, want %q", got, IntentTopRiskFindings)
	}
	if got := inferIntent("show top finding sources", ""); got != IntentAggregateFindingsBySource {
		t.Fatalf("inferIntent(top finding sources) = %q, want %q", got, IntentAggregateFindingsBySource)
	}
}

func TestInferIntentRecognizesOktaAccessReviewQuestions(t *testing.T) {
	cases := []struct {
		question string
		want     string
	}{
		{question: "Which privileged Okta users lack strong MFA?", want: IntentOktaPrivilegedWeakMFA},
		{question: "Which privileged Okta users lack MFA?", want: IntentOktaPrivilegedWeakMFA},
		{question: "Which dormant Okta users still have app or admin access?", want: IntentOktaDormantAccess},
		{question: "Which Okta group memberships create compliance risk?", want: IntentOktaGroupAccessRisk},
	}
	for _, tc := range cases {
		if got := inferIntent(tc.question, ""); got != tc.want {
			t.Fatalf("inferIntent(%q) = %q, want %q", tc.question, got, tc.want)
		}
	}
	if got := inferIntent("Which privileged Okta users have Slack app access?", ""); got == IntentOktaPrivilegedWeakMFA {
		t.Fatalf("inferIntent(Slack access) = %q, want non-MFA intent", got)
	}
	if got := inferIntent("Which privileged Okta users lack app assignments?", ""); got == IntentOktaPrivilegedWeakMFA {
		t.Fatalf("inferIntent(lack app assignments) = %q, want non-MFA intent", got)
	}
}

func TestInferIntentDetectsFailingControls(t *testing.T) {
	for _, question := range []string{
		"Which controls are failing?",
		"show failed controls",
		"show control failures",
		"controls not passing",
	} {
		if got := inferIntent(question, ""); got != IntentFailingControls {
			t.Fatalf("inferIntent(%q) = %q, want %q", question, got, IntentFailingControls)
		}
	}
}

func TestInferIntentRecognizesMITREAttackCoverage(t *testing.T) {
	for _, question := range []string{
		"Show MITRE ATT&CK coverage gaps by technique",
		"Which D3FEND techniques cover attack techniques?",
		"List attack data components for MITRE coverage",
	} {
		if got := inferIntent(question, ""); got != IntentMITREAttackCoverage {
			t.Fatalf("inferIntent(%q) = %q, want %q", question, got, IntentMITREAttackCoverage)
		}
	}
}

func TestInferIntentDoesNotStealGenericAttackQuestions(t *testing.T) {
	for _, tc := range []struct {
		question string
		want     string
	}{
		{question: "Explain the attack technique finding", want: IntentExplainFinding},
		{question: "Answer the attack defense questionnaire", want: IntentQuestionnaireEvidence},
		{question: "Show findings related to attack techniques", want: IntentRawCypher},
	} {
		if got := inferIntent(tc.question, ""); got != tc.want {
			t.Fatalf("inferIntent(%q) = %q, want %q", tc.question, got, tc.want)
		}
	}
}

func TestConvertDraftToQueryRendersOktaPrivilegedWeakMFATemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "Which privileged Okta users lack strong MFA?"}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentOktaPrivilegedWeakMFA, Limit: 25},
	})

	if result.Plan.Intent != IntentOktaPrivilegedWeakMFA || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic Okta privileged weak MFA template", result)
	}
	for _, want := range []string{
		"entity_type: 'okta.user'",
		"relation: 'can_admin'",
		"entity_type: 'okta.admin_role'",
		"user.mfa_disabled = true OR toLower(mfa_phishing_resistant) = 'false'",
		"mfa_factor_types",
		"overclaim_guard",
		"LIMIT 25",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
}

func TestConvertDraftToQueryClearsNoisyOktaFilters(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "Which privileged Okta users lack strong MFA?"}, &DraftResponse{
		Plan: &AskQueryPlan{
			Intent:  IntentOktaPrivilegedWeakMFA,
			Limit:   25,
			Filters: map[string]string{"entity_type": "okta.user"},
		},
	})

	if result.Plan.Intent != IntentOktaPrivilegedWeakMFA || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic Okta privileged weak MFA template", result)
	}
	if len(result.Plan.Filters) != 0 {
		t.Fatalf("filters = %#v, want cleared Okta deterministic filters", result.Plan.Filters)
	}
	if !strings.Contains(result.Cypher, "relation: 'can_admin'") {
		t.Fatalf("converted cypher missing Okta template:\n%s", result.Cypher)
	}
}

func TestConvertDraftToQueryRendersOktaDormantAccessTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "Which dormant Okta users still have app or admin access?"}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentOktaDormantAccess, Limit: 30},
	})

	if result.Plan.Intent != IntentOktaDormantAccess || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic Okta dormant access template", result)
	}
	for _, want := range []string{
		"last_login_at",
		"duration('P90D')",
		"direct_app_assignment",
		"group_app_assignment",
		"admin_role_assignment",
		"membership_event_id",
		"overclaim_guard",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
}

func TestConvertDraftToQueryRendersOktaGroupAccessRiskTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{TenantID: "writer", Question: "Which Okta group memberships create compliance risk?"}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentOktaGroupAccessRisk, Limit: 10},
	})

	if result.Plan.Intent != IntentOktaGroupAccessRisk || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic Okta group access risk template", result)
	}
	for _, want := range []string{
		"entity_type: 'okta.group'",
		"entity_type: 'okta.application'",
		"relation: 'member_of'",
		"direct_member_count",
		"grants_entitlement",
		"confers_capability",
		"privileged_group_app_access",
		"enumerate members from member_of edges or okta.group_membership events",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("converted cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	for _, forbidden := range []string{"direct_members", "direct_members_count"} {
		if strings.Contains(result.Cypher, forbidden) {
			t.Fatalf("converted cypher should not expose Okta group attribute %q:\n%s", forbidden, result.Cypher)
		}
	}
}

func TestInferIntentPrefersConnectorHealthWhenControlFailureIsContext(t *testing.T) {
	if got := inferIntent("show source health control failures", ""); got != IntentConnectorHealth {
		t.Fatalf("inferIntent(source health control failures) = %q, want %q", got, IntentConnectorHealth)
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
		`"controlRefs":"`,
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

func TestConvertDraftToQueryPreservesConfidentSpecificIntentOverFailingControlsHeuristic(t *testing.T) {
	draftCypher := `MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(finding:Entity {tenant_id: $tenant_id, entity_type: 'finding'})
RETURN finding.urn AS finding_urn
LIMIT 25`
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show findings with failed access control compliance",
	}, &DraftResponse{
		Plan: &AskQueryPlan{
			Intent:     IntentTopRiskFindings,
			Confidence: 0.91,
			Filters:    map[string]string{"status": "open"},
		},
		Cypher: draftCypher,
	})

	if result.Plan.Intent != IntentTopRiskFindings || !result.Deterministic || result.Source != "deterministic_template" {
		t.Fatalf("conversion result = %#v, want confident top risk plan preserved", result)
	}
	if strings.Contains(result.Cypher, "filter_control_refs <> ''") {
		t.Fatalf("converted cypher used failing controls template:\n%s", result.Cypher)
	}
	if !strings.Contains(result.Cypher, "toLower(filter_status) = 'open'") {
		t.Fatalf("converted cypher missing top risk status filter:\n%s", result.Cypher)
	}
}

func TestDeterministicFastPathKeepsTopRiskFindingIntentWhenControlFailureIsContext(t *testing.T) {
	plan, ok := deterministicFastPathPlan(AskRequest{
		TenantID: "writer",
		Question: "show high risk findings from failed access control",
	})
	if !ok {
		t.Fatalf("deterministicFastPathPlan() did not produce a plan")
	}
	if plan.Intent != IntentTopRiskFindings {
		t.Fatalf("plan.Intent = %q, want %q", plan.Intent, IntentTopRiskFindings)
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

func TestPostProcessFailingControlRowsKeepsDuplicateFindingSeverityConsistent(t *testing.T) {
	rows := []map[string]any{
		{
			"finding_urn":                       "urn:cerebro:writer:finding:f1",
			"finding_label":                     "Finding 1",
			"resource_urn":                      "urn:cerebro:writer:asset:a",
			"relation_attributes_json_internal": `{"status":"open","effective_severity":"HIGH","risk_score":"70","controlRefs":"SOC 2:CC6.1"}`,
			"finding_attributes_json_internal":  `{"status":"open","effective_severity":"HIGH","risk_score":"70"}`,
		},
		{
			"finding_urn":                       "urn:cerebro:writer:finding:f1",
			"finding_label":                     "Finding 1",
			"resource_urn":                      "urn:cerebro:writer:asset:b",
			"relation_attributes_json_internal": `{"status":"open","controlRefs":"SOC 2:CC6.1"}`,
			"finding_attributes_json_internal":  `{"status":"open","effective_severity":"CRITICAL","risk_score":"95"}`,
		},
	}

	result := postProcessFailingControlRows(AskQueryPlan{Intent: IntentFailingControls, Limit: 25}, rows)
	if len(result) != 1 {
		t.Fatalf("len(result) = %d, want 1: %#v", len(result), result)
	}
	control := result[0]
	if control["severity"] != "HIGH" || control["critical_findings"] != 0 || control["high_findings"] != 1 {
		t.Fatalf("duplicate finding severity summary = %#v, want HIGH with one high finding", control)
	}
	if control["risk_score"] != 70 {
		t.Fatalf("duplicate finding risk_score = %#v, want first-seen score 70", control["risk_score"])
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

func TestConvertDraftToQueryUsesMITREAttackCoverageTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Show MITRE ATT&CK coverage gaps by technique",
		ScopeURN: "urn:cerebro:writer:security_tool:agent-gateway",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentMITREAttackCoverage, Filters: map[string]string{"coverage_state": "gap"}, Limit: 25},
	})

	if result.Plan.Intent != IntentMITREAttackCoverage || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic MITRE ATT&CK coverage template", result)
	}
	for _, want := range []string{
		"entity_type: 'mitre.attack.coverage'",
		"entity_type: 'mitre.attack.technique'",
		"entity_type: 'mitre.attack.data_component'",
		"entity_type: 'mitre.attack.data_source'",
		"entity_type: 'mitre.defend.technique'",
		"relation: 'has_context'",
		"relation: 'supports'",
		"relation: 'has_evidence'",
		"WHERE toLower(coverage_state) = 'gap'",
		"$scope_urn",
		"overclaim_guard",
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("MITRE coverage cypher missing %q:\n%s", want, result.Cypher)
		}
	}
}

func TestConvertDraftToQueryUsesQuestionnaireEvidenceTemplate(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Answer this Okta MFA questionnaire item from evidence",
	}, &DraftResponse{
		Plan: &AskQueryPlan{Intent: IntentQuestionnaireEvidence, Filters: map[string]string{"topic": "okta_mfa"}, Limit: 25},
	})

	if result.Plan.Intent != IntentQuestionnaireEvidence || !result.Deterministic {
		t.Fatalf("conversion result = %#v, want deterministic questionnaire evidence template", result)
	}
	for _, want := range []string{
		"control_policy_type = 'control'",
		"relation: 'supports'",
		"relation: 'has_evidence'",
		`questionnaire_match_text =~ '(?s).*\\bokta\\b.*'`,
		`questionnaire_match_text =~ '(?s).*\\bmfa\\b.*'`,
		"OPTIONAL MATCH (support)-[supportEvidenceRel:RELATION {relation: 'has_evidence'}]->(supportEvidence:Entity {tenant_id: $tenant_id})",
		"OPTIONAL MATCH (control)-[controlEvidenceRel:RELATION {relation: 'has_evidence'}]->(controlEvidence:Entity {tenant_id: $tenant_id})",
		"WITH DISTINCT control, control_ref, support, supportRel, supportEvidence, supportEvidenceRel",
		"coalesce(supportEvidence, controlEvidence) AS evidence",
		"coalesce(supportEvidenceRel, controlEvidenceRel) AS evidenceRel",
		"controlEvidence.urn AS direct_evidence_urn",
		"direct_evidence_attributes_json_internal",
		"RETURN DISTINCT control.urn AS control_urn",
		"evidence_source_id,",
		"source_attributes_json_internal",
		"exception_attributes_json_internal",
		"finding_attributes_json_internal",
		"LIMIT " + strconv.Itoa(questionnaireEvidenceCandidateRowLimit),
	} {
		if !strings.Contains(result.Cypher, want) {
			t.Fatalf("questionnaire cypher missing %q:\n%s", want, result.Cypher)
		}
	}
	for _, forbidden := range []string{
		"control.status",
		"support.status",
		"evidence.status",
		"source.last_sync_at",
		"coalesce(support.entity_type, '') +",
		"coalesce(evidence.entity_type, '') +",
		"coalesce(controlEvidence.entity_type, '') +",
		"coalesce(control.attributes_json, '') +",
		"coalesce(support.attributes_json, '') +",
		"coalesce(evidence.attributes_json, '')) AS questionnaire_match_text",
		"OPTIONAL MATCH (support:Entity {tenant_id: $tenant_id})-[supportEvidenceRel",
		"OPTIONAL MATCH (control:Entity {tenant_id: $tenant_id})-[controlEvidenceRel",
		"OPTIONAL MATCH (support:Entity {tenant_id: $tenant_id})-[findingRel",
		"OPTIONAL MATCH (exception:Entity {tenant_id: $tenant_id})-[exceptionRel:RELATION]->(control:Entity",
	} {
		if strings.Contains(result.Cypher, forbidden) {
			t.Fatalf("questionnaire template references non-projected top-level field %q:\n%s", forbidden, result.Cypher)
		}
	}
}

func TestEnforceCypherLimitIgnoresQuotedAndCommentedText(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		wantQuery      string
		wantDiagnostic string
		wantChanged    bool
	}{
		{
			name:           "quoted limit is not a clause",
			query:          `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN 'LIMIT 500' AS label`,
			wantQuery:      "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN 'LIMIT 500' AS label\nLIMIT 100",
			wantDiagnostic: "limit_injected",
			wantChanged:    true,
		},
		{
			name:           "line commented limit is not a clause",
			query:          "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e // LIMIT 500",
			wantQuery:      "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e // LIMIT 500\nLIMIT 100",
			wantDiagnostic: "limit_injected",
			wantChanged:    true,
		},
		{
			name:      "commented limit does not override bounded clause",
			query:     "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 25 // LIMIT 500",
			wantQuery: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 25 // LIMIT 500",
		},
		{
			name:           "caps real clause before trailing comment",
			query:          "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 500 // LIMIT 900",
			wantQuery:      "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 100 // LIMIT 900",
			wantDiagnostic: "limit_capped",
			wantChanged:    true,
		},
		{
			name:           "block commented limit is not a clause",
			query:          `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e /* LIMIT 500 */`,
			wantQuery:      "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e /* LIMIT 500 */\nLIMIT 100",
			wantDiagnostic: "limit_injected",
			wantChanged:    true,
		},
		{
			name:           "limit variable is not a clause",
			query:          `MATCH (limit:Entity {tenant_id: $tenant_id}) RETURN limit`,
			wantQuery:      "MATCH (limit:Entity {tenant_id: $tenant_id}) RETURN limit\nLIMIT 100",
			wantDiagnostic: "limit_injected",
			wantChanged:    true,
		},
		{
			name:      "parameterized limit remains for validator refusal",
			query:     `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT $max`,
			wantQuery: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT $max`,
		},
		{
			name:      "arithmetic limit remains for validator refusal",
			query:     `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 2 * 1000`,
			wantQuery: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 2 * 1000`,
		},
		{
			name:           "limit variable does not hide later clause",
			query:          `MATCH (limit:Entity {tenant_id: $tenant_id}) RETURN limit LIMIT 1000`,
			wantQuery:      `MATCH (limit:Entity {tenant_id: $tenant_id}) RETURN limit LIMIT 100`,
			wantDiagnostic: "limit_capped",
			wantChanged:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, diagnostic, changed := enforceCypherLimit(tt.query, 100)
			if query != tt.wantQuery || changed != tt.wantChanged {
				t.Fatalf("enforceCypherLimit() = (%q, %#v, %t), want query %q and changed %t", query, diagnostic, changed, tt.wantQuery, tt.wantChanged)
			}
			if diagnostic.Code != tt.wantDiagnostic {
				t.Fatalf("diagnostic = %#v, want code %q", diagnostic, tt.wantDiagnostic)
			}
		})
	}
}

func TestLastNumericCypherLimitRejectsExpressions(t *testing.T) {
	for _, query := range []string{
		`MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 2 * 1000`,
		`MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 2 + 1000`,
	} {
		if value, _, _, ok := lastNumericCypherLimit(query); ok {
			t.Fatalf("lastNumericCypherLimit(%q) = (%d, true), want false", query, value)
		}
	}
}

func TestInferIntentRoutesQuestionnairePromptsToGraphEvidence(t *testing.T) {
	for _, question := range []string{
		"Does Okta enforce MFA for access?",
		"Answer the Okta access control question",
		"Explain Okta lifecycle evidence for user deprovisioning",
		"Answer this policy document questionnaire item",
		"Answer the access review questionnaire item",
		"Do we encrypt customer data at rest?",
		"Can you provide incident response evidence?",
		"Do we maintain a subprocessor list?",
		"Do we have a current SOC 2 report?",
		"Do we train AI models on customer data?",
		"Show vendor due diligence evidence",
		"Show control coverage evidence gaps",
		"Show the control evidence packet coverage",
	} {
		if got := inferIntent(question, ""); got != IntentQuestionnaireEvidence {
			t.Fatalf("inferIntent(%q) = %q, want %q", question, got, IntentQuestionnaireEvidence)
		}
	}
	if got := inferIntent("Which identities bridge Okta and GitHub access?", ""); got != IntentIdentityBridge {
		t.Fatalf("inferIntent(identity bridge access) = %q, want %q", got, IntentIdentityBridge)
	}
	if got := inferIntent("Explain the Okta access finding", ""); got != IntentExplainFinding {
		t.Fatalf("inferIntent(okta finding explanation) = %q, want %q", got, IntentExplainFinding)
	}
}

func TestInferIntentLeavesGenericControlEvidencePromptsForLLMPlanning(t *testing.T) {
	for _, question := range []string{
		"Show source evidence for access control findings",
		"What evidence supports this control gap?",
		"Do we have control evidence for access management?",
		"List controls with evidence attached",
		"What is in the evidence packet for this finding?",
		"Show the evidence packet export status",
		"List all policy documents",
		"Show policy doc count",
		"Policy document inventory",
		"Show Okta findings",
		"Answer this security questionnaire item",
		"Show source evidence for Okta access findings",
	} {
		if got := inferIntent(question, ""); got != IntentRawCypher {
			t.Fatalf("inferIntent(%q) = %q, want %q", question, got, IntentRawCypher)
		}
	}
}

func TestQuestionnaireFastPathRequiresResolvedTopic(t *testing.T) {
	for _, question := range []string{
		"Answer this security questionnaire item",
		"Can we answer this questionnaire item?",
	} {
		if result, _, ok := deterministicFastPathConversion(AskRequest{TenantID: "writer", Question: question}, true); ok {
			t.Fatalf("deterministicFastPathConversion(%q) = %#v, want LLM planning fallback", question, result)
		}
	}
}

func TestQuestionnaireTemplateRequiresTopicFilter(t *testing.T) {
	result := convertDraftToQuery(AskRequest{
		TenantID: "writer",
		Question: "Answer this security questionnaire item",
	}, &DraftResponse{Plan: &AskQueryPlan{Intent: IntentQuestionnaireEvidence, Limit: 25}})
	if result.Cypher != "" || result.Source != "conversion_refusal" {
		t.Fatalf("conversion result = %#v, want refusal without questionnaire topic", result)
	}
}

func TestQuestionnairePromptsUseDeterministicGraphRetrieval(t *testing.T) {
	for _, tt := range []struct {
		name        string
		question    string
		wantTopic   string
		wantSnippet string
	}{
		{name: "okta mfa", question: "Does Okta enforce MFA for access?", wantTopic: "okta_mfa", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bmfa\\b.*'`},
		{name: "okta access", question: "Answer the Okta access control question", wantTopic: "okta_access", wantSnippet: `questionnaire_match_text =~ '(?s).*\\baccess\\b.*'`},
		{name: "okta lifecycle", question: "Explain Okta lifecycle evidence for deprovisioning", wantTopic: "okta_lifecycle", wantSnippet: `questionnaire_match_text =~ '(?s).*\\blifecycle\\b.*'`},
		{name: "access review", question: "Answer the access review questionnaire item", wantTopic: "access_review", wantSnippet: "questionnaire_match_text CONTAINS 'access review'"},
		{name: "encryption", question: "Do we encrypt customer data at rest?", wantTopic: "encryption", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bencrypt\\b.*'`},
		{name: "incident response", question: "Can you provide incident response evidence?", wantTopic: "incident_response", wantSnippet: "questionnaire_match_text CONTAINS 'incident response'"},
		{name: "subprocessors", question: "Do we maintain a subprocessor list?", wantTopic: "subprocessors", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bsubprocessor\\b.*'`},
		{name: "audit report", question: "Do we have a current SOC 2 report?", wantTopic: "audit_report", wantSnippet: "questionnaire_match_text CONTAINS 'soc 2'"},
		{name: "policy docs", question: "Answer this policy document questionnaire item", wantTopic: "policy_documents", wantSnippet: "questionnaire_match_text CONTAINS 'policy_document'"},
		{name: "hyphenated policy docs", question: "Answer this policy-document questionnaire item", wantTopic: "policy_documents", wantSnippet: "questionnaire_match_text CONTAINS 'policy_document'"},
		{name: "ai data use", question: "Do we train AI models on customer data?", wantTopic: "ai_data_use", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bai\\b.*'`},
		{name: "vendor due diligence", question: "Show vendor due diligence evidence", wantTopic: "vendor_due_diligence", wantSnippet: "questionnaire_match_text CONTAINS 'due diligence'"},
		{name: "coverage gap", question: "Show control coverage evidence gaps", wantTopic: "control_coverage", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bcoverage\\b.*'`},
		{name: "hyphenated coverage gap", question: "Show control-coverage evidence-gaps", wantTopic: "control_coverage", wantSnippet: `questionnaire_match_text =~ '(?s).*\\bcoverage\\b.*'`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, _, ok := deterministicFastPathConversion(AskRequest{TenantID: "writer", Question: tt.question}, true)
			if !ok || !result.Deterministic || result.Source != "deterministic_fast_path" {
				t.Fatalf("deterministicFastPathConversion() = %#v, %v; want questionnaire graph fast path", result, ok)
			}
			if result.Plan.Intent != IntentQuestionnaireEvidence || result.Plan.Filters["topic"] != tt.wantTopic {
				t.Fatalf("plan = %#v, want questionnaire topic %q", result.Plan, tt.wantTopic)
			}
			for _, want := range []string{
				"relation: 'supports'",
				"relation: 'has_evidence'",
				"controlEvidence.urn AS direct_evidence_urn",
				"source_attributes_json_internal",
				tt.wantSnippet,
			} {
				if !strings.Contains(result.Cypher, want) {
					t.Fatalf("questionnaire cypher missing %q:\n%s", want, result.Cypher)
				}
			}
			for _, forbidden := range []string{
				"WHERE supportEvidence IS NULL",
				"coalesce(control.attributes_json, '') +",
				"coalesce(support.attributes_json, '') +",
				"coalesce(evidence.attributes_json, '') +",
			} {
				if strings.Contains(result.Cypher, forbidden) {
					t.Fatalf("questionnaire cypher contains forbidden raw/suppressing fragment %q:\n%s", forbidden, result.Cypher)
				}
			}
		})
	}
}

func TestQuestionnaireTopicPredicatesAvoidRawJSONKeyCollisions(t *testing.T) {
	tests := []struct {
		name       string
		question   string
		forbidden  []string
		want       []string
		wantFilter string
	}{
		{
			name:       "policy documents",
			question:   "Answer this policy document questionnaire item",
			wantFilter: "policy_documents",
			forbidden: []string{
				"questionnaire_match_text CONTAINS 'policy' OR",
				"coalesce(control.attributes_json, '') +",
				"coalesce(support.attributes_json, '') +",
				"coalesce(evidence.attributes_json, '')) AS questionnaire_match_text",
			},
			want: []string{
				"questionnaire_match_text CONTAINS 'policy document'",
				"questionnaire_match_text CONTAINS 'policy_document'",
				`questionnaire_match_text =~ '(?s).*\\bdocument\\b.*'`,
			},
		},
		{
			name:       "control coverage",
			question:   "Show control coverage evidence gaps",
			wantFilter: "control_coverage",
			forbidden: []string{
				"questionnaire_match_text CONTAINS 'control'",
				"questionnaire_match_text CONTAINS 'evidence'",
				"coalesce(control.attributes_json, '') +",
				"coalesce(support.attributes_json, '') +",
				"coalesce(evidence.attributes_json, '')) AS questionnaire_match_text",
			},
			want: []string{
				`questionnaire_match_text =~ '(?s).*\\bcoverage\\b.*'`,
				"questionnaire_match_text CONTAINS 'coverage_gap'",
				`questionnaire_match_text =~ '(?s).*\\bgap\\b.*'`,
				`questionnaire_match_text =~ '(?s).*\\bmissing\\b.*'`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, ok := deterministicFastPathConversion(AskRequest{TenantID: "writer", Question: tt.question}, true)
			if !ok || result.Plan.Filters["topic"] != tt.wantFilter {
				t.Fatalf("deterministicFastPathConversion() = %#v, %v; want topic %q", result, ok, tt.wantFilter)
			}
			for _, forbidden := range tt.forbidden {
				if strings.Contains(result.Cypher, forbidden) {
					t.Fatalf("questionnaire cypher contains collision-prone predicate %q:\n%s", forbidden, result.Cypher)
				}
			}
			for _, want := range tt.want {
				if !strings.Contains(result.Cypher, want) {
					t.Fatalf("questionnaire cypher missing %q:\n%s", want, result.Cypher)
				}
			}
		})
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
		name    string
		intent  string
		scope   string
		filters map[string]string
	}{
		{name: "source aggregation", intent: IntentAggregateFindingsBySource, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "top risk", intent: IntentTopRiskFindings, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "failing controls", intent: IntentFailingControls, scope: "urn:cerebro:writer:asset:alpha"},
		{name: "explain finding", intent: IntentExplainFinding, scope: "urn:cerebro:writer:finding:alpha"},
		{name: "identity bridge", intent: IntentIdentityBridge, scope: "urn:cerebro:writer:github_user:alice"},
		{name: "connector health", intent: IntentConnectorHealth, scope: "urn:cerebro:writer:source:github"},
		{name: "questionnaire evidence", intent: IntentQuestionnaireEvidence, scope: "urn:cerebro:writer:policy:control:ac-1", filters: map[string]string{"topic": "okta_mfa"}},
		{name: "mitre coverage", intent: IntentMITREAttackCoverage, scope: "urn:cerebro:writer:security_tool:agent-gateway", filters: map[string]string{"coverage_state": "gap"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := convertDraftToQuery(AskRequest{
				TenantID: "writer",
				Question: tt.name,
				ScopeURN: tt.scope,
			}, &DraftResponse{Plan: &AskQueryPlan{Intent: tt.intent, Limit: 25, Filters: tt.filters}})
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
		{name: "unsupported questionnaire owner filter", plan: AskQueryPlan{Intent: IntentQuestionnaireEvidence, Filters: map[string]string{"owner": "security"}}},
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

package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestPolicyCatalogRuleEmitsFindingForFailedEvidence(t *testing.T) {
	definition := RuleDefinition{
		ID:                "policy-test",
		Name:              "Policy Test",
		Description:       "Policy test description",
		SourceID:          policyRuleSourceID,
		EventKinds:        []string{policyRuleEvidenceKind, policyRuleResultEventKind},
		OutputKind:        policyRuleOutputKind,
		Severity:          "HIGH",
		Status:            "active",
		Maturity:          RuleMaturityCandidate,
		Tags:              []string{"policy", "test"},
		FalsePositives:    []string{"Approved exception."},
		Runbook:           "Review policy evidence.",
		FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn", "resource_id"},
		ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6"}},
		MITREAttack:       []MITREAttackRef{{Tactic: "Initial Access", Technique: "T1190"}},
		MITREDefend:       []MITREDefendRef{{Technique: "InboundTrafficFiltering", Artifact: "NetworkTraffic"}},
		Lifecycle:         Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone},
	}
	rule := newPolicyCatalogRule(policyRuleConfig{
		Definition:        definition,
		EvidenceMode:      "query",
		EvidenceType:      "query_result",
		AssessmentMethods: []string{"examine"},
		AuditorGuidance:   "Review returned rows.",
		RiskStatement:     "Mapped controls may lack operating evidence.",
		RemediationIntent: "Restore expected control state.",
		ExceptionGuidance: []string{"Documented exception."},
		ControlFamilies:   []string{"SOC 2 CC6 Logical and Physical Access"},
		ContractAttributes: map[string]string{
			"policy_input_freshness_sla":          "24h",
			"policy_context_graph_enrich":         "owner,privileged_access_path",
			"policy_verification_mutation_checks": "missing_required_field,stale_evidence",
			"policy_action_effort":                "low",
		},
		Category: "compliance",
		Query:    "SELECT id FROM resources WHERE failing = true",
		Enabled:  true,
	})
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-policy", SourceId: policyRuleSourceID}
	event := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant-1",
		SourceId: policyRuleSourceID,
		Kind:     policyRuleResultEventKind,
		Attributes: map[string]string{
			"policy_id":               "policy-test",
			"result":                  "failed",
			"resource_urn":            "urn:cerebro:tenant-1:test:resource-1",
			"resource_id":             "resource-1",
			"mitre_attack_tactics":    "Discovery",
			"mitre_attack_techniques": "T1087",
			"mitre_defend_techniques": "LocalAccountMonitoring",
			"mitre_defend_artifacts":  "UserAccount",
			"policy_mitre":            "Discovery:T1087",
		},
	}
	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("len(findings) = %d, want 1", got)
	}
	finding := findings[0]
	if finding.RuleID != "policy-test" || finding.PolicyID != "policy-test" || finding.CheckID != "policy-test" {
		t.Fatalf("finding identifiers = rule:%q policy:%q check:%q", finding.RuleID, finding.PolicyID, finding.CheckID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if finding.Title != "Policy failed: Policy Test" {
		t.Fatalf("Title = %q, want generated failure title", finding.Title)
	}
	if finding.Summary == "" || !strings.Contains(finding.Summary, "Mapped controls may lack operating evidence.") {
		t.Fatalf("Summary = %q, want generated risk statement", finding.Summary)
	}
	if !strings.Contains(finding.Summary, "Mapped control families: SOC 2 CC6 Logical and Physical Access.") {
		t.Fatalf("Summary = %q, want mapped control family", finding.Summary)
	}
	if !strings.Contains(finding.Summary, "Auditor review: Review returned rows.") {
		t.Fatalf("Summary = %q, want auditor guidance", finding.Summary)
	}
	if got := len(finding.ControlRefs); got != 1 {
		t.Fatalf("len(ControlRefs) = %d, want 1", got)
	}
	if got := finding.Attributes["policy_query_present"]; got != "true" {
		t.Fatalf("policy_query_present = %q, want true", got)
	}
	if got := finding.Attributes["policy_evidence_type"]; got != "query_result" {
		t.Fatalf("policy_evidence_type = %q, want query_result", got)
	}
	if got := finding.Attributes["policy_evidence_summary"]; got != "Failed query-result evidence for query result. Review each returned row as an exception candidate." {
		t.Fatalf("policy_evidence_summary = %q, want query result evidence summary", got)
	}
	if got := finding.Attributes["policy_audit_impact"]; got != "Mapped controls may lack operating evidence." {
		t.Fatalf("policy_audit_impact = %q, want audit impact", got)
	}
	if got := finding.Attributes["policy_next_step"]; got != "Restore expected control state." {
		t.Fatalf("policy_next_step = %q, want next step", got)
	}
	if got := finding.Attributes["policy_assessment_methods"]; got != "examine" {
		t.Fatalf("policy_assessment_methods = %q, want examine", got)
	}
	if got := finding.Attributes["policy_control_families"]; got != "SOC 2 CC6 Logical and Physical Access" {
		t.Fatalf("policy_control_families = %q, want SOC 2 family", got)
	}
	if got := finding.Attributes["policy_input_freshness_sla"]; got != "24h" {
		t.Fatalf("policy_input_freshness_sla = %q, want 24h", got)
	}
	if got := finding.Attributes["policy_context_graph_enrich"]; got != "owner,privileged_access_path" {
		t.Fatalf("policy_context_graph_enrich = %q, want graph context", got)
	}
	if got := finding.Attributes["policy_verification_mutation_checks"]; got != "missing_required_field,stale_evidence" {
		t.Fatalf("policy_verification_mutation_checks = %q, want mutation checks", got)
	}
	if got := finding.Attributes["policy_action_effort"]; got != "low" {
		t.Fatalf("policy_action_effort = %q, want low", got)
	}
	if got := finding.Attributes["mitre_attack_tactics"]; got != "Discovery,Initial Access" {
		t.Fatalf("mitre_attack_tactics = %q, want Discovery,Initial Access", got)
	}
	if got := finding.Attributes["mitre_attack_techniques"]; got != "T1087,T1190" {
		t.Fatalf("mitre_attack_techniques = %q, want T1087,T1190", got)
	}
	if got := finding.Attributes["policy_mitre"]; got != "Discovery:T1087,Initial Access:T1190" {
		t.Fatalf("policy_mitre = %q, want Discovery:T1087,Initial Access:T1190", got)
	}
	if got := finding.Attributes["rule_mitre_attack_techniques"]; got != "T1190" {
		t.Fatalf("rule_mitre_attack_techniques = %q, want T1190", got)
	}
	if got := finding.Attributes["mitre_defend_techniques"]; got != "LocalAccountMonitoring,InboundTrafficFiltering" {
		t.Fatalf("mitre_defend_techniques = %q, want LocalAccountMonitoring,InboundTrafficFiltering", got)
	}
	if got := finding.Attributes["mitre_defend_artifacts"]; got != "UserAccount,NetworkTraffic" {
		t.Fatalf("mitre_defend_artifacts = %q, want UserAccount,NetworkTraffic", got)
	}
	if got := finding.Attributes["mitre_defend"]; got != "InboundTrafficFiltering:NetworkTraffic" {
		t.Fatalf("mitre_defend = %q, want InboundTrafficFiltering:NetworkTraffic", got)
	}
	if got := finding.Attributes["rule_mitre_defend_techniques"]; got != "InboundTrafficFiltering" {
		t.Fatalf("rule_mitre_defend_techniques = %q, want InboundTrafficFiltering", got)
	}
}

func TestPolicyCatalogRuleIgnoresPassingEvidence(t *testing.T) {
	rule := newPolicyCatalogRule(policyRuleConfig{
		Definition: RuleDefinition{
			ID:                "policy-pass-test",
			Name:              "Policy Pass Test",
			Description:       "Policy pass test description",
			SourceID:          policyRuleSourceID,
			EventKinds:        []string{policyRuleEvidenceKind},
			OutputKind:        policyRuleOutputKind,
			Severity:          "LOW",
			Status:            "active",
			Maturity:          RuleMaturityCandidate,
			Tags:              []string{"policy", "test"},
			FalsePositives:    []string{"Approved exception."},
			Runbook:           "Review policy evidence.",
			FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn", "resource_id"},
			ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6"}},
			Lifecycle:         Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone},
		},
		Enabled: true,
	})
	findings, err := rule.Evaluate(context.Background(),
		&cerebrov1.SourceRuntime{Id: "runtime-policy", SourceId: policyRuleSourceID},
		&cerebrov1.EventEnvelope{
			Id:       "event-1",
			TenantId: "tenant-1",
			SourceId: policyRuleSourceID,
			Kind:     policyRuleEvidenceKind,
			Attributes: map[string]string{
				"policy_id": "policy-pass-test",
				"result":    "passed",
			},
		},
	)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestPolicyCatalogRuleDisabledDoesNotSupportRuntimeOrEmit(t *testing.T) {
	rule := newPolicyCatalogRule(policyRuleConfig{
		Definition: RuleDefinition{
			ID:                "policy-disabled-test",
			Name:              "Policy Disabled Test",
			Description:       "Policy disabled test description",
			SourceID:          policyRuleSourceID,
			EventKinds:        []string{policyRuleEvidenceKind},
			OutputKind:        policyRuleOutputKind,
			Severity:          "LOW",
			Status:            "disabled",
			Maturity:          RuleMaturityCandidate,
			Tags:              []string{"policy", "test"},
			FalsePositives:    []string{"Approved exception."},
			Runbook:           "Review policy evidence.",
			FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn", "resource_id"},
			ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6"}},
			Lifecycle:         Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone},
		},
		Enabled: false,
	})
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-policy", SourceId: policyRuleSourceID}
	if rule.SupportsRuntime(runtime) {
		t.Fatal("SupportsRuntime() = true, want false for disabled policy rule")
	}
	findings, err := rule.Evaluate(context.Background(), runtime, &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant-1",
		SourceId: policyRuleSourceID,
		Kind:     policyRuleEvidenceKind,
		Attributes: map[string]string{
			"policy_id": "policy-disabled-test",
			"result":    "failed",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestPolicyGraphCatalogRuleEmitsGraphFinding(t *testing.T) {
	rule := newPolicyCatalogRule(policyRuleConfig{
		Definition: RuleDefinition{
			ID:                "graph-policy-test",
			Name:              "Graph Policy Test",
			Description:       "Graph policy test description",
			SourceID:          policyRuleSourceID,
			EventKinds:        []string{"graph"},
			OutputKind:        policyRuleOutputKind,
			Severity:          "LOW",
			Status:            findingStatusOpen,
			Maturity:          RuleMaturityCandidate,
			Tags:              []string{"policy", "graph"},
			FalsePositives:    []string{"Inventory-only entity."},
			Runbook:           "Review graph evidence.",
			FingerprintFields: []string{"primary_urn"},
			ControlRefs:       []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}},
			MITREAttack:       []MITREAttackRef{{Tactic: "Discovery", Technique: "T1087"}},
			Lifecycle:         Lifecycle{Kind: LifecycleAuditEvidence, Anchor: AnchorNone},
		},
		EvidenceMode:      "graph",
		EvidenceType:      "graph_state",
		AssessmentMethods: []string{"examine"},
		AuditorGuidance:   "Review graph projection state.",
		RiskStatement:     "Graph evidence may be incomplete.",
		RemediationIntent: "Repair the graph projection.",
		ContractAttributes: map[string]string{
			"policy_input_source_kinds": "graph",
		},
		Graph: policyRuleGraphConfig{
			Query: `MATCH (entity:Entity {tenant_id: $tenant_id})
RETURN entity.urn AS primary_urn,
       entity.urn AS fingerprint_key,
       'LOW' AS severity,
       'Graph entity requires review' AS summary,
       [entity.urn] AS resource_urns,
       [] AS evidence
LIMIT $row_limit`,
			RowLimit:    250,
			Params:      map[string]any{"minimum_count": int64(2)},
			SourceKinds: []string{"graph"},
		},
		Enabled: true,
	})
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatalf("newPolicyCatalogRule() = %T, want GraphRule", rule)
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatalf("newPolicyCatalogRule() = %T, want MetadataRule", rule)
	}
	metadata := metadataRule.RuleMetadata()
	if metadata.SourceID != "graph" || metadata.OutputKind != policyGraphOutputKind {
		t.Fatalf("metadata source/output = %q/%q, want graph/%s", metadata.SourceID, metadata.OutputKind, policyGraphOutputKind)
	}
	if metadata.Lifecycle.Kind != LifecycleDurableState || metadata.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("metadata lifecycle = %+v, want durable graph anchored", metadata.Lifecycle)
	}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-graph", TenantId: "tenant-1", SourceId: "graph"}
	if !rule.SupportsRuntime(runtime) {
		t.Fatal("SupportsRuntime(graph runtime) = false, want true")
	}
	query := graphRule.QueryFor(runtime)
	if query.RowLimit != 250 || query.Params["row_limit"] != int64(250) {
		t.Fatalf("query row limit = request:%d param:%#v, want 250", query.RowLimit, query.Params["row_limit"])
	}
	if query.Params["tenant_id"] != "tenant-1" || query.Params["minimum_count"] != int64(2) {
		t.Fatalf("query params = %#v, want tenant and custom params", query.Params)
	}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{{Values: map[string]any{
		"primary_urn":     "urn:cerebro:tenant-1:resource:one",
		"primary_label":   "Resource One",
		"primary_type":    "resource",
		"fingerprint_key": "urn:cerebro:tenant-1:resource:one",
		"summary":         "Graph entity requires review",
		"resource_urns":   []any{"urn:cerebro:tenant-1:resource:one"},
		"evidence": []any{map[string]any{
			"urn":         "urn:cerebro:tenant-1:resource:one",
			"label":       "Resource One",
			"entity_type": "resource",
			"relation":    "self",
		}},
	}}})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != "graph-policy-test" || finding.PolicyID != "graph-policy-test" || finding.CheckID != "graph-policy-test" {
		t.Fatalf("finding identifiers = rule:%q policy:%q check:%q", finding.RuleID, finding.PolicyID, finding.CheckID)
	}
	for key, want := range map[string]string{
		"policy_id":                  "graph-policy-test",
		"policy_evidence":            "graph",
		"policy_graph_query_present": "true",
		"policy_input_source_kinds":  "graph",
		"policy_mitre":               "Discovery:T1087",
		"rule_mitre_attack":          "Discovery:T1087",
	} {
		if got := finding.Attributes[key]; got != want {
			t.Fatalf("Attributes[%s] = %q, want %q; attrs=%#v", key, got, want, finding.Attributes)
		}
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 1", len(finding.GraphEvidenceRows))
	}
}

func TestOktaVendorBroadGroupPolicyFingerprintsByApp(t *testing.T) {
	config := generatedPolicyRuleConfigByID("identity-okta-vendor-app-broad-group-access")
	if config == nil {
		t.Fatal("identity-okta-vendor-app-broad-group-access missing from generated policy catalog")
	}
	if !strings.Contains(config.Query, "SELECT a.app_id AS id") {
		t.Fatalf("query = %q, want app_id selected as id", config.Query)
	}
	if strings.Contains(config.Query, "SELECT a.assignee_id AS id") {
		t.Fatalf("query = %q, must not fingerprint broad group rows by assignee_id", config.Query)
	}
}

func TestOktaStaleAppAssignmentPolicyUsesStringSafeActivityCutoff(t *testing.T) {
	config := generatedPolicyRuleConfigByID("identity-okta-stale-app-assignment-graph-30d")
	if config == nil {
		t.Fatal("identity-okta-stale-app-assignment-graph-30d missing from generated policy catalog")
	}
	query := config.Graph.Query
	if strings.Contains(query, "datetime(split(split") {
		t.Fatalf("query parses extracted activity timestamps with datetime():\n%s", query)
	}
	for _, want := range []string{
		"=~ '^[0-9]{4}-",
		"substring(toString(datetime() - duration('P30D')), 0, 19)",
		"malformed activity timestamps are ignored",
		"activity.attributes_json, '') CONTAINS '\"event_type\":\"app.oauth2.token.grant.",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("query missing %q:\n%s", want, query)
		}
	}
	if strings.Contains(query, "CONTAINS '\"event_type\":\"app.oauth2.token.grant\"'") {
		t.Fatalf("query must match OAuth token grant event prefixes with a suffix separator:\n%s", query)
	}
}

func TestOktaLastLoginPoliciesUseStringSafeCutoffs(t *testing.T) {
	for _, tc := range []struct {
		id       string
		duration string
	}{
		{id: "identity-okta-dormant-admin-role-assignment", duration: "P30D"},
		{id: "identity-okta-stale-group-membership-graph-90d", duration: "P90D"},
	} {
		config := generatedPolicyRuleConfigByID(tc.id)
		if config == nil {
			t.Fatalf("%s missing from generated policy catalog", tc.id)
		}
		query := config.Graph.Query
		if strings.Contains(query, "datetime(last_login_at)") {
			t.Fatalf("%s query parses extracted login timestamps with datetime():\n%s", tc.id, query)
		}
		for _, want := range []string{
			"last_login_at =~ '^[0-9]{4}-",
			"substring(toString(datetime() - duration('" + tc.duration + "')), 0, 19)",
			"malformed login timestamps are ignored",
		} {
			if !strings.Contains(query, want) {
				t.Fatalf("%s query missing %q:\n%s", tc.id, want, query)
			}
		}
	}
}

func TestOktaPrivilegedNoMFAPolicyCarriesDSLContractMetadata(t *testing.T) {
	config := generatedPolicyRuleConfigByID("identity-okta-privileged-no-mfa")
	if config == nil {
		t.Fatal("identity-okta-privileged-no-mfa missing from generated policy catalog")
	}
	definition := config.Definition
	for _, want := range []string{"tenant_id", "policy_id", "resource_urn", "resource_id", "privilege_level", "mfa_enrolled", "observed_at", "subject_urn"} {
		if !policyRuleTestContainsString(definition.RequiredAttributes, want) {
			t.Fatalf("RequiredAttributes = %v, missing %q", definition.RequiredAttributes, want)
		}
	}
	if !policyRuleTestContainsString(definition.FingerprintFields, "resource_urn") {
		t.Fatalf("FingerprintFields = %v, missing resource_urn", definition.FingerprintFields)
	}
	if !policyRuleTestContainsString(definition.References, "crown_jewel_distance") {
		t.Fatalf("References = %v, missing graph enrichment", definition.References)
	}
	if got := config.EvidenceType; got != "identity_configuration" {
		t.Fatalf("EvidenceType = %q, want identity_configuration", got)
	}
	for key, want := range map[string]string{
		"policy_input_freshness_sla":               "24h",
		"policy_evidence_required_for_audit":       "true",
		"policy_audit_exception_requires_approval": "true",
		"policy_action_owner_from":                 "graph.owner",
		"policy_action_effort":                     "low",
	} {
		if got := config.ContractAttributes[key]; got != want {
			t.Fatalf("ContractAttributes[%s] = %q, want %q; attrs=%#v", key, got, want, config.ContractAttributes)
		}
	}
}

func TestGeneratedGraphOrphanPolicyUsesGraphDSL(t *testing.T) {
	config := generatedPolicyRuleConfigByID("graph-orphan-nonfinding-node")
	if config == nil {
		t.Fatal("graph-orphan-nonfinding-node missing from generated policy catalog")
	}
	if strings.TrimSpace(config.Graph.Query) == "" {
		t.Fatal("graph-orphan-nonfinding-node generated config missing graph query")
	}
	if config.Definition.SourceID != "graph" || config.Definition.OutputKind != policyGraphOutputKind {
		t.Fatalf("source/output = %q/%q, want graph/%s", config.Definition.SourceID, config.Definition.OutputKind, policyGraphOutputKind)
	}
	if config.Definition.Lifecycle.Kind != LifecycleDurableState || config.Definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("lifecycle = %+v, want durable graph anchored", config.Definition.Lifecycle)
	}
	if config.EvidenceMode != "graph" {
		t.Fatalf("EvidenceMode = %q, want graph", config.EvidenceMode)
	}
	if !policyRuleTestContainsString(config.Graph.RequiredColumns, "primary_urn") {
		t.Fatalf("Graph.RequiredColumns = %v, missing primary_urn", config.Graph.RequiredColumns)
	}
	rule := newPolicyCatalogRule(*config)
	if _, ok := rule.(GraphRule); !ok {
		t.Fatalf("newPolicyCatalogRule(generated graph policy) = %T, want GraphRule", rule)
	}
}

func generatedPolicyRuleConfigByID(ruleID string) *policyRuleConfig {
	for i := range generatedPolicyRuleCatalog {
		if generatedPolicyRuleCatalog[i].Definition.ID == ruleID {
			return &generatedPolicyRuleCatalog[i]
		}
	}
	return nil
}

func policyRuleTestContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

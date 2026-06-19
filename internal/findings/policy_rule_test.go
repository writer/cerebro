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
			"policy_id":    "policy-test",
			"result":       "failed",
			"resource_urn": "urn:cerebro:tenant-1:test:resource-1",
			"resource_id":  "resource-1",
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

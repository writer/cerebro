package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGRCPolicyRuleLinksPolicyControlsRequirementsOwnerDocumentAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-rule-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_rule",
		Attributes: map[string]string{
			"provider":                  "cerebro",
			"policy_rule_id":            "identity-access-okta-user",
			"policy_rule_name":          "Okta user access evidence",
			"policy_id":                 "access-policy",
			"policy_version_id":         "access-policy-v2",
			"control_ids":               "CC6.1",
			"evidence_requirement_refs": "identity-access/okta/identity_user,repository-access/github/repository_access",
			"owner_id":                  "owner-1",
			"document_id":               "access-policy-doc",
			"evidence_cas_uri":          "evidencecas://policy-rules/identity-access-okta-user",
			"profile_id":                "identity-access",
			"required_source_id":        "okta",
			"entity_type":               "identity_user",
			"target_id":                 "production-identity",
			"target_type":               "identity_system",
			"mitre_attack_techniques":   "T1078",
			"mitre_defend_techniques":   "TokenBinding",
			"claim_strength":            "source_backed",
			"sufficiency_rule":          "source_period_state_exception",
			"coverage_claim":            "supports_control",
			"status":                    "active",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	ruleURN := "urn:cerebro:writer:policy_rule:cerebro:identity-access-okta-user"
	policyURN := "urn:cerebro:writer:policy:cerebro:policy:access-policy"
	versionURN := "urn:cerebro:writer:policy_version:cerebro:access-policy-v2"
	controlURN := "urn:cerebro:writer:policy:cerebro:control:CC6.1"
	firstRequirementURN := "urn:cerebro:writer:evidence_requirement:cerebro:identity-access/okta/identity_user"
	secondRequirementURN := "urn:cerebro:writer:evidence_requirement:cerebro:repository-access/github/repository_access"
	integrationURN := "urn:cerebro:writer:source:cerebro:integration:okta"
	targetURN := "urn:cerebro:writer:grc_target:cerebro:production-identity"
	attackTechniqueURN := "urn:cerebro:writer:mitre_attack_technique:T1078"
	defendTechniqueURN := "urn:cerebro:writer:mitre_defend_technique:TokenBinding"
	ownerURN := "urn:cerebro:writer:user:cerebro:owner-1"
	documentURN := "urn:cerebro:writer:document:cerebro:access-policy-doc"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidencecas_policy_rules_identity_access_okta_user"
	if entity := state.entities[ruleURN]; entity == nil || entity.EntityType != "policy.rule" || entity.Attributes["claim_strength"] != "source_backed" {
		t.Fatalf("policy rule entity = %#v, want typed policy rule", entity)
	}
	assertProjectedLink(t, state, ruleURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, ruleURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, ruleURN, relationSupports, controlURN)
	assertProjectedLink(t, state, ruleURN, relationAssociatedWith, firstRequirementURN)
	assertProjectedLink(t, state, ruleURN, relationAssociatedWith, secondRequirementURN)
	assertProjectedLink(t, state, ruleURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, ruleURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, ruleURN, relationHasContext, attackTechniqueURN)
	assertProjectedLink(t, state, ruleURN, relationHasContext, defendTechniqueURN)
	assertProjectedLink(t, state, ruleURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, ruleURN, relationHasEvidence, documentURN)
	assertProjectedLink(t, state, ruleURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCEvidenceRequirementLinksControlsPolicyRulesOwnerAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-evidence-requirement-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.evidence_requirement",
		Attributes: map[string]string{
			"provider":                "cerebro",
			"evidence_requirement_id": "identity-access/okta/identity_user",
			"requirement_name":        "Okta user state",
			"profile_id":              "identity-access",
			"required_source_id":      "okta",
			"entity_type":             "identity_user",
			"required_fields":         "user_id,status",
			"freshness_window":        "24h",
			"control_ids":             "CC6.1,CC6.2",
			"policy_rule_id":          "identity-access-okta-user",
			"owner_id":                "owner-1",
			"evidence_id":             "requirement-evidence-1",
			"status":                  "current",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	requirementURN := "urn:cerebro:writer:evidence_requirement:cerebro:identity-access/okta/identity_user"
	firstControlURN := "urn:cerebro:writer:policy:cerebro:control:CC6.1"
	secondControlURN := "urn:cerebro:writer:policy:cerebro:control:CC6.2"
	ruleURN := "urn:cerebro:writer:policy_rule:cerebro:identity-access-okta-user"
	integrationURN := "urn:cerebro:writer:source:cerebro:integration:okta"
	ownerURN := "urn:cerebro:writer:user:cerebro:owner-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:requirement-evidence-1"
	if entity := state.entities[requirementURN]; entity == nil || entity.EntityType != "evidence.requirement" || entity.Attributes["required_fields"] != "user_id,status" {
		t.Fatalf("evidence requirement entity = %#v, want typed requirement", entity)
	}
	assertProjectedLink(t, state, requirementURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, requirementURN, relationSupports, secondControlURN)
	assertProjectedLink(t, state, requirementURN, relationAssociatedWith, ruleURN)
	assertProjectedLink(t, state, requirementURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, requirementURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, requirementURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCCoverageGapLinksControlsRulesRequirementsTargetsOwnerDocumentAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-coverage-gap-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.coverage_gap",
		Attributes: map[string]string{
			"provider":                "cerebro",
			"coverage_gap_id":         "gap-identity-access-okta-status",
			"gap_title":               "Okta user status missing",
			"gap_type":                "missing_field",
			"gap_state":               "open",
			"severity":                "medium",
			"control_references":      "CC6.1=CC6.1",
			"policy_rule_id":          "identity-access-okta-user",
			"evidence_requirement_id": "identity-access/okta/identity_user",
			"target_id":               "okta-user-status",
			"target_type":             "identity_user",
			"required_source_id":      "okta",
			"owner_id":                "owner-1",
			"document_id":             "gap-evidence-doc",
			"evidence_id":             "gap-evidence-1",
			"finding_id":              "finding-should-not-exist",
			"status":                  "open",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	gapURN := "urn:cerebro:writer:coverage_gap:cerebro:gap-identity-access-okta-status"
	controlURN := "urn:cerebro:writer:policy:cerebro:control:CC6.1"
	ruleURN := "urn:cerebro:writer:policy_rule:cerebro:identity-access-okta-user"
	requirementURN := "urn:cerebro:writer:evidence_requirement:cerebro:identity-access/okta/identity_user"
	targetURN := "urn:cerebro:writer:grc_target:cerebro:okta-user-status"
	integrationURN := "urn:cerebro:writer:source:cerebro:integration:okta"
	ownerURN := "urn:cerebro:writer:user:cerebro:owner-1"
	documentURN := "urn:cerebro:writer:document:cerebro:gap-evidence-doc"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:gap-evidence-1"
	findingURN := "urn:cerebro:writer:finding:finding-should-not-exist"
	if entity := state.entities[gapURN]; entity == nil || entity.EntityType != "coverage.gap" || entity.Attributes["gap_type"] != "missing_field" {
		t.Fatalf("coverage gap entity = %#v, want typed coverage gap", entity)
	}
	assertProjectedLink(t, state, gapURN, relationSupports, controlURN)
	if got := state.links[gapURN+"|"+relationSupports+"|"+controlURN].Attributes["coverage_status"]; got != "gap" {
		t.Fatalf("coverage gap control link coverage_status = %q, want gap", got)
	}
	assertProjectedLink(t, state, gapURN, relationAssociatedWith, ruleURN)
	assertProjectedLink(t, state, gapURN, relationAssociatedWith, requirementURN)
	assertProjectedLink(t, state, gapURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, gapURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, gapURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, gapURN, relationHasEvidence, documentURN)
	assertProjectedLink(t, state, gapURN, relationHasEvidence, evidenceURN)
	if state.entities[findingURN] != nil {
		t.Fatalf("coverage gap projected a finding entity: %#v", state.entities[findingURN])
	}
}

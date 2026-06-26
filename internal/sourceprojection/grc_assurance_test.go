package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGRCSecurityReviewLinksVendorAccountOwnerControlsEvidenceAndQuestionnaire(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-security-review-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.security_review",
		Attributes: map[string]string{
			"provider":                  "grc",
			"security_review_id":        "review-1",
			"title":                     "Acme annual review",
			"vendor_id":                 "vendor-1",
			"customer_trust_account_id": "account-1",
			"owner_id":                  "user-1",
			"control_ids":               "control-1",
			"evidence_id":               "evidence-1",
			"evidence_type":             "security_review",
			"security_questionnaire_id": "questionnaire-1",
			"review_type":               "annual",
			"risk_level":                "HIGH",
			"status":                    "complete",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	reviewURN := "urn:cerebro:writer:security_review:grc:review-1"
	vendorURN := "urn:cerebro:writer:vendor:grc:vendor-1"
	accountURN := "urn:cerebro:writer:customer_trust_account:grc:account-1"
	ownerURN := "urn:cerebro:writer:user:grc:user-1"
	controlURN := "urn:cerebro:writer:policy:grc:control:control-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-1"
	questionnaireURN := "urn:cerebro:writer:security_questionnaire:grc:questionnaire-1"
	riskTagURN := "urn:cerebro:writer:asset_tag:security_review:high"
	if entity := state.entities[reviewURN]; entity == nil || entity.EntityType != "security.review" {
		t.Fatalf("security review entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, reviewURN, relationAssociatedWith, vendorURN)
	assertProjectedLink(t, state, reviewURN, relationAssociatedWith, accountURN)
	assertProjectedLink(t, state, reviewURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, reviewURN, relationSupports, controlURN)
	assertProjectedLink(t, state, reviewURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, reviewURN, relationAssociatedWith, questionnaireURN)
	assertProjectedLink(t, state, reviewURN, relationTaggedAs, riskTagURN)
}

func TestProjectGRCSecurityQuestionnaireLinksAccountControlsEvidenceAndDocument(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-security-questionnaire-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.security_questionnaire",
		Attributes: map[string]string{
			"provider":                  "grc",
			"security_questionnaire_id": "questionnaire-1",
			"customer_trust_account_id": "account-1",
			"owner_id":                  "user-1",
			"control_ids":               "control-1,control-2",
			"evidence_cas_uri":          "evidencecas://questionnaires/questionnaire-1",
			"document_id":               "document-1",
			"questionnaire_type":        "customer_assurance",
			"status":                    "submitted",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	questionnaireURN := "urn:cerebro:writer:security_questionnaire:grc:questionnaire-1"
	accountURN := "urn:cerebro:writer:customer_trust_account:grc:account-1"
	ownerURN := "urn:cerebro:writer:user:grc:user-1"
	firstControlURN := "urn:cerebro:writer:policy:grc:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:grc:control:control-2"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidencecas_questionnaires_questionnaire_1"
	documentURN := "urn:cerebro:writer:assurance_document:grc:document-1"
	assertProjectedLink(t, state, questionnaireURN, relationAssociatedWith, accountURN)
	assertProjectedLink(t, state, questionnaireURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, questionnaireURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, questionnaireURN, relationSupports, secondControlURN)
	assertProjectedLink(t, state, questionnaireURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, questionnaireURN, relationAssociatedWith, documentURN)
	if got := state.entities[accountURN].Label; got != "account-1" {
		t.Fatalf("customer trust account label = %q, want account-1", got)
	}
}

func TestProjectGRCSecurityReviewDocumentIDDoesNotCreateAssuranceDocumentLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-security-review-ambiguous-document",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.security_review",
		Attributes: map[string]string{
			"provider":           "grc",
			"security_review_id": "review-1",
			"document_id":        "document-1",
			"status":             "complete",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	reviewURN := "urn:cerebro:writer:security_review:grc:review-1"
	documentURN := "urn:cerebro:writer:assurance_document:grc:document-1"
	assertProjectedLinkMissing(t, state, reviewURN, relationAssociatedWith, documentURN)
	if entity := state.entities[documentURN]; entity != nil {
		t.Fatalf("assurance document entity was created from ambiguous document_id: %#v", entity)
	}
}

func TestProjectGRCPenetrationTestLinksTargetControlsFindingsAndVulnerabilities(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-penetration-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.penetration_test",
		Attributes: map[string]string{
			"provider":            "grc",
			"penetration_test_id": "pentest-1",
			"title":               "External network assessment",
			"target_id":           "edge-api",
			"target_type":         "service",
			"control_ids":         "control-1",
			"finding_ids":         "finding-1,finding-2",
			"vulnerability_ids":   "vuln-1",
			"evidence_id":         "pentest-evidence-1",
			"test_type":           "external",
			"status":              "complete",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:penetration_test:grc:pentest-1"
	targetURN := "urn:cerebro:writer:grc_target:grc:edge-api"
	controlURN := "urn:cerebro:writer:policy:grc:control:control-1"
	firstFindingURN := "urn:cerebro:writer:finding:finding-1"
	secondFindingURN := "urn:cerebro:writer:finding:finding-2"
	vulnerabilityURN := "urn:cerebro:writer:grc_vulnerability:grc:vuln-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:pentest-evidence-1"
	if entity := state.entities[testURN]; entity == nil || entity.EntityType != "penetration.test" {
		t.Fatalf("penetration test entity missing: %#v", entity)
	}
	if got := state.entities[firstFindingURN].Label; got != "finding-1" {
		t.Fatalf("first finding label = %q, want finding-1", got)
	}
	if got := state.entities[secondFindingURN].Label; got != "finding-2" {
		t.Fatalf("second finding label = %q, want finding-2", got)
	}
	if got := state.entities[vulnerabilityURN].Label; got != "vuln-1" {
		t.Fatalf("vulnerability label = %q, want vuln-1", got)
	}
	assertProjectedLink(t, state, testURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, testURN, relationSupports, controlURN)
	assertProjectedLink(t, state, testURN, relationAssociatedWith, firstFindingURN)
	assertProjectedLink(t, state, testURN, relationAssociatedWith, secondFindingURN)
	assertProjectedLink(t, state, testURN, relationAssociatedWith, vulnerabilityURN)
	assertProjectedLink(t, state, testURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCAssuranceDocumentLinksUploadHostVendorControlsAndReview(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-assurance-document-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.assurance_document",
		Attributes: map[string]string{
			"provider":              "grc",
			"assurance_document_id": "document-1",
			"title":                 "SOC 2 report",
			"document_type":         "SOC 2",
			"vendor_id":             "vendor-1",
			"uploaded_by_user_id":   "user-1",
			"control_ids":           "control-1",
			"security_review_id":    "review-1",
			"evidence_id":           "document-evidence-1",
			"url":                   "https://trust.writer.com/reports/soc-2",
			"status":                "approved",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	documentURN := "urn:cerebro:writer:assurance_document:grc:document-1"
	hostURN := "urn:cerebro:writer:internet_host:trust.writer.com"
	vendorURN := "urn:cerebro:writer:vendor:grc:vendor-1"
	userURN := "urn:cerebro:writer:user:grc:user-1"
	controlURN := "urn:cerebro:writer:policy:grc:control:control-1"
	reviewURN := "urn:cerebro:writer:security_review:grc:review-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:document-evidence-1"
	typeTagURN := "urn:cerebro:writer:asset_tag:assurance_document:soc_2"
	if entity := state.entities[documentURN]; entity == nil || entity.EntityType != "assurance.document" {
		t.Fatalf("assurance document entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, documentURN, relationHasIdentifier, hostURN)
	assertProjectedLink(t, state, documentURN, relationAssociatedWith, vendorURN)
	assertProjectedLink(t, state, documentURN, relationOwnedBy, userURN)
	assertProjectedLink(t, state, userURN, relationActedOn, documentURN)
	assertProjectedLink(t, state, documentURN, relationSupports, controlURN)
	assertProjectedLink(t, state, documentURN, relationAssociatedWith, reviewURN)
	assertProjectedLink(t, state, documentURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, documentURN, relationTaggedAs, typeTagURN)
}

func TestProjectGRCDocumentLinksURLAndCategory(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-document-doc-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.document",
		Attributes: map[string]string{
			"provider":    "vanta",
			"document_id": "doc-1",
			"title":       "AWS Architecture",
			"category":    "Infrastructure",
			"url":         "https://docs.writer.com/security/aws-architecture",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	documentURN := "urn:cerebro:writer:document:vanta:doc-1"
	hostURN := "urn:cerebro:writer:internet_host:docs.writer.com"
	categoryURN := "urn:cerebro:writer:asset_tag:grc_category:infrastructure"
	assertProjectedLink(t, state, documentURN, relationHasIdentifier, hostURN)
	assertProjectedLink(t, state, documentURN, relationTaggedAs, categoryURN)
}

func TestProjectGRCContractLinksVendorControlsOwnerAndEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-contract-contract-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.contract",
		Attributes: map[string]string{
			"provider":         "vanta",
			"contract_id":      "contract-1",
			"name":             "Acme Critical ICT Contract",
			"vendor_id":        "vendor-1",
			"vendor_name":      "Acme SaaS",
			"owner_id":         "user-1",
			"control_ids":      "control-1",
			"evidence_id":      "evidence-1",
			"evidence_cas_uri": "evidencecas://contracts/contract-1",
			"evidence_type":    "signed_contract",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	contractURN := "urn:cerebro:writer:contract:vanta:contract-1"
	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-1"
	if entity := state.entities[contractURN]; entity == nil || entity.EntityType != "contract" {
		t.Fatalf("contract entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, contractURN, relationAssociatedWith, vendorURN)
	assertProjectedLink(t, state, contractURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, contractURN, relationSupports, controlURN)
	assertProjectedLink(t, state, contractURN, relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationObservedOn, contractURN)
}

package sourceprojection

import (
	"context"
	"fmt"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type endpointCheckingGraphRecorder struct {
	projectionRecorder
}

func (r *endpointCheckingGraphRecorder) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if r.entities[link.FromURN] == nil {
		return fmt.Errorf("graph link source entity %q missing", link.FromURN)
	}
	if r.entities[link.ToURN] == nil {
		return fmt.Errorf("graph link target entity %q missing", link.ToURN)
	}
	return r.projectionRecorder.UpsertProjectedLink(ctx, link)
}

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

func TestProjectGRCVendorWithOwner(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vendor-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":               "vanta",
			"vendor_id":              "vendor-1",
			"name":                   "Acme SaaS",
			"website_url":            "https://app.writer.com",
			"security_owner_user_id": "user-1",
			"inherent_risk_level":    "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	aliasURN := "urn:cerebro:writer:vendor_alias:acme-saas"
	if entity := state.entities[vendorURN]; entity == nil || entity.EntityType != "vendor" {
		t.Fatalf("vendor entity missing: %#v", entity)
	}
	if got := state.entities[vendorURN].Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("vendor inherent_risk_level = %q, want HIGH", got)
	}
	if entity := state.entities[ownerURN]; entity == nil || entity.EntityType != "user" {
		t.Fatalf("owner user entity missing: %#v", entity)
	}
	if entity := state.entities[hostURN]; entity == nil || entity.EntityType != "internet.host" {
		t.Fatalf("internet host entity missing: %#v", entity)
	}
	if entity := state.entities[aliasURN]; entity == nil || entity.EntityType != "vendor.alias" {
		t.Fatalf("vendor alias entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, vendorURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, vendorURN, relationHasIdentifier, hostURN)
	assertProjectedLink(t, state, vendorURN, relationHasIdentifier, aliasURN)
}

func TestProjectGRCVendorLinksAccountManagerEmail(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vendor-contact",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":              "vanta",
			"vendor_id":             "vendor-1",
			"name":                  "Acme SaaS",
			"account_manager_email": "manager@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	vendorURN := "urn:cerebro:writer:vendor:vanta:vendor-1"
	identityURN := "urn:cerebro:writer:identity:email:manager@example.com"
	assertProjectedLink(t, state, vendorURN, relationAssociatedWith, identityURN)
	link := state.links[vendorURN+"|"+relationAssociatedWith+"|"+identityURN]
	if got := link.Attributes["contact_type"]; got != "account_manager" {
		t.Fatalf("contact_type = %q, want account_manager", got)
	}
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

func TestProjectGRCDiscoveredVendorLinksAliasesCategoryAndReviewer(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-discovered-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.discovered_vendor",
		Attributes: map[string]string{
			"provider":             "grc",
			"discovered_vendor_id": "discovered-vendor-1",
			"name":                 "Acme, Inc.",
			"normalized_name":      "Acme",
			"category":             "AI",
			"ignored_reason":       "duplicate",
			"ignored_by_user_id":   "user-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	discoveryURN := "urn:cerebro:writer:vendor_discovery:grc:discovered-vendor-1"
	aliasURN := "urn:cerebro:writer:vendor_alias:acme-inc"
	normalizedAliasURN := "urn:cerebro:writer:vendor_alias:acme"
	categoryURN := "urn:cerebro:writer:asset_tag:vendor_category:ai"
	userURN := "urn:cerebro:writer:user:grc:user-1"
	if entity := state.entities[discoveryURN]; entity == nil || entity.EntityType != "vendor.discovery" {
		t.Fatalf("discovered vendor entity missing: %#v", entity)
	}
	if got := state.entities[discoveryURN].Attributes["status"]; got != "ignored" {
		t.Fatalf("discovered vendor status = %q, want ignored", got)
	}
	assertProjectedLink(t, state, discoveryURN, relationHasIdentifier, aliasURN)
	assertProjectedLink(t, state, discoveryURN, relationHasIdentifier, normalizedAliasURN)
	assertProjectedLink(t, state, discoveryURN, relationTaggedAs, categoryURN)
	assertProjectedLink(t, state, userURN, relationActedOn, discoveryURN)
}

func TestProjectGRCEventLogLinksActorAndTargets(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-1",
			"action":       "vendor.review.created",
			"actor_type":   "user",
			"actor_id":     "user-1",
			"targets":      "vendor:vendor-1;control:control-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	eventURN := "urn:cerebro:writer:grc_audit_event:grc:event-log-1"
	actorURN := "urn:cerebro:writer:user:grc:user-1"
	vendorTargetURN := "urn:cerebro:writer:grc_audit_target:grc:vendor:vendor-1"
	controlTargetURN := "urn:cerebro:writer:grc_audit_target:grc:control:control-1"
	if entity := state.entities[eventURN]; entity == nil || entity.EntityType != "audit.event" {
		t.Fatalf("event log entity missing: %#v", entity)
	}
	if got := state.entities[actorURN].Attributes["user_id"]; got != "user-1" {
		t.Fatalf("user actor user_id = %q, want user-1", got)
	}
	assertProjectedLink(t, state, actorURN, relationActedOn, eventURN)
	assertProjectedLink(t, state, eventURN, relationObservedOn, vendorTargetURN)
	assertProjectedLink(t, state, eventURN, relationObservedOn, controlTargetURN)
}

func TestProjectGRCEventLogDoesNotSetUserIDForNonUserActor(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-2",
			"action":       "integration.sync.completed",
			"actor_type":   "system",
			"actor_id":     "automation",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	actorURN := "urn:cerebro:writer:grc_audit_actor:grc:system:automation"
	entity := state.entities[actorURN]
	if entity == nil || entity.EntityType != "audit.actor" {
		t.Fatalf("non-user actor entity missing: %#v", entity)
	}
	if got := entity.Attributes["user_id"]; got != "" {
		t.Fatalf("non-user actor user_id = %q, want unset", got)
	}
}

func TestProjectGRCEventLogDefaultsMissingActorTypeToResource(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-event-log-3",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.event_log",
		Attributes: map[string]string{
			"provider":     "grc",
			"event_log_id": "event-log-3",
			"action":       "resource.updated",
			"actor_id":     "automation",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	eventURN := "urn:cerebro:writer:grc_audit_event:grc:event-log-3"
	actorURN := "urn:cerebro:writer:grc_audit_actor:grc:resource:automation"
	entity := state.entities[actorURN]
	if entity == nil || entity.EntityType != "audit.actor" {
		t.Fatalf("default actor entity missing: %#v", entity)
	}
	if got := entity.Attributes["actor_type"]; got != "resource" {
		t.Fatalf("default actor_type = %q, want resource", got)
	}
	assertProjectedLink(t, state, actorURN, relationActedOn, eventURN)
	link := state.links[actorURN+"|"+relationActedOn+"|"+eventURN]
	if got := link.Attributes["actor_type"]; got != "resource" {
		t.Fatalf("default actor link actor_type = %q, want resource", got)
	}
}

func TestProjectGRCGroupAndVendorRiskAttribute(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "grc-group-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.group",
			Attributes: map[string]string{
				"provider":   "grc",
				"group_id":   "group-1",
				"group_name": "Security",
			},
		},
		{
			Id:       "grc-vendor-risk-attribute-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.vendor_risk_attribute",
			Attributes: map[string]string{
				"provider":                 "grc",
				"vendor_risk_attribute_id": "risk-attr-1",
				"name":                     "Sensitive data",
				"vendor_categories":        "AI,Infrastructure",
				"risk_level":               "HIGH",
				"enabled":                  "true",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.Kind, err)
		}
	}

	groupURN := "urn:cerebro:writer:grc_group:grc:group-1"
	attributeURN := "urn:cerebro:writer:vendor_risk_attribute:grc:risk-attr-1"
	categoryURN := "urn:cerebro:writer:asset_tag:vendor_category:ai"
	riskURN := "urn:cerebro:writer:asset_tag:vendor_risk_level:high"
	if entity := state.entities[groupURN]; entity == nil || entity.EntityType != "group" {
		t.Fatalf("group entity missing: %#v", entity)
	}
	if entity := state.entities[attributeURN]; entity == nil || entity.EntityType != "vendor.risk_attribute" {
		t.Fatalf("vendor risk attribute entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, attributeURN, relationTaggedAs, categoryURN)
	assertProjectedLink(t, state, attributeURN, relationTaggedAs, riskURN)
}

func TestProjectGRCRegulatoryNotificationLinksIncidentAndControls(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-regulatory-notification-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.regulatory_notification",
		Attributes: map[string]string{
			"provider":          "vanta",
			"framework":         "DORA",
			"incident_id":       "incident-1",
			"incident_title":    "Payments outage",
			"notification_type": "initial",
			"control_ids":       "dora-art-19",
			"status":            "sent",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	notificationURN := "urn:cerebro:writer:regulatory_notification:vanta:dora_incident_1_initial"
	incidentURN := "urn:cerebro:writer:incident:vanta:incident-1"
	controlURN := "urn:cerebro:writer:policy:vanta:control:dora-art-19"
	if entity := state.entities[notificationURN]; entity == nil || entity.EntityType != "regulatory.notification" {
		t.Fatalf("notification entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, notificationURN, relationObservedOn, incidentURN)
	assertProjectedLink(t, state, notificationURN, relationSupports, controlURN)
}

func TestProjectGRCRecoveryObjectiveTargetsServiceAndProcess(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-recovery-objective-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.recovery_objective",
		Attributes: map[string]string{
			"provider":              "vanta",
			"recovery_objective_id": "objective-1",
			"service_id":            "payments-api",
			"target_type":           "service",
			"business_process":      "Payment Processing",
			"rto_minutes":           "60",
			"rpo_minutes":           "15",
			"control_ids":           "cp-10",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	objectiveURN := "urn:cerebro:writer:resilience_recovery_objective:vanta:objective-1"
	targetURN := "urn:cerebro:writer:grc_target:vanta:payments-api"
	processURN := "urn:cerebro:writer:business_process:vanta:payment_processing"
	controlURN := "urn:cerebro:writer:policy:vanta:control:cp-10"
	if got := state.entities[objectiveURN].Attributes["rto_minutes"]; got != "60" {
		t.Fatalf("rto_minutes = %q, want 60", got)
	}
	assertProjectedLink(t, state, objectiveURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, objectiveURN, relationSupports, processURN)
	assertProjectedLink(t, state, objectiveURN, relationSupports, controlURN)
}

func TestProjectGRCAuthorizationPackageTargetsSystemAndControls(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-authorization-package-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.authorization_package",
		Attributes: map[string]string{
			"provider":                 "vanta",
			"authorization_package_id": "ato-1",
			"framework":                "FedRAMP Rev. 5",
			"impact_level":             "Moderate",
			"system_id":                "writer-cloud",
			"system_name":              "Writer Cloud",
			"target_type":              "cloud_service_offering",
			"control_ids":              "fedramp-ca-7",
			"evidence_id":              "ssp-evidence-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageURN := "urn:cerebro:writer:authorization_package:vanta:ato-1"
	targetURN := "urn:cerebro:writer:grc_target:vanta:writer-cloud"
	controlURN := "urn:cerebro:writer:policy:vanta:control:fedramp-ca-7"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:ssp-evidence-1"
	if entity := state.entities[packageURN]; entity == nil || entity.EntityType != "authorization.package" {
		t.Fatalf("authorization package entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, packageURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, packageURN, relationSupports, controlURN)
	assertProjectedLink(t, state, packageURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCPOAMItemLinksFindingTargetAndControl(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-poam-item-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.poam_item",
		Attributes: map[string]string{
			"provider":      "vanta",
			"poam_item_id":  "poam-1",
			"finding_id":    "finding-1",
			"title":         "GuardDuty not enabled",
			"risk_rating":   "high",
			"status":        "open",
			"target_id":     "aws-prod",
			"target_type":   "account",
			"control_ids":   "si-4",
			"evidence_type": "poam_record",
			"evidence_id":   "poam-evidence-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	itemURN := "urn:cerebro:writer:poam_item:vanta:poam-1"
	findingURN := "urn:cerebro:writer:finding:finding-1"
	targetURN := "urn:cerebro:writer:grc_target:vanta:aws-prod"
	controlURN := "urn:cerebro:writer:policy:vanta:control:si-4"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:poam-evidence-1"
	if entity := state.entities[itemURN]; entity == nil || entity.EntityType != "poam.item" {
		t.Fatalf("POA&M item entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, itemURN, relationAssociatedWith, findingURN)
	assertProjectedLink(t, state, itemURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, itemURN, relationSupports, controlURN)
	assertProjectedLink(t, state, itemURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCTrainingAttestationLinksPersonUserAndControl(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-training-attestation-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.training_attestation",
		Attributes: map[string]string{
			"provider":         "vanta",
			"attestation_id":   "attestation-1",
			"person_id":        "person-1",
			"user_id":          "user-1",
			"course_id":        "security-101",
			"course_name":      "Security Awareness",
			"training_type":    "security_awareness",
			"completed_at":     "2026-06-01T00:00:00Z",
			"control_ids":      "training-control",
			"evidence_cas_uri": "evidencecas://training/attestation-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	attestationURN := "urn:cerebro:writer:training_attestation:vanta:attestation-1"
	personURN := "urn:cerebro:writer:person:vanta:person-1"
	userURN := "urn:cerebro:writer:user:vanta:user-1"
	controlURN := "urn:cerebro:writer:policy:vanta:control:training-control"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidencecas_training_attestation_1"
	if entity := state.entities[attestationURN]; entity == nil || entity.EntityType != "training.attestation" {
		t.Fatalf("training attestation entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, personURN, relationHasEvidence, attestationURN)
	assertProjectedLink(t, state, userURN, relationHasEvidence, attestationURN)
	assertProjectedLink(t, state, attestationURN, relationSupports, controlURN)
	assertProjectedLink(t, state, attestationURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCIntegrationTagsResourceKinds(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-integration-aws",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.integration",
		Attributes: map[string]string{
			"provider":       "vanta",
			"integration_id": "aws",
			"display_name":   "AWS",
			"resource_kinds": "AwsAccountMetadata,CloudTrail",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	sourceURN := "urn:cerebro:writer:source:vanta:integration:aws"
	accountMetadataURN := "urn:cerebro:writer:asset_tag:grc_resource_kind:awsaccountmetadata"
	cloudTrailURN := "urn:cerebro:writer:asset_tag:grc_resource_kind:cloudtrail"
	assertProjectedLink(t, state, sourceURN, relationTaggedAs, accountMetadataURN)
	assertProjectedLink(t, state, sourceURN, relationTaggedAs, cloudTrailURN)
}

func TestProjectGRCVulnerabilityRemediationLinksVulnerabilityAndAsset(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-remediation-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability_remediation",
		Attributes: map[string]string{
			"provider":            "grc",
			"remediation_id":      "remediation-1",
			"vulnerability_id":    "vuln-1",
			"vulnerable_asset_id": "asset-1",
			"severity":            "HIGH",
			"sla_deadline_at":     "2026-06-30T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	remediationURN := "urn:cerebro:writer:vulnerability_remediation:grc:remediation-1"
	vulnerabilityURN := "urn:cerebro:writer:grc_vulnerability:grc:vuln-1"
	targetURN := "urn:cerebro:writer:grc_target:grc:asset-1"
	if entity := state.entities[remediationURN]; entity == nil || entity.EntityType != "vulnerability.remediation" {
		t.Fatalf("vulnerability remediation entity missing: %#v", entity)
	}
	if got := state.entities[remediationURN].Attributes["status"]; got != "open" {
		t.Fatalf("remediation status = %q, want open", got)
	}
	vulnerabilityEntity := state.entities[vulnerabilityURN]
	if vulnerabilityEntity == nil {
		t.Fatalf("vulnerability entity missing: %#v", vulnerabilityEntity)
	}
	if got := vulnerabilityEntity.Attributes["remediation_id"]; got != "" {
		t.Fatalf("vulnerability remediation_id = %q, want unset", got)
	}
	if got := vulnerabilityEntity.Attributes["sla_deadline_at"]; got != "" {
		t.Fatalf("vulnerability sla_deadline_at = %q, want unset", got)
	}
	assertProjectedLink(t, state, remediationURN, relationAssociatedWith, vulnerabilityURN)
	assertProjectedLink(t, state, remediationURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
}

func TestProjectGRCControlTestSupportsControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC6.2,CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:evidence:vanta:control_test:test-1"
	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	assertProjectedLink(t, state, testURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, testURN, relationSupports, secondControlURN)
	if got := state.entities[firstControlURN].Attributes["control_external_id"]; got != "CC6.2" {
		t.Fatalf("first control_external_id = %q, want CC6.2", got)
	}
	if got := state.entities[firstControlURN].Label; got != "CC6.2" {
		t.Fatalf("first control label = %q, want CC6.2", got)
	}
}

func TestProjectGRCControlTestLinksOwnerIntegrationAndCategory(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":     "vanta",
			"test_id":      "test-1",
			"name":         "AWS Config enabled",
			"owner_id":     "user-1",
			"integrations": "aws,gcp",
			"category":     "Infrastructure",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	testURN := "urn:cerebro:writer:evidence:vanta:control_test:test-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	awsSourceURN := "urn:cerebro:writer:source:vanta:integration:aws"
	gcpSourceURN := "urn:cerebro:writer:source:vanta:integration:gcp"
	categoryURN := "urn:cerebro:writer:asset_tag:grc_category:infrastructure"
	assertProjectedLink(t, state, testURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, testURN, relationBelongsTo, awsSourceURN)
	assertProjectedLink(t, state, testURN, relationBelongsTo, gcpSourceURN)
	assertProjectedLink(t, state, testURN, relationTaggedAs, categoryURN)
}

func TestProjectGRCControlTestKeepsPairedControlReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":             "vanta",
			"test_id":              "test-1",
			"control_ids":          "control-1,control-2",
			"control_external_ids": "CC7.1",
			"control_references":   "control-1=;control-2=CC7.1",
			"status":               "FAIL",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	firstControlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	secondControlURN := "urn:cerebro:writer:policy:vanta:control:control-2"
	if state.entities[firstControlURN] != nil {
		t.Fatalf("first control entity = %#v, want no placeholder without external ID", state.entities[firstControlURN])
	}
	if got := state.entities[secondControlURN].Attributes["control_external_id"]; got != "CC7.1" {
		t.Fatalf("second control_external_id = %q, want CC7.1", got)
	}
}

func TestProjectGRCControlLinksOwnerAndDomains(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-control-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control",
		Attributes: map[string]string{
			"provider":    "vanta",
			"control_id":  "control-1",
			"name":        "Access Reviews",
			"owner_id":    "user-1",
			"domains":     "COMPLIANCE, SECURITY & PRIVACY GOVERNANCE",
			"description": "Access is reviewed periodically",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	ownerURN := "urn:cerebro:writer:user:vanta:user-1"
	complianceURN := "urn:cerebro:writer:asset_tag:grc_domain:compliance"
	securityURN := "urn:cerebro:writer:asset_tag:grc_domain:security_privacy_governance"
	assertProjectedLink(t, state, controlURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, controlURN, relationTaggedAs, complianceURN)
	assertProjectedLink(t, state, controlURN, relationTaggedAs, securityURN)
}

func TestProjectGRCControlTestDoesNotRegressControlLabelWhenExternalIDMissingLater(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	first := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-1",
			"control_references": "control-1=CC6.2",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), first); err != nil {
		t.Fatalf("Project(first) error = %v", err)
	}
	second := &cerebrov1.EventEnvelope{
		Id:       "grc-control-test-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider":           "vanta",
			"test_id":            "test-2",
			"control_references": "control-1=",
			"status":             "FAIL",
		},
	}
	if _, err := service.Project(context.Background(), second); err != nil {
		t.Fatalf("Project(second) error = %v", err)
	}

	controlURN := "urn:cerebro:writer:policy:vanta:control:control-1"
	if got := state.entities[controlURN].Label; got != "CC6.2" {
		t.Fatalf("control label = %q, want CC6.2", got)
	}
}

func TestProjectGRCRiskScenarioOwnerDoesNotCreatePersonIdentityBridge(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-risk-risk-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.risk_scenario",
		Attributes: map[string]string{
			"provider":    "vanta",
			"risk_id":     "risk-1",
			"description": "AI vendor risk",
			"owner":       "alice@writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	riskURN := "urn:cerebro:writer:claim:vanta:risk_scenario:risk-1"
	contactURN := "urn:cerebro:writer:contact:vanta:owner:alice@writer.com"
	personURN := "urn:cerebro:writer:person:vanta:owner:alice@writer.com"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	assertProjectedLink(t, state, riskURN, relationAssignedTo, contactURN)
	if _, ok := state.entities[personURN]; ok {
		t.Fatalf("risk owner projected as GRC person: %#v", state.entities[personURN])
	}
	assertProjectedLinkMissing(t, state, contactURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, contactURN, relationAssociatedWith, identityURN)
}

func TestProjectGRCPersonIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-person-person-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.person",
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	if entity := state.entities[personURN]; entity == nil || entity.EntityType != "person" {
		t.Fatalf("person entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, personURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, personURN, relationSameActor, "urn:cerebro:writer:identity:email:alice@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:identity:email:alice@writer.com", relationSameActor, personURN)
}

func TestProjectGRCPersonAndUserSameActorByEmail(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "grc-person-person-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.person",
			Attributes: map[string]string{
				"provider":  "vanta",
				"person_id": "person-1",
				"email":     "alice@writer.com",
			},
		},
		{
			Id:       "grc-user-user-1",
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.user",
			Attributes: map[string]string{
				"provider": "vanta",
				"user_id":  "user-1",
				"email":    "alice@writer.com",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	userURN := "urn:cerebro:writer:user:vanta:user-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	assertProjectedLink(t, state, personURN, relationSameActor, identityURN)
	assertProjectedLink(t, state, userURN, relationSameActor, identityURN)
	assertProjectedLink(t, state, identityURN, relationSameActor, personURN)
	assertProjectedLink(t, state, identityURN, relationSameActor, userURN)
}

func TestProjectGRCPersonStampsIdentifierLinksWithObservationTime(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	historicalEmploymentDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "grc-person-person-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.person",
		OccurredAt: timestamppb.New(historicalEmploymentDate),
		Attributes: map[string]string{
			"provider":          "vanta",
			"person_id":         "person-1",
			"email":             "alice@writer.com",
			"employment_status": "CURRENT",
		},
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	personURN := "urn:cerebro:writer:person:vanta:person-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	link, ok := state.links[personURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", personURN, identityURN, state.links)
	}
	stamped, err := time.Parse(time.RFC3339, link.Attributes["at"])
	if err != nil {
		t.Fatalf("represents_identity at = %q is not RFC3339: %v", link.Attributes["at"], err)
	}
	if stamped.Equal(historicalEmploymentDate) {
		t.Fatalf("represents_identity at = %q, want projection observation time", link.Attributes["at"])
	}
	if stamped.Before(before.Add(-time.Second)) || stamped.After(after.Add(time.Second)) {
		t.Fatalf("represents_identity at = %v not within projection window [%v, %v]", stamped, before, after)
	}
}

func TestProjectGRCVulnerabilityUsesCanonicalVulnerability(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":          "vanta",
			"vulnerability_id":  "vuln-1",
			"name":              "CVE-2026-4242",
			"package":           "pkg:golang/example/module@1.2.3",
			"package_purl":      "pkg:golang/example/module@1.2.3",
			"severity":          "HIGH",
			"remediate_by_date": "2026-05-30T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	if entity := state.entities[vulnerabilityURN]; entity == nil || entity.EntityType != "vulnerability" {
		t.Fatalf("vulnerability entity missing: %#v", entity)
	}
	if got := state.entities[vulnerabilityURN].Attributes["remediate_by_date"]; got != "" {
		t.Fatalf("canonical vulnerability remediate_by_date = %q, want empty package-specific deadline", got)
	}
	if got := state.entities[vulnerabilityURN].Attributes["package"]; got != "" {
		t.Fatalf("canonical vulnerability package = %q, want empty package-specific package", got)
	}
	packageURN := "urn:cerebro:writer:package:grc:pkg:golang/example/module@1.2.3"
	link := state.links[packageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]
	if link == nil {
		t.Fatalf("GRC package affected_by vulnerability link missing: %#v", state.links)
	}
	if got := link.Attributes["remediate_by_date"]; got != "2026-05-30T00:00:00Z" {
		t.Fatalf("affected_by remediate_by_date = %q, want deadline", got)
	}
}

func TestProjectGRCVulnerabilitySkipsMissingTargetAndIntegrationIDs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta"
	integrationURN := "urn:cerebro:writer:source:vanta:integration"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	packageURN := "urn:cerebro:writer:package:grc:example/module"

	if entity := state.entities[targetURN]; entity != nil {
		t.Fatalf("phantom GRC target entity = %#v, want nil", entity)
	}
	if entity := state.entities[integrationURN]; entity != nil {
		t.Fatalf("phantom GRC integration entity = %#v, want nil", entity)
	}
	assertProjectedLinkMissing(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLinkMissing(t, state, targetURN, relationContains, packageURN)
	assertProjectedLinkMissing(t, state, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityLinksTargetPackageAndIntegration(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":           "vanta",
			"vulnerability_id":   "vuln-1",
			"name":               "CVE-2026-4242",
			"package":            "example/module",
			"package_purl":       "pkg:golang/example/module@1.2.3",
			"severity":           "HIGH",
			"target_id":          "target-1",
			"integration_id":     "integration-1",
			"vulnerability_type": "package",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"

	if entity := state.entities[targetURN]; entity == nil || entity.EntityType != "grc.target" {
		t.Fatalf("GRC target entity missing: %#v", entity)
	}
	if got := state.entities[targetURN].Attributes["integration_id"]; got != "integration-1" {
		t.Fatalf("target integration_id = %q, want integration-1", got)
	}
	if entity := state.entities[integrationURN]; entity == nil || entity.EntityType != "source" {
		t.Fatalf("GRC integration source reference missing: %#v", entity)
	}
	assertProjectedLink(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationContains, packageURN)
	assertProjectedLink(t, state, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityLinksHostLikeTargetID(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-host-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"target_id":        "app.writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:app.writer.com"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	if got := state.entities[targetURN].Attributes["host"]; got != "app.writer.com" {
		t.Fatalf("target host = %q, want app.writer.com", got)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
}

func TestProjectGRCVulnerableAssetEnrichesVulnerabilityTarget(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-1",
			"target_name":                "App Server",
			"hostname":                   "app.writer.com",
			"ip":                         "203.0.113.10",
			"integration_id":             "integration-1",
			"asset_type":                 "server",
			"vulnerability_ids":          "CVE-2026-4242",
			"package_identifiers":        "pkg:golang/example/module@1.2.3",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/module@1.2.3"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	ipURN := "urn:cerebro:writer:internet_ip:203.0.113.10"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:pkg:golang/example/module@1.2.3"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:golang/example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"

	if entity := state.entities[targetURN]; entity == nil || entity.EntityType != "grc.target" {
		t.Fatalf("GRC target entity missing: %#v", entity)
	}
	if got := state.entities[targetURN].Attributes["host"]; got != "app.writer.com" {
		t.Fatalf("target host = %q, want app.writer.com", got)
	}
	if got := state.entities[targetURN].Attributes["target_type"]; got != "server" {
		t.Fatalf("target_type = %q, want server", got)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, ipURN)
	assertProjectedLink(t, state, targetURN, relationBelongsTo, integrationURN)
	assertProjectedLink(t, state, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
	assertProjectedLink(t, state, packageURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, canonicalPackageURN, relationAffectedBy, vulnerabilityURN)
}

func TestProjectGRCVulnerableAssetPreservesPackageVulnerabilityPairs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-2",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers": "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[` +
				`{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/one@1.0.0"},` +
				`{"vulnerability_id":"CVE-2026-4243","package_identifier":"pkg:golang/example/two@2.0.0"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetZipsFlatPackageVulnerabilityFields(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-flat",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-flat",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers": "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetMergesFlatPackagesIntoReferences(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-mixed",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-mixed",
			"package_identifiers":        "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242"},{"vulnerability_id":"CVE-2026-4243"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityOneURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageOneURN, relationAffectedBy, vulnerabilityOneURN)
	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
	assertProjectedLinkMissing(t, state, packageTwoURN, relationAffectedBy, vulnerabilityOneURN)
}

func TestProjectGRCVulnerableAssetAppendsTrailingFlatTuples(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-trailing",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":                   "vanta",
			"target_id":                  "target-trailing",
			"vulnerability_ids":          "CVE-2026-4242,CVE-2026-4243",
			"package_identifiers":        "pkg:golang/example/one@1.0.0,pkg:golang/example/two@2.0.0",
			"vulnerability_package_refs": `[{"vulnerability_id":"CVE-2026-4242","package_identifier":"pkg:golang/example/one@1.0.0"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageTwoURN := "urn:cerebro:writer:package:grc:pkg:golang/example/two@2.0.0"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLink(t, state, packageTwoURN, relationAffectedBy, vulnerabilityTwoURN)
}

func TestProjectGRCVulnerableAssetZipsFlatVulnerabilityNames(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-names",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "target-names",
			"vulnerability_ids":   "CVE-2026-4242,CVE-2026-4243",
			"vulnerability_names": "openssl bug,nginx bug",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-names"
	firstVulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	secondVulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"
	assertProjectedLink(t, state, targetURN, relationAffectedBy, firstVulnerabilityURN)
	assertProjectedLink(t, state, targetURN, relationAffectedBy, secondVulnerabilityURN)
	if got := state.links[targetURN+"|"+relationAffectedBy+"|"+firstVulnerabilityURN].Attributes["name"]; got != "openssl bug" {
		t.Fatalf("first vulnerability evidence name = %q, want openssl bug", got)
	}
	if got := state.links[targetURN+"|"+relationAffectedBy+"|"+secondVulnerabilityURN].Attributes["name"]; got != "nginx bug" {
		t.Fatalf("second vulnerability evidence name = %q, want nginx bug", got)
	}
}

func TestProjectGRCVulnerableAssetLinksURLOnlyHost(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-url",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":     "vanta",
			"target_id":    "asset-123",
			"external_url": "https://app.writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:asset-123"
	hostURN := "urn:cerebro:writer:internet_host:app.writer.com"
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
}

func TestProjectGRCVulnerableAssetLinksPlatformResources(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-platform",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":       "vanta",
			"target_id":      "vanta-asset-1",
			"target_name":    "ip-10-86-43-17.ec2.internal: i-0f359ce073424f8d6",
			"hostnames":      "ip-10-86-43-17.ec2.internal",
			"ip_addresses":   "10.86.43.17",
			"integration_id": "aws",
			"platform_asset_refs": `[` +
				`{"provider":"aws","resource_id":"arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6","resource_name":"ip-10-86-43-17.ec2.internal","resource_type":"SERVER","scanner_resource_id":"scanner-resource-1","hostnames":"ip-10-86-43-17.ec2.internal","ips":"10.86.43.17"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:vanta-asset-1"
	awsInstanceURN := "urn:cerebro:writer:aws_ec2_instance:arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6"
	hostURN := "urn:cerebro:writer:internet_host:ip-10-86-43-17.ec2.internal"
	ipURN := "urn:cerebro:writer:internet_ip:10.86.43.17"
	accountURN := "urn:cerebro:writer:cloud_account:381491964434"

	if entity := state.entities[awsInstanceURN]; entity == nil || entity.EntityType != "aws.ec2.instance" || entity.SourceID != "aws" {
		t.Fatalf("AWS instance entity missing: %#v", entity)
	}
	if entity := state.entities[accountURN]; entity != nil {
		t.Fatalf("GRC projection must not upsert shared AWS account entity: %#v", entity)
	}
	assertProjectedLink(t, state, targetURN, relationRepresents, awsInstanceURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, targetURN, relationRepresents, ipURN)
	assertProjectedLinkMissing(t, state, awsInstanceURN, relationBelongsTo, accountURN)
	assertProjectedLink(t, state, awsInstanceURN, relationRepresents, hostURN)
	assertProjectedLink(t, state, awsInstanceURN, relationRepresents, ipURN)

	// The platform resource gets a human-friendly label so dashboards and the
	// ask-the-graph UX surface "ip-10-86-43-17.ec2.internal" instead of the URN.
	if entity := state.entities[awsInstanceURN]; entity == nil || entity.Label == awsInstanceURN || entity.Label == "" {
		t.Fatalf("aws instance label = %q, want human-readable resource_name", entity.Label)
	}

	// Vanta-discovered platform resources must back-link to the originating
	// GRC integration so that orphan checks and source-of-truth queries can
	// traverse from github.code.repository / aws.* into the integration node.
	integrationURN := "urn:cerebro:writer:source:vanta:integration:aws"
	assertProjectedLink(t, state, awsInstanceURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerableAssetLabelsAndLinksGitHubRepoToIntegration(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-github",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "github-repo-asset",
			"integration_id":      "github",
			"platform_asset_refs": `[{"provider":"github","resource_id":"1242719606","resource_name":"Writer/cerebro","resource_type":"code_repository"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	repoURN := "urn:cerebro:writer:github_code_repository:1242719606"
	orgURN := "urn:cerebro:writer:github_org:Writer"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:github"

	repo := state.entities[repoURN]
	if repo == nil {
		t.Fatalf("github code repository entity %q missing", repoURN)
	}
	if repo.Label != "Writer/cerebro" {
		t.Fatalf("github repo label = %q, want resource_name %q", repo.Label, "Writer/cerebro")
	}
	if got := repo.Attributes["owner_login"]; got != "Writer" {
		t.Fatalf("github repo owner_login = %q, want Writer", got)
	}
	if org := state.entities[orgURN]; org == nil || org.EntityType != "github.org" {
		t.Fatalf("github org entity %q missing or wrong type: %#v", orgURN, org)
	}
	assertProjectedLink(t, state, repoURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, repoURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerableAssetDoesNotCreateGitHubAliasForNonGitHubSlashName(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-non-github-slash",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":            "vanta",
			"target_id":           "non-github-slash-asset",
			"integration_id":      "aws",
			"platform_asset_refs": `[{"provider":"aws","resource_id":"arn:aws:s3:::prod-app","resource_name":"prod/app","resource_type":"bucket"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if entity := state.entities["urn:cerebro:writer:github_code_repository:prod/app"]; entity != nil {
		t.Fatalf("non-github platform asset unexpectedly created github repo alias: %#v", entity)
	}
	if entity := state.entities["urn:cerebro:writer:github_org:prod"]; entity != nil {
		t.Fatalf("non-github platform asset unexpectedly created github org: %#v", entity)
	}
}

func TestGRCAWSResourceTypeFromARNHandlesAPIGatewayCustomDomain(t *testing.T) {
	got := grcAWSResourceTypeFromARN("arn:aws:apigateway:us-east-1::/domainnames/api.writer.com")
	if got != "apigateway_domain" {
		t.Fatalf("grcAWSResourceTypeFromARN() = %q, want apigateway_domain", got)
	}
}

func TestProjectGRCVulnerableAssetDoesNotInferVulnerabilityFromReferenceJSON(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerable-asset-3",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerable_asset",
		Attributes: map[string]string{
			"provider":  "vanta",
			"target_id": "target-3",
			"vulnerability_package_refs": `[` +
				`{"package_identifier":"pkg:golang/example/one@1.0.0"},` +
				`{"vulnerability_id":"CVE-2026-4243","package_identifier":"pkg:golang/example/two@2.0.0"}` +
				`]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	packageOneURN := "urn:cerebro:writer:package:grc:pkg:golang/example/one@1.0.0"
	vulnerabilityTwoURN := "urn:cerebro:writer:vulnerability:cve-2026-4243"

	assertProjectedLinkMissing(t, state, packageOneURN, relationAffectedBy, vulnerabilityTwoURN)
}

func TestProjectGRCVulnerabilityWritesGraphTargetIntegrationLinks(t *testing.T) {
	state := &projectionRecorder{}
	graph := &endpointCheckingGraphRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
			"target_id":        "target-1",
			"integration_id":   "integration-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	packageURN := "urn:cerebro:writer:package:grc:example/module"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-4242"
	if graph.entities[targetURN] == nil {
		t.Fatalf("graph target entity missing")
	}
	if graph.entities[integrationURN] == nil {
		t.Fatalf("graph integration entity missing")
	}
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationContains, packageURN)
	assertProjectedLink(t, &graph.projectionRecorder, targetURN, relationBelongsTo, integrationURN)
}

func TestProjectGRCVulnerabilityDoesNotRegressIntegrationLabel(t *testing.T) {
	integrationURN := "urn:cerebro:writer:source:vanta:integration:integration-1"
	targetURN := "urn:cerebro:writer:grc_target:vanta:target-1"
	entities, links, err := grcVulnerabilityProjections(&cerebrov1.EventEnvelope{
		Id:       "grc-vulnerability-vuln-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vulnerability",
		Attributes: map[string]string{
			"provider":         "vanta",
			"vulnerability_id": "vuln-1",
			"name":             "CVE-2026-4242",
			"package":          "example/module",
			"target_id":        "target-1",
			"integration_id":   "integration-1",
		},
	})
	if err != nil {
		t.Fatalf("grcVulnerabilityProjections() error = %v", err)
	}

	var integrationLabel string
	integrationFound := false
	for _, entity := range entities {
		if entity.URN == integrationURN {
			integrationFound = true
			integrationLabel = entity.Label
			break
		}
	}
	if !integrationFound {
		t.Fatalf("integration reference entity missing: %#v", entities)
	}
	if integrationLabel != "" {
		t.Fatalf("integration reference label = %q, want empty fallback-preserving label", integrationLabel)
	}
	for _, link := range links {
		if link.FromURN == targetURN && link.Relation == relationBelongsTo && link.ToURN == integrationURN {
			return
		}
	}
	t.Fatalf("target belongs_to integration link missing: %#v", links)
}

package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

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

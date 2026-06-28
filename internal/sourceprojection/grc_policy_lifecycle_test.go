package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectGRCPolicyLinksLifecycleContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy",
		Attributes: map[string]string{
			"provider":          "policyops",
			"policy_id":         "policy-1",
			"name":              "Access Control Policy",
			"owner_id":          "user-1",
			"control_ids":       "control-1",
			"document_id":       "document-1",
			"employee_group_id": "group-1",
			"evidence_cas_uri":  "evidencecas://policy/policy-1",
			"frameworks":        "SOC 2,ISO 27001",
			"status":            "approved",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	ownerURN := "urn:cerebro:writer:user:policyops:user-1"
	controlURN := "urn:cerebro:writer:policy:policyops:control:control-1"
	documentURN := "urn:cerebro:writer:document:policyops:document-1"
	groupURN := "urn:cerebro:writer:grc_group:policyops:group-1"
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidencecas_policy_policy_1"
	if entity := state.entities[policyURN]; entity == nil || entity.EntityType != "policy" {
		t.Fatalf("policy entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, policyURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, policyURN, relationSupports, controlURN)
	assertProjectedLink(t, state, policyURN, relationHasEvidence, documentURN)
	assertProjectedLink(t, state, policyURN, relationAssignedTo, groupURN)
	assertProjectedLink(t, state, policyURN, relationHasEvidence, evidenceURN)
}

func TestProjectGRCPolicyTemplateLinksLibraryContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-template-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_template",
		Attributes: map[string]string{
			"provider":    "policyops",
			"template_id": "template-access",
			"title":       "Access Control Policy Template",
			"owner_id":    "owner-1",
			"control_ids": "CC6.1,CC6.2",
			"frameworks":  "SOC 2",
			"status":      "published",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	templateURN := "urn:cerebro:writer:policy_template:policyops:template-access"
	ownerURN := "urn:cerebro:writer:user:policyops:owner-1"
	firstControlURN := "urn:cerebro:writer:policy:policyops:control:CC6.1"
	secondControlURN := "urn:cerebro:writer:policy:policyops:control:CC6.2"
	if entity := state.entities[templateURN]; entity == nil || entity.EntityType != "policy.template" {
		t.Fatalf("policy template entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, templateURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, templateURN, relationSupports, firstControlURN)
	assertProjectedLink(t, state, templateURN, relationSupports, secondControlURN)
}

func TestProjectGRCPolicyVersionLinksDocumentControlAndPolicy(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-version-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_version",
		Attributes: map[string]string{
			"provider":          "policyops",
			"policy_id":         "policy-1",
			"policy_version_id": "version-2",
			"policy_name":       "Access Control Policy",
			"version":           "2",
			"status":            "pending_approval",
			"control_ids":       "control-1",
			"document_id":       "document-2",
			"author_user_id":    "author-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	versionURN := "urn:cerebro:writer:policy_version:policyops:version-2"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	controlURN := "urn:cerebro:writer:policy:policyops:control:control-1"
	documentURN := "urn:cerebro:writer:document:policyops:document-2"
	authorURN := "urn:cerebro:writer:user:policyops:author-1"
	if entity := state.entities[versionURN]; entity == nil || entity.EntityType != "policy.version" {
		t.Fatalf("policy version entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, versionURN, relationBelongsTo, policyURN)
	assertProjectedLink(t, state, versionURN, relationSupports, controlURN)
	assertProjectedLink(t, state, versionURN, relationHasEvidence, documentURN)
	assertProjectedLink(t, state, authorURN, relationActedOn, versionURN)
}

func TestProjectGRCPolicyApprovalLinksApproversAndVersion(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-approval-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_approval",
		Attributes: map[string]string{
			"provider":             "policyops",
			"approval_id":          "approval-1",
			"policy_id":            "policy-1",
			"policy_version_id":    "version-2",
			"approver_user_ids":    "approver-1,approver-2",
			"requested_by_user_id": "author-1",
			"status":               "approved",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	approvalURN := "urn:cerebro:writer:policy_approval:policyops:approval-1"
	versionURN := "urn:cerebro:writer:policy_version:policyops:version-2"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	firstApproverURN := "urn:cerebro:writer:user:policyops:approver-1"
	secondApproverURN := "urn:cerebro:writer:user:policyops:approver-2"
	requesterURN := "urn:cerebro:writer:user:policyops:author-1"
	lifecycleEventURN := "urn:cerebro:writer:policy_lifecycle_event:policyops:grc-policy-approval-1"
	if entity := state.entities[lifecycleEventURN]; entity == nil || entity.EntityType != "policy.lifecycle.event" {
		t.Fatalf("policy lifecycle event missing: %#v", entity)
	}
	assertProjectedLink(t, state, approvalURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, approvalURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, approvalURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, firstApproverURN, relationActedOn, approvalURN)
	assertProjectedLink(t, state, secondApproverURN, relationActedOn, approvalURN)
	assertProjectedLink(t, state, requesterURN, relationActedOn, approvalURN)
	if got := state.links[firstApproverURN+"|"+relationActedOn+"|"+approvalURN].Attributes["action"]; got != "approved" {
		t.Fatalf("approver action = %q, want approved", got)
	}
}

func TestProjectGRCPolicyLifecycleEventPreservesGovernanceGapState(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "gap-event-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_lifecycle_event",
		Attributes: map[string]string{
			"provider":           "policyops",
			"source_event_id":    "gap-event-1",
			"record_type":        "governance.gap",
			"record_urn":         "urn:document:secure-development:gap:owner",
			"gap_id":             "urn:document:secure-development:gap:owner",
			"gap_state":          "acknowledged",
			"action":             "governance_gap.acknowledge",
			"status":             "acknowledged",
			"actor_user_id":      "operator-1",
			"reason":             "Owner tracked in source",
			"policy_id":          "secure-development",
			"document_id":        "secure-development-doc",
			"risk_id":            "privileged-access",
			"control_ids":        "CC6.1",
			"evidence_cas_uri":   "evidencecas://policy/gap-owner",
			"state_updated_at":   "2026-02-02T12:00:00Z",
			"source_document_id": "secure-development-doc",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	lifecycleEventURN := "urn:cerebro:writer:policy_lifecycle_event:policyops:gap-event-1"
	gapURN := "urn:document:secure-development:gap:owner"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:secure-development"
	operatorURN := "urn:cerebro:writer:user:policyops:operator-1"
	if entity := state.entities[lifecycleEventURN]; entity == nil || entity.EntityType != "policy.lifecycle.event" || entity.Attributes["gap_state"] != "acknowledged" || entity.Attributes["gap_id"] != gapURN {
		t.Fatalf("lifecycle event entity = %#v, want gap state attributes", entity)
	}
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, gapURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, operatorURN, relationActedOn, lifecycleEventURN)
}

func TestProjectGRCPolicyLifecycleEventLinksBulkGapIDs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "gap-event-bulk",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_lifecycle_event",
		Attributes: map[string]string{
			"provider":        "policyops",
			"source_event_id": "gap-event-bulk",
			"record_id":       "bulk-assign-owner",
			"record_type":     "governance.gap",
			"gap_ids":         "urn:document:secure-development:gap:owner,urn:document:secure-development:gap:controls",
			"action":          "governance_gap.assign_owner",
			"status":          "in_progress",
			"actor_user_id":   "operator-1",
			"policy_id":       "secure-development",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	lifecycleEventURN := "urn:cerebro:writer:policy_lifecycle_event:policyops:gap-event-bulk"
	firstGapURN := "urn:document:secure-development:gap:owner"
	secondGapURN := "urn:document:secure-development:gap:controls"
	syntheticURN := "urn:cerebro:writer:policy_lifecycle_subject:policyops:bulk-assign-owner"
	eventEntity := state.entities[lifecycleEventURN]
	if eventEntity == nil || eventEntity.Attributes["record_id"] != "bulk-assign-owner" || eventEntity.Attributes["record_urn"] != firstGapURN || eventEntity.Attributes["gap_ids"] == "" {
		t.Fatalf("lifecycle event entity = %#v, want bulk record id and gap targets", eventEntity)
	}
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, firstGapURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, secondGapURN)
	assertProjectedLinkMissing(t, state, lifecycleEventURN, relationAssociatedWith, syntheticURN)
}

func TestProjectGRCPolicyLifecycleEventLinksTargetPolicy(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "gap-event-link-policy",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_lifecycle_event",
		Attributes: map[string]string{
			"provider":           "policyops",
			"source_event_id":    "gap-event-link-policy",
			"record_type":        "governance.gap",
			"record_urn":         "urn:document:secure-development:gap:linked-policy",
			"gap_id":             "urn:document:secure-development:gap:linked-policy",
			"action":             "governance_gap.link_policy",
			"status":             "in_progress",
			"policy_id":          "context-policy",
			"policy_name":        "Context policy",
			"target_policy_id":   "linked-policy",
			"target_policy_name": "Linked policy",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	lifecycleEventURN := "urn:cerebro:writer:policy_lifecycle_event:policyops:gap-event-link-policy"
	gapURN := "urn:document:secure-development:gap:linked-policy"
	contextPolicyURN := "urn:cerebro:writer:policy:policyops:policy:context-policy"
	targetPolicyURN := "urn:cerebro:writer:policy:policyops:policy:linked-policy"
	eventEntity := state.entities[lifecycleEventURN]
	if eventEntity == nil || eventEntity.Attributes["policy_id"] != "context-policy" || eventEntity.Attributes["target_policy_id"] != "linked-policy" {
		t.Fatalf("lifecycle event entity = %#v, want separate context and target policy attrs", eventEntity)
	}
	if targetPolicy := state.entities[targetPolicyURN]; targetPolicy == nil || targetPolicy.Label != "Linked policy" {
		t.Fatalf("target policy entity = %#v, want linked policy label", targetPolicy)
	}
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, gapURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, contextPolicyURN)
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, targetPolicyURN)
	link := state.links[lifecycleEventURN+"|"+relationAssociatedWith+"|"+targetPolicyURN]
	if link.Attributes["match_type"] != "grc_target_policy_reference" || link.Attributes["target_policy_id"] != "linked-policy" {
		t.Fatalf("target policy link attrs = %#v, want target policy reference", link.Attributes)
	}
}

func TestProjectGRCPolicyLifecycleEventLinksTargetPolicyWithoutContextPolicy(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "gap-event-target-only",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_lifecycle_event",
		Attributes: map[string]string{
			"provider":           "policyops",
			"source_event_id":    "gap-event-target-only",
			"record_type":        "governance.gap",
			"record_urn":         "urn:risk:privileged-access:gap:policy",
			"gap_id":             "urn:risk:privileged-access:gap:policy",
			"action":             "governance_gap.link_policy",
			"status":             "in_progress",
			"target_policy_id":   "linked-policy",
			"target_policy_name": "Linked policy",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	lifecycleEventURN := "urn:cerebro:writer:policy_lifecycle_event:policyops:gap-event-target-only"
	targetPolicyURN := "urn:cerebro:writer:policy:policyops:policy:linked-policy"
	eventEntity := state.entities[lifecycleEventURN]
	if eventEntity == nil || eventEntity.Attributes["policy_id"] != "" || eventEntity.Attributes["target_policy_id"] != "linked-policy" {
		t.Fatalf("lifecycle event entity = %#v, want target policy without context policy", eventEntity)
	}
	assertProjectedLink(t, state, lifecycleEventURN, relationAssociatedWith, targetPolicyURN)
}

func TestProjectGRCPolicyAcceptanceLinksEmployeeAndAssignment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-acceptance-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_acceptance",
		Attributes: map[string]string{
			"provider":          "policyops",
			"acceptance_id":     "acceptance-1",
			"policy_id":         "policy-1",
			"policy_version_id": "version-2",
			"person_id":         "person-1",
			"user_id":           "user-1",
			"email":             "ada@example.com",
			"group_id":          "group-1",
			"status":            "accepted",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	acceptanceURN := "urn:cerebro:writer:policy_acceptance:policyops:acceptance-1"
	versionURN := "urn:cerebro:writer:policy_version:policyops:version-2"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	personURN := "urn:cerebro:writer:person:policyops:person-1"
	userURN := "urn:cerebro:writer:user:policyops:user-1"
	groupURN := "urn:cerebro:writer:grc_group:policyops:group-1"
	emailURN := "urn:cerebro:writer:identity:email:ada@example.com"
	assertProjectedLink(t, state, acceptanceURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, acceptanceURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, personURN, relationHasEvidence, acceptanceURN)
	assertProjectedLink(t, state, userURN, relationHasEvidence, acceptanceURN)
	assertProjectedLink(t, state, acceptanceURN, relationAssignedTo, groupURN)
	assertProjectedLink(t, state, acceptanceURN, relationAssociatedWith, emailURN)
}

func TestProjectGRCPolicyReminderLinksRecipientsAndEscalation(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-reminder-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_reminder",
		Attributes: map[string]string{
			"provider":              "policyops",
			"reminder_id":           "reminder-1",
			"policy_id":             "policy-1",
			"policy_version_id":     "version-2",
			"employee_group_id":     "group-1",
			"sent_by_user_id":       "owner-1",
			"escalated_to_user_ids": "manager-1,manager-2",
			"status":                "sent",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	reminderURN := "urn:cerebro:writer:policy_reminder:policyops:reminder-1"
	versionURN := "urn:cerebro:writer:policy_version:policyops:version-2"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	groupURN := "urn:cerebro:writer:grc_group:policyops:group-1"
	senderURN := "urn:cerebro:writer:user:policyops:owner-1"
	firstManagerURN := "urn:cerebro:writer:user:policyops:manager-1"
	secondManagerURN := "urn:cerebro:writer:user:policyops:manager-2"
	if entity := state.entities[reminderURN]; entity == nil || entity.EntityType != "policy.reminder" {
		t.Fatalf("policy reminder entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, reminderURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, reminderURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, reminderURN, relationAssignedTo, groupURN)
	assertProjectedLink(t, state, senderURN, relationActedOn, reminderURN)
	assertProjectedLink(t, state, firstManagerURN, relationActedOn, reminderURN)
	assertProjectedLink(t, state, secondManagerURN, relationActedOn, reminderURN)
	if got := state.links[firstManagerURN+"|"+relationActedOn+"|"+reminderURN].Attributes["action"]; got != "escalated" {
		t.Fatalf("manager action = %q, want escalated", got)
	}
}

func TestProjectGRCPolicyReviewAndException(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-review-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_review",
		Attributes: map[string]string{
			"provider":          "policyops",
			"review_id":         "review-1",
			"policy_id":         "policy-1",
			"policy_version_id": "version-2",
			"reviewer_user_id":  "reviewer-1",
			"review_cadence":    "annual",
			"status":            "complete",
		},
	})
	if err != nil {
		t.Fatalf("Project() review error = %v", err)
	}
	_, err = service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-exception-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_exception",
		Attributes: map[string]string{
			"provider":          "policyops",
			"exception_id":      "exception-1",
			"policy_id":         "policy-1",
			"policy_version_id": "version-2",
			"control_ids":       "control-1",
			"owner_id":          "risk-owner-1",
			"approver_user_id":  "approver-1",
			"target_id":         "asset-1",
			"status":            "active",
		},
	})
	if err != nil {
		t.Fatalf("Project() exception error = %v", err)
	}
	_, err = service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "grc-policy-exception-2",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.policy_exception",
		Attributes: map[string]string{
			"provider":          "policyops",
			"exception_id":      "exception-2",
			"policy_id":         "policy-1",
			"policy_version_id": "version-2",
			"person_id":         "person-1",
			"user_id":           "user-2",
			"status":            "active",
		},
	})
	if err != nil {
		t.Fatalf("Project() identity exception error = %v", err)
	}

	reviewURN := "urn:cerebro:writer:policy_review:policyops:review-1"
	exceptionURN := "urn:cerebro:writer:policy_exception:policyops:exception-1"
	identityExceptionURN := "urn:cerebro:writer:policy_exception:policyops:exception-2"
	versionURN := "urn:cerebro:writer:policy_version:policyops:version-2"
	policyURN := "urn:cerebro:writer:policy:policyops:policy:policy-1"
	reviewerURN := "urn:cerebro:writer:user:policyops:reviewer-1"
	controlURN := "urn:cerebro:writer:policy:policyops:control:control-1"
	ownerURN := "urn:cerebro:writer:user:policyops:risk-owner-1"
	approverURN := "urn:cerebro:writer:user:policyops:approver-1"
	targetURN := "urn:cerebro:writer:grc_target:policyops:asset-1"
	personTargetURN := "urn:cerebro:writer:person:policyops:person-1"
	userTargetURN := "urn:cerebro:writer:user:policyops:user-2"
	assertProjectedLink(t, state, reviewURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, reviewURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, reviewerURN, relationActedOn, reviewURN)
	assertProjectedLink(t, state, exceptionURN, relationAssociatedWith, versionURN)
	assertProjectedLink(t, state, exceptionURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, exceptionURN, relationAssociatedWith, controlURN)
	assertProjectedLink(t, state, exceptionURN, relationOwnedBy, ownerURN)
	assertProjectedLink(t, state, approverURN, relationActedOn, exceptionURN)
	assertProjectedLink(t, state, exceptionURN, relationTargeted, targetURN)
	assertProjectedLink(t, state, identityExceptionURN, relationAssociatedWith, policyURN)
	assertProjectedLink(t, state, identityExceptionURN, relationTargeted, personTargetURN)
	assertProjectedLink(t, state, identityExceptionURN, relationTargeted, userTargetURN)
}

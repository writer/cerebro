package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcPolicyTemplateProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	templateID := firstAttribute(ctx.attrs, "template_id", "policy_template_id", "external_id")
	if templateID == "" {
		return nil, nil, nil
	}
	templateURN := ctx.resourceURN("policy_template", templateID)
	ctx.addResourceEntity(
		templateURN,
		"policy.template",
		firstAttribute(ctx.attrs, "title", "name", "policy_name", "template_id", "policy_template_id"),
		map[string]string{
			"source_system": ctx.provider,
			"status":        firstAttribute(ctx.attrs, "status", "template_status", "lifecycle_state"),
			"template_id":   templateID,
		},
	)
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "policy_owner_user_id"))
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, ctx.provider)
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, "policy_template_framework", firstAttribute(ctx.attrs, "frameworks", "framework"))
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, templateURN, "policy_template_category", firstAttribute(ctx.attrs, "category", "policy_category"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyVersionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id", "external_id")
	if versionID == "" {
		versionID = grcDerivedID(policyID, firstAttribute(ctx.attrs, "version", "version_number"), firstAttribute(ctx.attrs, "approved_at", "created_at", "effective_at"))
	}
	if versionID == "" {
		return nil, nil, nil
	}
	versionURN := ctx.resourceURN("policy_version", versionID)
	ctx.addResourceEntity(
		versionURN,
		"policy.version",
		firstAttribute(ctx.attrs, "title", "name", "policy_name", "version", "policy_version_id", "version_id"),
		map[string]string{
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "policy_status", "lifecycle_state"),
			"version":           firstAttribute(ctx.attrs, "version", "version_number"),
		},
	)
	if policyURN := addGRCPolicyReference(ctx, policyID); policyURN != "" {
		ctx.addEventLink(versionURN, policyURN, relationBelongsTo)
	}
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, versionURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "policy_owner_user_id"))
	addGRCPolicyDocumentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, versionURN, ctx.provider, ctx.attrs)
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, versionURN, ctx.provider)
	addGRCPolicyAssignmentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, versionURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, versionURN, ctx.provider, ctx.attrs)
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "author_user_id", "created_by_user_id"), versionURN, "authored")
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyApprovalProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id")
	approvalID := firstAttribute(ctx.attrs, "approval_id", "policy_approval_id", "external_id")
	if approvalID == "" {
		approvalID = grcDerivedID(policyID, versionID, firstAttribute(ctx.attrs, "approval_step", "step"), firstAttribute(ctx.attrs, "approver_user_id", "approved_by_user_id"), firstAttribute(ctx.attrs, "approved_at", "reviewed_at", "requested_at"))
	}
	if approvalID == "" {
		return nil, nil, nil
	}
	approvalURN := ctx.resourceURN("policy_approval", approvalID)
	ctx.addResourceEntity(
		approvalURN,
		"policy.approval",
		firstAttribute(ctx.attrs, "title", "name", "policy_name", "approval_id", "policy_approval_id"),
		map[string]string{
			"approval_id":       approvalID,
			"approval_step":     firstAttribute(ctx.attrs, "approval_step", "step"),
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "approval_status"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, approvalURN, policyID, versionID)
	addGRCPolicyUserActionLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, approvalURN, firstAttribute(ctx.attrs, "approver_user_id", "approver_user_ids", "approved_by_user_id", "reviewer_user_id", "reviewer_user_ids"), grcPolicyApprovalAction(ctx.attrs))
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "requested_by_user_id"), approvalURN, "requested_approval")
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, approvalURN, ctx.provider, ctx.attrs)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyAcceptanceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id")
	acceptanceID := firstAttribute(ctx.attrs, "acceptance_id", "policy_acceptance_id", "attestation_id", "external_id")
	if acceptanceID == "" {
		acceptanceID = grcDerivedID(firstAttribute(ctx.attrs, "person_id", "user_id", "email"), policyID, versionID, firstAttribute(ctx.attrs, "accepted_at", "completed_at"))
	}
	if acceptanceID == "" {
		return nil, nil, nil
	}
	acceptanceURN := ctx.resourceURN("policy_acceptance", acceptanceID)
	ctx.addResourceEntity(
		acceptanceURN,
		"policy.acceptance",
		firstAttribute(ctx.attrs, "title", "policy_name", "person_name", "email", "acceptance_id", "policy_acceptance_id"),
		map[string]string{
			"acceptance_id":     acceptanceID,
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "acceptance_status"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, acceptanceURN, policyID, versionID)
	addGRCPolicyPersonEvidenceLinks(ctx, acceptanceURN)
	addGRCPolicyAssignmentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, acceptanceURN, ctx.provider, ctx.attrs)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, acceptanceURN, ctx.provider, ctx.attrs)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyReviewProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id")
	reviewID := firstAttribute(ctx.attrs, "review_id", "policy_review_id", "external_id")
	if reviewID == "" {
		reviewID = grcDerivedID(policyID, versionID, firstAttribute(ctx.attrs, "review_due_at", "due_at"), firstAttribute(ctx.attrs, "reviewed_at", "completed_at"))
	}
	if reviewID == "" {
		return nil, nil, nil
	}
	reviewURN := ctx.resourceURN("policy_review", reviewID)
	ctx.addResourceEntity(
		reviewURN,
		"policy.review",
		firstAttribute(ctx.attrs, "title", "policy_name", "review_id", "policy_review_id"),
		map[string]string{
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"review_cadence":    firstAttribute(ctx.attrs, "review_cadence", "cadence"),
			"review_id":         reviewID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "review_status"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, reviewURN, policyID, versionID)
	addGRCPolicyUserActionLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, reviewURN, firstAttribute(ctx.attrs, "reviewer_user_id", "reviewer_user_ids", "reviewed_by_user_id"), "reviewed")
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reviewURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "policy_owner_user_id"))
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reviewURN, ctx.provider, ctx.attrs)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyReminderProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id")
	reminderID := firstAttribute(ctx.attrs, "reminder_id", "policy_reminder_id", "escalation_id", "external_id")
	if reminderID == "" {
		reminderID = grcDerivedID(policyID, versionID, firstAttribute(ctx.attrs, "target_id", "person_id", "user_id", "email", "group_id"), firstAttribute(ctx.attrs, "due_at", "sent_at", "scheduled_at"))
	}
	if reminderID == "" {
		return nil, nil, nil
	}
	reminderURN := ctx.resourceURN("policy_reminder", reminderID)
	ctx.addResourceEntity(
		reminderURN,
		"policy.reminder",
		firstAttribute(ctx.attrs, "title", "policy_name", "reminder_id", "policy_reminder_id", "escalation_id"),
		map[string]string{
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"reminder_id":       reminderID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "reminder_status", "escalation_status"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, reminderURN, policyID, versionID)
	addGRCPolicyAssignmentLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reminderURN, ctx.provider, ctx.attrs)
	addGRCUserActionLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, firstAttribute(ctx.attrs, "sent_by_user_id", "created_by_user_id"), reminderURN, "sent_reminder")
	addGRCPolicyUserActionLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, reminderURN, firstAttribute(ctx.attrs, "escalated_to_user_id", "escalated_to_user_ids"), "escalated")
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, reminderURN, ctx.provider, ctx.attrs)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyExceptionProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	policyID := firstAttribute(ctx.attrs, "policy_id")
	versionID := firstAttribute(ctx.attrs, "policy_version_id", "version_id")
	exceptionID := firstAttribute(ctx.attrs, "exception_id", "waiver_id", "policy_exception_id", "external_id")
	if exceptionID == "" {
		exceptionID = grcDerivedID(policyID, versionID, firstAttribute(ctx.attrs, "target_id", "resource_id", "asset_id", "user_id", "person_id"), firstAttribute(ctx.attrs, "expires_at", "expiration_at"))
	}
	if exceptionID == "" {
		return nil, nil, nil
	}
	exceptionURN := ctx.resourceURN("policy_exception", exceptionID)
	ctx.addResourceEntity(
		exceptionURN,
		"policy.exception",
		firstAttribute(ctx.attrs, "title", "summary", "policy_name", "exception_id", "waiver_id", "policy_exception_id"),
		map[string]string{
			"exception_id":      exceptionID,
			"policy_id":         policyID,
			"policy_version_id": versionID,
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "exception_status", "waiver_status"),
		},
	)
	addGRCPolicyLifecycleSubjectLinks(ctx, exceptionURN, policyID, versionID)
	addGRCControlAssociationLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, exceptionURN, ctx.provider, relationAssociatedWith, "grc_policy_exception")
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, exceptionURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "risk_owner_user_id"))
	addGRCPolicyUserActionLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, ctx.provider, exceptionURN, firstAttribute(ctx.attrs, "approver_user_id", "approved_by_user_id"), "approved_exception")
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, exceptionURN, ctx.provider, ctx.attrs, relationTargeted, "grc_policy_exception")
	addGRCPolicyExceptionIdentityTargetLinks(ctx, exceptionURN)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, exceptionURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, exceptionURN, "policy_exception_status", firstAttribute(ctx.attrs, "status", "exception_status", "waiver_status"))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPolicyURN(tenantID string, provider string, policyID string) string {
	return projectionURN(tenantID, "policy", provider, "policy", policyID)
}

func addGRCPolicyReference(ctx *grcProjectionContext, policyID string) string {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return ""
	}
	policyURN := grcPolicyURN(ctx.tenantID, ctx.provider, policyID)
	ctx.addReferenceEntity(
		policyURN,
		"policy",
		firstAttribute(ctx.attrs, "policy_name", "name", "title", "policy_id"),
		map[string]string{"policy_id": policyID, "policy_type": "policy", "source_system": ctx.provider},
	)
	return policyURN
}

func addGRCPolicyLifecycleSubjectLinks(ctx *grcProjectionContext, fromURN string, policyID string, versionID string) {
	if versionID != "" {
		versionURN := ctx.resourceURN("policy_version", versionID)
		ctx.addReferenceEntity(
			versionURN,
			"policy.version",
			firstAttribute(ctx.attrs, "policy_name", "title", "name", "version", "policy_version_id", "version_id"),
			map[string]string{"policy_id": policyID, "policy_version_id": versionID, "source_system": ctx.provider},
		)
		ctx.addEventLink(fromURN, versionURN, relationAssociatedWith)
	}
	if policyURN := addGRCPolicyReference(ctx, policyID); policyURN != "" {
		ctx.addEventLink(fromURN, policyURN, relationAssociatedWith)
	}
}

func addGRCPolicyDocumentLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string) {
	if fromURN == "" {
		return
	}
	rawDocumentIDs := strings.Join([]string{
		attrs["document_id"],
		attrs["document_ids"],
		attrs["approved_document_id"],
		attrs["approved_document_ids"],
		attrs["file_id"],
	}, ",")
	for _, documentID := range grcAttributeSequence(rawDocumentIDs) {
		documentURN := projectionURN(tenantID, "document", provider, documentID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        documentURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "document",
			Label:      firstAttribute(attrs, "document_title", "file_name", "title", "policy_name", "name", "document_id"),
			Attributes: grcAttributes(nil, map[string]string{
				"document_id":   documentID,
				"document_type": firstAttribute(attrs, "document_type", "file_type"),
				"source_system": provider,
			}),
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, documentURN, relationHasEvidence, map[string]string{
			"document_id": documentID,
			"event_id":    event.GetId(),
			"match_type":  "grc_policy_document",
		}))
	}
	addInternetHostLink(entities, links, tenantID, sourceID, event, fromURN, relationHasIdentifier, firstAttribute(attrs, "url", "document_url", "file_url", "download_url"), "grc_policy_document_url_host", "0.90")
}

func addGRCPolicyAssignmentLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, attrs map[string]string) {
	if fromURN == "" {
		return
	}
	rawGroupIDs := strings.Join([]string{attrs["group_id"], attrs["group_ids"], attrs["employee_group_id"], attrs["employee_group_ids"], attrs["acceptance_group_id"], attrs["acceptance_group_ids"]}, ",")
	for _, groupID := range grcAttributeSequence(rawGroupIDs) {
		groupURN := projectionURN(tenantID, "grc_group", provider, groupID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        groupURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "group",
			Label:      firstAttribute(attrs, "group_name", "employee_group_name", "acceptance_group_name", "name"),
			Attributes: grcAttributes(nil, map[string]string{"group_id": groupID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, groupURN, relationAssignedTo, map[string]string{
			"event_id":   event.GetId(),
			"group_id":   groupID,
			"match_type": "grc_policy_assignment_group",
		}))
	}
	rawUserIDs := strings.Join([]string{attrs["assigned_user_id"], attrs["assigned_user_ids"], attrs["employee_user_id"], attrs["employee_user_ids"]}, ",")
	for _, userID := range grcAttributeSequence(rawUserIDs) {
		userURN := grcUserURN(tenantID, provider, userID)
		addEntity(entities, grcUserEntity(tenantID, sourceID, userURN, userID, map[string]string{"source_system": provider, "user_id": userID}))
		addLink(links, projectedLink(tenantID, sourceID, fromURN, userURN, relationAssignedTo, map[string]string{
			"event_id":   event.GetId(),
			"match_type": "grc_policy_assignment_user",
			"user_id":    userID,
		}))
	}
}

func addGRCPolicyPersonEvidenceLinks(ctx *grcProjectionContext, acceptanceURN string) {
	if personID := firstAttribute(ctx.attrs, "person_id"); personID != "" {
		personURN := ctx.resourceURN("person", personID)
		ctx.addReferenceEntity(
			personURN,
			"person",
			firstAttribute(ctx.attrs, "person_name", "email", "person_id"),
			map[string]string{"person_id": personID, "source_system": ctx.provider},
		)
		ctx.addEventLink(personURN, acceptanceURN, relationHasEvidence)
		ctx.addEventLink(acceptanceURN, personURN, relationObservedOn)
	}
	if userID := firstAttribute(ctx.attrs, "user_id"); userID != "" {
		userURN := grcUserURN(ctx.tenantID, ctx.provider, userID)
		addEntity(ctx.entities, grcUserEntity(ctx.tenantID, ctx.sourceID, userURN, firstAttribute(ctx.attrs, "display_name", "email", "user_id"), grcAttributes(nil, map[string]string{"user_id": userID, "source_system": ctx.provider})))
		ctx.addEventLink(userURN, acceptanceURN, relationHasEvidence)
		ctx.addEventLink(acceptanceURN, userURN, relationObservedOn)
	}
	addSecurityContactEmailLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, acceptanceURN, firstAttribute(ctx.attrs, "email", "person_email", "user_email"), "policy_acceptance")
}

func addGRCPolicyExceptionIdentityTargetLinks(ctx *grcProjectionContext, exceptionURN string) {
	if exceptionURN == "" {
		return
	}
	if personID := firstAttribute(ctx.attrs, "person_id"); personID != "" {
		personURN := ctx.resourceURN("person", personID)
		ctx.addReferenceEntity(
			personURN,
			"person",
			firstAttribute(ctx.attrs, "person_name", "email", "person_id"),
			map[string]string{"person_id": personID, "source_system": ctx.provider},
		)
		addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, exceptionURN, personURN, relationTargeted, map[string]string{
			"event_id":         ctx.event.GetId(),
			"person_id":        personID,
			"relationship":     relationTargeted,
			"relationship_by":  "grc_policy_exception",
			"source_reference": "grc_person",
			"target_id":        personID,
		}))
	}
	if userID := firstAttribute(ctx.attrs, "user_id"); userID != "" {
		userURN := grcUserURN(ctx.tenantID, ctx.provider, userID)
		addEntity(ctx.entities, grcUserEntity(ctx.tenantID, ctx.sourceID, userURN, firstAttribute(ctx.attrs, "display_name", "email", "user_id"), grcAttributes(nil, map[string]string{"user_id": userID, "source_system": ctx.provider})))
		addLink(ctx.links, projectedLink(ctx.tenantID, ctx.sourceID, exceptionURN, userURN, relationTargeted, map[string]string{
			"event_id":         ctx.event.GetId(),
			"relationship":     relationTargeted,
			"relationship_by":  "grc_policy_exception",
			"source_reference": "grc_user",
			"target_id":        userID,
			"user_id":          userID,
		}))
	}
}

func addGRCPolicyUserActionLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, provider string, toURN string, rawUserIDs string, action string) {
	for _, userID := range grcAttributeSequence(rawUserIDs) {
		addGRCUserActionLink(entities, links, tenantID, sourceID, event, provider, userID, toURN, action)
	}
}

func grcPolicyApprovalAction(attrs map[string]string) string {
	status := normalizeIdentifier(firstAttribute(attrs, "status", "approval_status"))
	switch status {
	case "approved":
		return "approved"
	case "rejected", "declined":
		return "rejected"
	case "cancelled", "canceled":
		return "canceled_approval"
	default:
		return "reviewed"
	}
}

func addGRCControlAssociationLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, event *cerebrov1.EventEnvelope, fromURN string, provider string, relation string, relationshipBy string) {
	if fromURN == "" {
		return
	}
	for _, controlRef := range grcControlReferences(event.GetAttributes()) {
		controlURN := projectionURN(tenantID, "policy", provider, "control", controlRef.id)
		if controlURN == "" {
			continue
		}
		if controlRef.externalID != "" || !controlRef.paired {
			controlAttrs := map[string]string{"control_id": controlRef.id, "policy_id": controlRef.id, "policy_type": "control", "source_system": provider}
			if controlRef.externalID != "" {
				controlAttrs["control_external_id"] = controlRef.externalID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        controlURN,
				TenantID:   tenantID,
				SourceID:   sourceID,
				EntityType: "policy",
				Label:      firstNonEmpty(controlRef.externalID, controlRef.id),
				Attributes: controlAttrs,
			})
		}
		addLink(links, projectedLink(tenantID, sourceID, fromURN, controlURN, relation, map[string]string{
			"event_id":         event.GetId(),
			"relationship":     relation,
			"relationship_by":  relationshipBy,
			"source_reference": "grc_control",
		}))
	}
}

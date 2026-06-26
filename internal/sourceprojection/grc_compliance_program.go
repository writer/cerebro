package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	groupID := firstAttribute(ctx.attrs, "group_id", "external_id")
	if groupID == "" {
		return nil, nil, nil
	}
	ctx.addResourceEntity(
		ctx.resourceURN("grc_group", groupID),
		"group",
		firstAttribute(ctx.attrs, "group_name", "name", "group_id"),
		map[string]string{
			"group_id":      groupID,
			"group_name":    firstAttribute(ctx.attrs, "group_name", "name"),
			"source_system": ctx.provider,
		},
	)
	entities, links := ctx.done()
	return entities, links, nil
}

func grcRegulatoryNotificationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	notificationID := firstAttribute(ctx.attrs, "notification_id", "external_id")
	if notificationID == "" {
		notificationID = grcDerivedID(firstAttribute(ctx.attrs, "framework"), firstAttribute(ctx.attrs, "incident_id", "case_id"), firstAttribute(ctx.attrs, "notification_type", "report_type"))
	}
	if notificationID == "" {
		return nil, nil, nil
	}
	notificationURN := ctx.resourceURN("regulatory_notification", notificationID)
	ctx.addResourceEntity(
		notificationURN,
		"regulatory.notification",
		firstAttribute(ctx.attrs, "title", "notification_type", "report_type", "notification_id"),
		map[string]string{
			"incident_id":       firstAttribute(ctx.attrs, "incident_id", "case_id"),
			"notification_id":   notificationID,
			"notification_type": firstAttribute(ctx.attrs, "notification_type", "report_type"),
			"source_system":     ctx.provider,
			"status":            firstAttribute(ctx.attrs, "status", "notification_status"),
		},
	)
	if incidentID := firstAttribute(ctx.attrs, "incident_id", "case_id"); incidentID != "" {
		incidentURN := ctx.resourceURN("incident", incidentID)
		ctx.addReferenceEntity(
			incidentURN,
			"incident",
			firstAttribute(ctx.attrs, "incident_title", "incident_name", "incident_id", "case_id"),
			map[string]string{"incident_id": incidentID, "source_system": ctx.provider},
		)
		ctx.addEventLink(notificationURN, incidentURN, relationObservedOn)
	}
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, notificationURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id"))
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, notificationURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, notificationURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, notificationURN, "regulatory_notification", strings.Join([]string{ctx.attrs["framework"], ctx.attrs["regulator"], ctx.attrs["notification_type"], ctx.attrs["report_type"]}, ","))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcRecoveryObjectiveProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	objectiveID := firstAttribute(ctx.attrs, "recovery_objective_id", "objective_id", "bia_id", "external_id")
	if objectiveID == "" {
		objectiveID = grcDerivedID(firstAttribute(ctx.attrs, "service_id", "target_id", "resource_id", "asset_id"), firstAttribute(ctx.attrs, "business_process"), firstAttribute(ctx.attrs, "rto_minutes"), firstAttribute(ctx.attrs, "rpo_minutes"))
	}
	if objectiveID == "" {
		return nil, nil, nil
	}
	objectiveURN := ctx.resourceURN("resilience_recovery_objective", objectiveID)
	ctx.addResourceEntity(
		objectiveURN,
		"resilience.recovery_objective",
		firstAttribute(ctx.attrs, "name", "business_process", "service_id", "objective_id", "recovery_objective_id"),
		map[string]string{
			"recovery_objective_id": objectiveID,
			"source_system":         ctx.provider,
			"status":                firstAttribute(ctx.attrs, "status"),
		},
	)
	if processName := firstAttribute(ctx.attrs, "business_process", "process_name"); processName != "" {
		processURN := ctx.resourceURN("business_process", grcDerivedID(processName))
		ctx.addReferenceEntity(
			processURN,
			"business.process",
			processName,
			map[string]string{"business_process": processName, "source_system": ctx.provider},
		)
		ctx.addEventLink(objectiveURN, processURN, relationSupports)
	}
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, objectiveURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id"))
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, objectiveURN, ctx.provider, ctx.attrs, relationTargeted, "grc_recovery_objective")
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, objectiveURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, objectiveURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, objectiveURN, "resilience_tier", strings.Join([]string{ctx.attrs["impact_tier"], ctx.attrs["criticality"], ctx.attrs["recovery_priority"]}, ","))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcAuthorizationPackageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	packageID := firstAttribute(ctx.attrs, "authorization_package_id", "package_id", "ato_id", "ssp_id", "external_id")
	if packageID == "" {
		return nil, nil, nil
	}
	packageURN := ctx.resourceURN("authorization_package", packageID)
	ctx.addResourceEntity(
		packageURN,
		"authorization.package",
		firstAttribute(ctx.attrs, "name", "system_name", "package_name", "package_id", "authorization_package_id"),
		map[string]string{
			"authorization_package_id": packageID,
			"framework":                firstAttribute(ctx.attrs, "framework"),
			"impact_level":             firstAttribute(ctx.attrs, "impact_level"),
			"source_system":            ctx.provider,
			"status":                   firstAttribute(ctx.attrs, "status", "authorization_status"),
		},
	)
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, packageURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id", "system_owner_user_id"))
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, packageURN, ctx.provider, ctx.attrs, relationTargeted, "grc_authorization_package")
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, packageURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, packageURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, packageURN, "authorization_package", strings.Join([]string{ctx.attrs["framework"], ctx.attrs["impact_level"], ctx.attrs["status"], ctx.attrs["authorization_status"]}, ","))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcPOAMItemProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	itemID := firstAttribute(ctx.attrs, "poam_item_id", "weakness_id", "finding_id", "external_id")
	if itemID == "" {
		return nil, nil, nil
	}
	itemURN := ctx.resourceURN("poam_item", itemID)
	ctx.addResourceEntity(
		itemURN,
		"poam.item",
		firstAttribute(ctx.attrs, "title", "weakness_name", "finding_name", "poam_item_id", "weakness_id"),
		map[string]string{
			"poam_item_id":  itemID,
			"risk_rating":   firstAttribute(ctx.attrs, "risk_rating", "severity"),
			"source_system": ctx.provider,
			"status":        firstAttribute(ctx.attrs, "status"),
			"weakness_id":   firstAttribute(ctx.attrs, "weakness_id"),
		},
	)
	if findingID := firstAttribute(ctx.attrs, "finding_id"); findingID != "" {
		findingURN := ctx.globalURN("finding", findingID)
		ctx.addReferenceEntity(
			findingURN,
			"finding",
			firstAttribute(ctx.attrs, "finding_name", "title", "finding_id"),
			map[string]string{"finding_id": findingID, "source_system": ctx.provider},
		)
		ctx.addEventLink(itemURN, findingURN, relationAssociatedWith)
	}
	addGRCUserOwnerLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, itemURN, ctx.provider, firstAttribute(ctx.attrs, "owner_id"))
	addGRCTargetReferenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, itemURN, ctx.provider, ctx.attrs, relationTargeted, "grc_poam_item")
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, itemURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, itemURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, itemURN, "poam_risk", strings.Join([]string{ctx.attrs["risk_rating"], ctx.attrs["severity"], ctx.attrs["status"]}, ","))
	entities, links := ctx.done()
	return entities, links, nil
}

func grcTrainingAttestationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	ctx, err := newGRCProjectionContext(event)
	if err != nil {
		return nil, nil, err
	}
	attestationID := firstAttribute(ctx.attrs, "attestation_id", "training_attestation_id", "external_id")
	if attestationID == "" {
		attestationID = grcDerivedID(firstAttribute(ctx.attrs, "person_id", "user_id", "email"), firstAttribute(ctx.attrs, "course_id", "training_type"), firstAttribute(ctx.attrs, "completed_at", "expires_at"))
	}
	if attestationID == "" {
		return nil, nil, nil
	}
	attestationURN := ctx.resourceURN("training_attestation", attestationID)
	ctx.addResourceEntity(
		attestationURN,
		"training.attestation",
		firstAttribute(ctx.attrs, "course_name", "training_type", "course_id", "attestation_id"),
		map[string]string{
			"attestation_id": attestationID,
			"source_system":  ctx.provider,
			"status":         firstAttribute(ctx.attrs, "status"),
		},
	)
	if personID := firstAttribute(ctx.attrs, "person_id"); personID != "" {
		personURN := ctx.resourceURN("person", personID)
		ctx.addReferenceEntity(
			personURN,
			"person",
			firstAttribute(ctx.attrs, "person_name", "email", "person_id"),
			map[string]string{"person_id": personID, "source_system": ctx.provider},
		)
		ctx.addEventLink(personURN, attestationURN, relationHasEvidence)
		ctx.addEventLink(attestationURN, personURN, relationObservedOn)
	}
	if userID := firstAttribute(ctx.attrs, "user_id"); userID != "" {
		userURN := grcUserURN(ctx.tenantID, ctx.provider, userID)
		addEntity(ctx.entities, grcUserEntity(ctx.tenantID, ctx.sourceID, userURN, firstAttribute(ctx.attrs, "display_name", "email", "user_id"), grcAttributes(nil, map[string]string{"user_id": userID, "source_system": ctx.provider})))
		ctx.addEventLink(userURN, attestationURN, relationHasEvidence)
		ctx.addEventLink(attestationURN, userURN, relationObservedOn)
	}
	addGRCControlSupportLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, attestationURN, ctx.provider)
	addGRCEvidenceLink(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, attestationURN, ctx.provider, ctx.attrs)
	addGRCAssetTagLinks(ctx.entities, ctx.links, ctx.tenantID, ctx.sourceID, ctx.event, attestationURN, "training_type", firstAttribute(ctx.attrs, "training_type", "course_type"))
	entities, links := ctx.done()
	return entities, links, nil
}

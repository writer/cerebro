package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func grcGroupProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	groupID := firstAttribute(attrs, "group_id", "external_id")
	if groupID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	groupURN := projectionURN(tenantID, "grc_group", provider, groupID)
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        groupURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "group",
		Label:      firstAttribute(attrs, "group_name", "name", "group_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"group_id":      groupID,
			"group_name":    firstAttribute(attrs, "group_name", "name"),
			"source_system": provider,
		}),
	})
	projectedEntities, projectedLinks := entitiesAndLinks(entities, nil)
	return projectedEntities, projectedLinks, nil
}

func grcRegulatoryNotificationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	notificationID := firstAttribute(attrs, "notification_id", "external_id")
	if notificationID == "" {
		notificationID = grcDerivedID(firstAttribute(attrs, "framework"), firstAttribute(attrs, "incident_id", "case_id"), firstAttribute(attrs, "notification_type", "report_type"))
	}
	if notificationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	notificationURN := projectionURN(tenantID, "regulatory_notification", provider, notificationID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        notificationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "regulatory.notification",
		Label:      firstAttribute(attrs, "title", "notification_type", "report_type", "notification_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"incident_id":       firstAttribute(attrs, "incident_id", "case_id"),
			"notification_id":   notificationID,
			"notification_type": firstAttribute(attrs, "notification_type", "report_type"),
			"source_system":     provider,
			"status":            firstAttribute(attrs, "status", "notification_status"),
		}),
	})
	if incidentID := firstAttribute(attrs, "incident_id", "case_id"); incidentID != "" {
		incidentURN := projectionURN(tenantID, "incident", provider, incidentID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        incidentURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "incident",
			Label:      firstAttribute(attrs, "incident_title", "incident_name", "incident_id", "case_id"),
			Attributes: grcAttributes(nil, map[string]string{"incident_id": incidentID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), notificationURN, incidentURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, notificationURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, notificationURN, "regulatory_notification", strings.Join([]string{attrs["framework"], attrs["regulator"], attrs["notification_type"], attrs["report_type"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcRecoveryObjectiveProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	objectiveID := firstAttribute(attrs, "recovery_objective_id", "objective_id", "bia_id", "external_id")
	if objectiveID == "" {
		objectiveID = grcDerivedID(firstAttribute(attrs, "service_id", "target_id", "resource_id", "asset_id"), firstAttribute(attrs, "business_process"), firstAttribute(attrs, "rto_minutes"), firstAttribute(attrs, "rpo_minutes"))
	}
	if objectiveID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	objectiveURN := projectionURN(tenantID, "resilience_recovery_objective", provider, objectiveID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        objectiveURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "resilience.recovery_objective",
		Label:      firstAttribute(attrs, "name", "business_process", "service_id", "objective_id", "recovery_objective_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"recovery_objective_id": objectiveID,
			"source_system":         provider,
			"status":                firstAttribute(attrs, "status"),
		}),
	})
	if processName := firstAttribute(attrs, "business_process", "process_name"); processName != "" {
		processID := grcDerivedID(processName)
		processURN := projectionURN(tenantID, "business_process", provider, processID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        processURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "business.process",
			Label:      processName,
			Attributes: grcAttributes(nil, map[string]string{"business_process": processName, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), objectiveURN, processURN, relationSupports, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, attrs, relationTargeted, "grc_recovery_objective")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, objectiveURN, "resilience_tier", strings.Join([]string{attrs["impact_tier"], attrs["criticality"], attrs["recovery_priority"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcAuthorizationPackageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	packageID := firstAttribute(attrs, "authorization_package_id", "package_id", "ato_id", "ssp_id", "external_id")
	if packageID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	packageURN := projectionURN(tenantID, "authorization_package", provider, packageID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        packageURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "authorization.package",
		Label:      firstAttribute(attrs, "name", "system_name", "package_name", "package_id", "authorization_package_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"authorization_package_id": packageID,
			"framework":                firstAttribute(attrs, "framework"),
			"impact_level":             firstAttribute(attrs, "impact_level"),
			"source_system":            provider,
			"status":                   firstAttribute(attrs, "status", "authorization_status"),
		}),
	})
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, firstAttribute(attrs, "owner_id", "system_owner_user_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, attrs, relationTargeted, "grc_authorization_package")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, packageURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, packageURN, "authorization_package", strings.Join([]string{attrs["framework"], attrs["impact_level"], attrs["status"], attrs["authorization_status"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcPOAMItemProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	itemID := firstAttribute(attrs, "poam_item_id", "weakness_id", "finding_id", "external_id")
	if itemID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	itemURN := projectionURN(tenantID, "poam_item", provider, itemID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        itemURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "poam.item",
		Label:      firstAttribute(attrs, "title", "weakness_name", "finding_name", "poam_item_id", "weakness_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"poam_item_id":  itemID,
			"risk_rating":   firstAttribute(attrs, "risk_rating", "severity"),
			"source_system": provider,
			"status":        firstAttribute(attrs, "status"),
			"weakness_id":   firstAttribute(attrs, "weakness_id"),
		}),
	})
	if findingID := firstAttribute(attrs, "finding_id"); findingID != "" {
		findingURN := projectionURN(tenantID, "finding", findingID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        findingURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "finding",
			Label:      firstAttribute(attrs, "finding_name", "title", "finding_id"),
			Attributes: grcAttributes(nil, map[string]string{"finding_id": findingID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), itemURN, findingURN, relationAssociatedWith, map[string]string{"event_id": event.GetId()}))
	}
	addGRCUserOwnerLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, firstAttribute(attrs, "owner_id"))
	addGRCTargetReferenceLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, attrs, relationTargeted, "grc_poam_item")
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, itemURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, itemURN, "poam_risk", strings.Join([]string{attrs["risk_rating"], attrs["severity"], attrs["status"]}, ","))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func grcTrainingAttestationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	attestationID := firstAttribute(attrs, "attestation_id", "training_attestation_id", "external_id")
	if attestationID == "" {
		attestationID = grcDerivedID(firstAttribute(attrs, "person_id", "user_id", "email"), firstAttribute(attrs, "course_id", "training_type"), firstAttribute(attrs, "completed_at", "expires_at"))
	}
	if attestationID == "" {
		return nil, nil, nil
	}
	provider := grcProvider(attrs)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	attestationURN := projectionURN(tenantID, "training_attestation", provider, attestationID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        attestationURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "training.attestation",
		Label:      firstAttribute(attrs, "course_name", "training_type", "course_id", "attestation_id"),
		Attributes: grcAttributes(attrs, map[string]string{
			"attestation_id": attestationID,
			"source_system":  provider,
			"status":         firstAttribute(attrs, "status"),
		}),
	})
	if personID := firstAttribute(attrs, "person_id"); personID != "" {
		personURN := projectionURN(tenantID, "person", provider, personID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        personURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "person",
			Label:      firstAttribute(attrs, "person_name", "email", "person_id"),
			Attributes: grcAttributes(nil, map[string]string{"person_id": personID, "source_system": provider}),
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), personURN, attestationURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), attestationURN, personURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	if userID := firstAttribute(attrs, "user_id"); userID != "" {
		userURN := grcUserURN(tenantID, provider, userID)
		addEntity(entities, grcUserEntity(tenantID, event.GetSourceId(), userURN, firstAttribute(attrs, "display_name", "email", "user_id"), grcAttributes(nil, map[string]string{"user_id": userID, "source_system": provider})))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, attestationURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), attestationURN, userURN, relationObservedOn, map[string]string{"event_id": event.GetId()}))
	}
	addGRCControlSupportLinks(entities, links, tenantID, event.GetSourceId(), event, attestationURN, provider)
	addGRCEvidenceLink(entities, links, tenantID, event.GetSourceId(), event, attestationURN, provider, attrs)
	addGRCAssetTagLinks(entities, links, tenantID, event.GetSourceId(), event, attestationURN, "training_type", firstAttribute(attrs, "training_type", "course_type"))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

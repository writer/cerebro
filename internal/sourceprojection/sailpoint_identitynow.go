package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var sailpointIdentitynowProfile = identityProjectionProfile{Provider: "sailpoint_identitynow"}

func sailpointIdentitynowIdentitiesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowAccountsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	accountID := firstNonEmpty(attrs["account_id"], attrs["resource_id"], attrs["external_id"], event.GetId())
	accountURN := projectionURN(tenantID, "sailpoint_identitynow_account", accountID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	if accountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        accountURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "sailpoint_identitynow.account",
			Label:      firstNonEmpty(attrs["resource_name"], attrs["native_identity"], accountID),
			Attributes: map[string]string{
				"account_id":       accountID,
				"native_identity":  strings.TrimSpace(attrs["native_identity"]),
				"source_id":        strings.TrimSpace(attrs["source_id"]),
				"source_name":      strings.TrimSpace(attrs["source_name"]),
				"identity_id":      strings.TrimSpace(attrs["identity_id"]),
				"disabled":         strings.TrimSpace(attrs["disabled"]),
				"locked":           strings.TrimSpace(attrs["locked"]),
				"system_account":   strings.TrimSpace(attrs["system_account"]),
				"has_entitlements": strings.TrimSpace(attrs["has_entitlements"]),
			},
		})
	}
	if sourceID := strings.TrimSpace(attrs["source_id"]); sourceID != "" {
		sourceURN := identityApplicationURN(tenantID, sailpointIdentitynowProfile.Provider, sourceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        sourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: sailpointIdentitynowProfile.entityType("application"),
			Label:      firstNonEmpty(attrs["source_name"], sourceID),
			Attributes: map[string]string{"source_id": sourceID, "source_name": strings.TrimSpace(attrs["source_name"])},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), accountURN, sourceURN, relationBelongsTo, identityEventLinkAttributes(event)))
	}
	if identityID := strings.TrimSpace(attrs["identity_id"]); identityID != "" {
		userURN := identityPrincipalURN(tenantID, sailpointIdentitynowProfile.Provider, "user", identityID, "")
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: sailpointIdentitynowProfile.entityType("user"),
			Label:      firstNonEmpty(attrs["identity_name"], identityID),
			Attributes: map[string]string{"user_id": identityID},
		})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, accountURN, relationAssignedTo, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func sailpointIdentitynowSourcesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowSourceSchemasProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowSourceChildProjections(event, "source_schema", firstNonEmpty(event.GetAttributes()["schema_id"], event.GetAttributes()["external_id"]), firstNonEmpty(event.GetAttributes()["schema_name"], event.GetAttributes()["external_id"]))
}

func sailpointIdentitynowSourceHealthProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowSourceChildProjections(event, "source_health", firstNonEmpty(event.GetAttributes()["source_id"], event.GetAttributes()["external_id"]), firstNonEmpty(event.GetAttributes()["source_name"], event.GetAttributes()["source_id"]))
}

func sailpointIdentitynowSourceProvisioningPoliciesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowSourceSchedulesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowAccessProfilesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowRoleDimensionsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowIdentityProfilesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowLifecycleStatesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowCampaignsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowCertificationsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowAccessRequestStatusProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowAccountActivitiesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowSegmentsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowAccessModelProjections(event)
}

func sailpointIdentitynowWorkgroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowWorkgroupMembersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowRoleAssignedIdentitiesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowIdentityRoleAssignmentsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowPersonalAccessTokensProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, sailpointIdentitynowProfile)
}

func sailpointIdentitynowEntitlementsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowEntitlementProjections(event)
}

func sailpointIdentitynowAccountEntitlementsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowEntitlementProjections(event)
}

func sailpointIdentitynowAccessProfileEntitlementsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowEntitlementProjections(event)
}

func sailpointIdentitynowRoleEntitlementsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowEntitlementProjections(event)
}

func sailpointIdentitynowIdentityEntitlementsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return sailpointIdentitynowEntitlementProjections(event)
}

func sailpointIdentitynowCertificationAccessReviewItemsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	itemID := firstNonEmpty(attrs["review_item_id"], attrs["external_id"], event.GetId())
	itemURN := projectionURN(tenantID, "sailpoint_identitynow_certification_review_item", itemID)
	certURN := projectionURN(tenantID, "sailpoint_identitynow_certification", attrs["certification_id"])
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        itemURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sailpoint_identitynow.certification_review_item",
		Label:      firstNonEmpty(attrs["access_name"], attrs["identity_name"], itemID),
		Attributes: map[string]string{
			"review_item_id":   itemID,
			"certification_id": strings.TrimSpace(attrs["certification_id"]),
			"decision":         strings.TrimSpace(attrs["decision"]),
			"completed":        strings.TrimSpace(attrs["completed"]),
			"access_type":      strings.TrimSpace(attrs["access_type"]),
		},
	})
	if certURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: certURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "sailpoint_identitynow.certification", Label: firstNonEmpty(attrs["certification_id"], "Certification")})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), itemURN, certURN, relationBelongsTo, identityEventLinkAttributes(event)))
	}
	if identityID := strings.TrimSpace(attrs["identity_id"]); identityID != "" {
		userURN := identityPrincipalURN(tenantID, sailpointIdentitynowProfile.Provider, "user", identityID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: userURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("user"), Label: firstNonEmpty(attrs["identity_name"], identityID), Attributes: map[string]string{"user_id": identityID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), itemURN, userURN, relationObservedOn, identityEventLinkAttributes(event)))
	}
	if accessID := strings.TrimSpace(attrs["access_id"]); accessID != "" {
		entitlementURN := projectionURN(tenantID, "sailpoint_identitynow_entitlement", accessID)
		addEntity(entities, &ports.ProjectedEntity{URN: entitlementURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "sailpoint_identitynow.entitlement", Label: firstNonEmpty(attrs["access_name"], accessID), Attributes: map[string]string{"entitlement_id": accessID, "access_type": strings.TrimSpace(attrs["access_type"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), itemURN, entitlementURN, relationObservedOn, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func sailpointIdentitynowSourceChildProjections(event *cerebrov1.EventEnvelope, childKind string, childID string, label string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	childURN := projectionURN(tenantID, "sailpoint_identitynow_"+childKind, childID)
	sourceURN := identityApplicationURN(tenantID, sailpointIdentitynowProfile.Provider, attrs["source_id"])
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        childURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sailpoint_identitynow." + childKind,
		Label:      firstNonEmpty(label, childID),
		Attributes: copySailpointAttributes(attrs, "source_id", "schema_id", "schema_name", "status", "hostname", "native_object_type", "identity_attribute", "display_attribute", "include_permissions"),
	})
	if sourceURN != "" {
		addEntity(entities, &ports.ProjectedEntity{URN: sourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("application"), Label: firstNonEmpty(attrs["source_name"], attrs["source_id"]), Attributes: map[string]string{"source_id": strings.TrimSpace(attrs["source_id"])}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), childURN, sourceURN, relationBelongsTo, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func sailpointIdentitynowAccessModelProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entityKind := sailpointAccessModelKind(attrs)
	entityID := sailpointAccessModelID(attrs, entityKind)
	entityURN := projectionURN(tenantID, "sailpoint_identitynow_"+entityKind, entityID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        entityURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sailpoint_identitynow." + entityKind,
		Label:      firstNonEmpty(attrs["policy_name"], attrs["role_name"], attrs["access_profile_name"], attrs["identity_profile_name"], attrs["segment_name"], attrs["campaign_name"], attrs["certification_name"], attrs["schedule_type"], entityID),
		Attributes: copySailpointAttributes(attrs, "policy_id", "policy_name", "policy_type", "policy_status", "role_id", "role_name", "access_profile_id", "identity_profile_id", "lifecycle_state", "campaign_id", "certification_id", "segment_id", "source_id", "owner_id", "enabled", "requestable", "status", "phase", "completed", "deadline", "identity_count"),
	})
	if sourceID := strings.TrimSpace(attrs["source_id"]); sourceID != "" {
		sourceURN := identityApplicationURN(tenantID, sailpointIdentitynowProfile.Provider, sourceID)
		addEntity(entities, &ports.ProjectedEntity{URN: sourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("application"), Label: firstNonEmpty(attrs["source_name"], sourceID), Attributes: map[string]string{"source_id": sourceID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entityURN, sourceURN, relationBelongsTo, identityEventLinkAttributes(event)))
	}
	if ownerID := strings.TrimSpace(attrs["owner_id"]); ownerID != "" {
		ownerURN := identityPrincipalURN(tenantID, sailpointIdentitynowProfile.Provider, "user", ownerID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: ownerURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("user"), Label: firstNonEmpty(attrs["owner_name"], ownerID), Attributes: map[string]string{"user_id": ownerID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), ownerURN, entityURN, relationCanAdmin, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func sailpointIdentitynowEntitlementProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	entitlementID := firstNonEmpty(attrs["entitlement_id"], attrs["external_id"], event.GetId())
	entitlementURN := projectionURN(tenantID, "sailpoint_identitynow_entitlement", entitlementID)
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        entitlementURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "sailpoint_identitynow.entitlement",
		Label:      firstNonEmpty(attrs["entitlement_name"], attrs["entitlement_value"], entitlementID),
		Attributes: copySailpointAttributes(attrs, "entitlement_id", "entitlement_name", "entitlement_value", "attribute", "source_id", "source_name", "privileged", "requestable", "tags"),
	})
	if sourceID := strings.TrimSpace(attrs["source_id"]); sourceID != "" {
		sourceURN := identityApplicationURN(tenantID, sailpointIdentitynowProfile.Provider, sourceID)
		addEntity(entities, &ports.ProjectedEntity{URN: sourceURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("application"), Label: firstNonEmpty(attrs["source_name"], sourceID), Attributes: map[string]string{"source_id": sourceID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), entitlementURN, sourceURN, relationBelongsTo, identityEventLinkAttributes(event)))
	}
	if accountID := strings.TrimSpace(attrs["account_id"]); accountID != "" {
		accountURN := projectionURN(tenantID, "sailpoint_identitynow_account", accountID)
		addEntity(entities, &ports.ProjectedEntity{URN: accountURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "sailpoint_identitynow.account", Label: accountID, Attributes: map[string]string{"account_id": accountID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), accountURN, entitlementURN, relationAssignedTo, identityEventLinkAttributes(event)))
	}
	if accessProfileID := strings.TrimSpace(attrs["access_profile_id"]); accessProfileID != "" {
		accessProfileURN := projectionURN(tenantID, "sailpoint_identitynow_access_profile", accessProfileID)
		addEntity(entities, &ports.ProjectedEntity{URN: accessProfileURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "sailpoint_identitynow.access_profile", Label: accessProfileID, Attributes: map[string]string{"access_profile_id": accessProfileID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), accessProfileURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	}
	if roleID := strings.TrimSpace(attrs["role_id"]); roleID != "" {
		roleURN := projectionURN(tenantID, "sailpoint_identitynow_role", roleID)
		addEntity(entities, &ports.ProjectedEntity{URN: roleURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: "sailpoint_identitynow.role", Label: firstNonEmpty(attrs["role_name"], roleID), Attributes: map[string]string{"role_id": roleID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), roleURN, entitlementURN, relationGrantsEntitlement, identityEventLinkAttributes(event)))
	}
	if identityID := firstNonEmpty(attrs["identity_id"], attrs["subject_id"]); identityID != "" {
		userURN := identityPrincipalURN(tenantID, sailpointIdentitynowProfile.Provider, "user", identityID, "")
		addEntity(entities, &ports.ProjectedEntity{URN: userURN, TenantID: tenantID, SourceID: event.GetSourceId(), EntityType: sailpointIdentitynowProfile.entityType("user"), Label: identityID, Attributes: map[string]string{"user_id": identityID}})
		addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, entitlementURN, relationAssignedTo, identityEventLinkAttributes(event)))
	}
	return identityProjectionResult(entities, links)
}

func sailpointAccessModelKind(attrs map[string]string) string {
	switch strings.TrimSpace(attrs["policy_type"]) {
	case "access_profile":
		return "access_profile"
	case "role":
		return "role"
	case "role_dimension":
		return "role_dimension"
	case "identity_profile":
		return "identity_profile"
	case "lifecycle_state":
		return "lifecycle_state"
	case "certification_campaign":
		return "campaign"
	case "segment":
		return "segment"
	case "source_schedule":
		return "source_schedule"
	case "provisioning_policy":
		return "provisioning_policy"
	}
	if strings.TrimSpace(attrs["certification_id"]) != "" {
		return "certification"
	}
	return "access_model"
}

func sailpointAccessModelID(attrs map[string]string, kind string) string {
	switch kind {
	case "access_profile":
		return firstNonEmpty(attrs["access_profile_id"], attrs["policy_id"])
	case "role":
		return firstNonEmpty(attrs["role_id"], attrs["policy_id"])
	case "role_dimension":
		return firstNonEmpty(attrs["dimension_id"], attrs["policy_id"])
	case "identity_profile":
		return firstNonEmpty(attrs["identity_profile_id"], attrs["policy_id"])
	case "lifecycle_state":
		return firstNonEmpty(attrs["lifecycle_state_id"], attrs["policy_id"])
	case "campaign":
		return firstNonEmpty(attrs["campaign_id"], attrs["policy_id"])
	case "certification":
		return firstNonEmpty(attrs["certification_id"], attrs["external_id"])
	case "segment":
		return firstNonEmpty(attrs["segment_id"], attrs["policy_id"])
	}
	return firstNonEmpty(attrs["policy_id"], attrs["external_id"])
}

func copySailpointAttributes(attrs map[string]string, keys ...string) map[string]string {
	out := map[string]string{}
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); value != "" {
			out[key] = value
		}
	}
	return out
}

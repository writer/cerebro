package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestSailpointIdentitynowProjectsEveryRuntimeKind(t *testing.T) {
	tests := []struct {
		name    string
		event   *cerebrov1.EventEnvelope
		project ProjectFunc
	}{
		{name: "identities", event: sailpointIdentitynowEvent("sailpoint_identitynow.identities", sailpointProjectionAttrs()), project: sailpointIdentitynowIdentitiesProjections},
		{name: "accounts", event: sailpointIdentitynowEvent("sailpoint_identitynow.accounts", sailpointProjectionAttrs()), project: sailpointIdentitynowAccountsProjections},
		{name: "account_entitlements", event: sailpointIdentitynowEvent("sailpoint_identitynow.account_entitlements", sailpointProjectionAttrs()), project: sailpointIdentitynowAccountEntitlementsProjections},
		{name: "sources", event: sailpointIdentitynowEvent("sailpoint_identitynow.sources", sailpointProjectionAttrs()), project: sailpointIdentitynowSourcesProjections},
		{name: "source_schemas", event: sailpointIdentitynowEvent("sailpoint_identitynow.source_schemas", sailpointProjectionAttrs()), project: sailpointIdentitynowSourceSchemasProjections},
		{name: "source_health", event: sailpointIdentitynowEvent("sailpoint_identitynow.source_health", sailpointProjectionAttrs()), project: sailpointIdentitynowSourceHealthProjections},
		{name: "source_provisioning_policies", event: sailpointIdentitynowEvent("sailpoint_identitynow.source_provisioning_policies", sailpointProjectionAttrs()), project: sailpointIdentitynowSourceProvisioningPoliciesProjections},
		{name: "source_schedules", event: sailpointIdentitynowEvent("sailpoint_identitynow.source_schedules", sailpointProjectionAttrs()), project: sailpointIdentitynowSourceSchedulesProjections},
		{name: "access_profiles", event: sailpointIdentitynowEvent("sailpoint_identitynow.access_profiles", sailpointProjectionAttrs()), project: sailpointIdentitynowAccessProfilesProjections},
		{name: "access_profile_entitlements", event: sailpointIdentitynowEvent("sailpoint_identitynow.access_profile_entitlements", sailpointProjectionAttrs()), project: sailpointIdentitynowAccessProfileEntitlementsProjections},
		{name: "roles", event: sailpointIdentitynowEvent("sailpoint_identitynow.roles", sailpointProjectionAttrs()), project: sailpointIdentitynowRolesProjections},
		{name: "role_assigned_identities", event: sailpointIdentitynowEvent("sailpoint_identitynow.role_assigned_identities", sailpointProjectionAttrs()), project: sailpointIdentitynowRoleAssignedIdentitiesProjections},
		{name: "role_entitlements", event: sailpointIdentitynowEvent("sailpoint_identitynow.role_entitlements", sailpointProjectionAttrs()), project: sailpointIdentitynowRoleEntitlementsProjections},
		{name: "role_dimensions", event: sailpointIdentitynowEvent("sailpoint_identitynow.role_dimensions", sailpointProjectionAttrs()), project: sailpointIdentitynowRoleDimensionsProjections},
		{name: "entitlements", event: sailpointIdentitynowEvent("sailpoint_identitynow.entitlements", sailpointProjectionAttrs()), project: sailpointIdentitynowEntitlementsProjections},
		{name: "identity_entitlements", event: sailpointIdentitynowEvent("sailpoint_identitynow.identity_entitlements", sailpointProjectionAttrs()), project: sailpointIdentitynowIdentityEntitlementsProjections},
		{name: "identity_role_assignments", event: sailpointIdentitynowEvent("sailpoint_identitynow.identity_role_assignments", sailpointProjectionAttrs()), project: sailpointIdentitynowIdentityRoleAssignmentsProjections},
		{name: "identity_profiles", event: sailpointIdentitynowEvent("sailpoint_identitynow.identity_profiles", sailpointProjectionAttrs()), project: sailpointIdentitynowIdentityProfilesProjections},
		{name: "lifecycle_states", event: sailpointIdentitynowEvent("sailpoint_identitynow.lifecycle_states", sailpointProjectionAttrs()), project: sailpointIdentitynowLifecycleStatesProjections},
		{name: "workgroups", event: sailpointIdentitynowEvent("sailpoint_identitynow.workgroups", sailpointProjectionAttrs()), project: sailpointIdentitynowWorkgroupsProjections},
		{name: "workgroup_members", event: sailpointIdentitynowEvent("sailpoint_identitynow.workgroup_members", sailpointProjectionAttrs()), project: sailpointIdentitynowWorkgroupMembersProjections},
		{name: "campaigns", event: sailpointIdentitynowEvent("sailpoint_identitynow.campaigns", sailpointProjectionAttrs()), project: sailpointIdentitynowCampaignsProjections},
		{name: "certifications", event: sailpointIdentitynowEvent("sailpoint_identitynow.certifications", sailpointProjectionAttrs()), project: sailpointIdentitynowCertificationsProjections},
		{name: "certification_access_review_items", event: sailpointIdentitynowEvent("sailpoint_identitynow.certification_access_review_items", sailpointProjectionAttrs()), project: sailpointIdentitynowCertificationAccessReviewItemsProjections},
		{name: "access_request_status", event: sailpointIdentitynowEvent("sailpoint_identitynow.access_request_status", sailpointProjectionAttrs()), project: sailpointIdentitynowAccessRequestStatusProjections},
		{name: "account_activities", event: sailpointIdentitynowEvent("sailpoint_identitynow.account_activities", sailpointProjectionAttrs()), project: sailpointIdentitynowAccountActivitiesProjections},
		{name: "personal_access_tokens", event: sailpointIdentitynowEvent("sailpoint_identitynow.personal_access_tokens", sailpointProjectionAttrs()), project: sailpointIdentitynowPersonalAccessTokensProjections},
		{name: "segments", event: sailpointIdentitynowEvent("sailpoint_identitynow.segments", sailpointProjectionAttrs()), project: sailpointIdentitynowSegmentsProjections},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entities, _, err := test.project(test.event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if len(entities) == 0 {
				t.Fatal("expected projected entities")
			}
		})
	}
}

func TestSailpointIdentitynowIdentityProjection(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.identities", map[string]string{
		"user_id":      "2c91808568c529c60168cca6f90c1313",
		"display_name": "Jane Access",
		"email":        "jane.access@example.test",
		"status":       "ACTIVE",
	})
	entities, links, err := sailpointIdentitynowIdentitiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected identity entity")
	}
	if len(links) == 0 {
		t.Fatal("expected identity links")
	}
}

func TestSailpointIdentitynowAccountProjectionLinksIdentityAndSource(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.accounts", map[string]string{
		"account_id":      "acct-1",
		"native_identity": "jane.access",
		"source_id":       "source-1",
		"source_name":     "Workday",
		"identity_id":     "identity-1",
		"identity_name":   "Jane Access",
	})
	entities, links, err := sailpointIdentitynowAccountsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 3 {
		t.Fatalf("entities = %d, want account, identity, and source", len(entities))
	}
	if len(links) < 2 {
		t.Fatalf("links = %d, want identity/account/source links", len(links))
	}
}

func TestSailpointIdentitynowEntitlementProjectionLinksAccessModel(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.role_entitlements", map[string]string{
		"entitlement_id":    "entitlement-1",
		"entitlement_name":  "Payroll Admin",
		"entitlement_value": "payroll-admin",
		"source_id":         "source-1",
		"source_name":       "Payroll",
		"role_id":           "role-1",
		"role_name":         "Payroll Reviewer",
	})
	entities, links, err := sailpointIdentitynowRoleEntitlementsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 3 {
		t.Fatalf("entities = %d, want entitlement, role, and source", len(entities))
	}
	if len(links) < 2 {
		t.Fatalf("links = %d, want entitlement links", len(links))
	}
}

func TestSailpointIdentitynowRoleAssignmentProjection(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.role_assigned_identities", map[string]string{
		"role_id":       "role-1",
		"role_name":     "Payroll Reviewer",
		"subject_id":    "identity-1",
		"subject_name":  "Jane Access",
		"subject_email": "jane.access@example.test",
		"subject_type":  "user",
	})
	entities, links, err := sailpointIdentitynowRoleAssignedIdentitiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 {
		t.Fatalf("entities = %d, want role and identity", len(entities))
	}
	if len(links) == 0 {
		t.Fatal("expected assignment link")
	}
}

func TestSailpointIdentitynowCertificationReviewProjectionLinksAccess(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.certification_access_review_items", map[string]string{
		"review_item_id":   "review-item-1",
		"certification_id": "certification-1",
		"identity_id":      "identity-1",
		"identity_name":    "Jane Access",
		"access_id":        "entitlement-1",
		"access_name":      "Payroll Admin",
		"access_type":      "ENTITLEMENT",
		"decision":         "APPROVED",
	})
	entities, links, err := sailpointIdentitynowCertificationAccessReviewItemsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 4 {
		t.Fatalf("entities = %d, want review item, certification, identity, and entitlement", len(entities))
	}
	if len(links) < 3 {
		t.Fatalf("links = %d, want review context links", len(links))
	}
}

func TestSailpointIdentitynowCertificationProjectionCopiesPolicyStatus(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.certifications", map[string]string{
		"certification_id":   "certification-1",
		"certification_name": "Finance approver certification",
		"policy_type":        "certification",
		"policy_status":      "ACTIVE",
		"phase":              "ACTIVE",
	})
	entities, _, err := sailpointIdentitynowCertificationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	for _, entity := range entities {
		if entity.EntityType == "sailpoint_identitynow.certification" {
			if got := entity.Attributes["policy_status"]; got != "ACTIVE" {
				t.Fatalf("policy_status = %q, want ACTIVE", got)
			}
			if got := entity.Attributes["policy_type"]; got != "certification" {
				t.Fatalf("policy_type = %q, want certification", got)
			}
			return
		}
	}
	t.Fatalf("missing certification entity in %#v", entities)
}

func TestSailpointIdentitynowSourceHealthProjectionCopiesHealthMetadata(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.source_health", map[string]string{
		"source_id":     "source-1",
		"source_name":   "Corporate Active Directory",
		"source_type":   "Active Directory - Direct",
		"status":        "SOURCE_STATE_HEALTHY",
		"hostname":      "ad.example.test",
		"org":           "acme",
		"authoritative": "true",
		"cluster":       "false",
	})
	entities, _, err := sailpointIdentitynowSourceHealthProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	entity := sailpointEntityByType(entities, "sailpoint_identitynow.source_health")
	if entity == nil {
		t.Fatalf("missing source health entity in %#v", entities)
	}
	for key, want := range map[string]string{
		"source_name":   "Corporate Active Directory",
		"source_type":   "Active Directory - Direct",
		"org":           "acme",
		"authoritative": "true",
		"cluster":       "false",
	} {
		if got := entity.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestSailpointIdentitynowSourceScheduleProjectionCopiesCronExpression(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.source_schedules", map[string]string{
		"source_id":       "source-1",
		"schedule_id":     "source-1-ACCOUNT_AGGREGATION",
		"schedule_type":   "ACCOUNT_AGGREGATION",
		"cron_expression": "0 0 2 * * ?",
		"policy_id":       "source-1-ACCOUNT_AGGREGATION",
		"policy_name":     "ACCOUNT_AGGREGATION",
		"policy_type":     "source_schedule",
	})
	entities, _, err := sailpointIdentitynowSourceSchedulesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	entity := sailpointEntityByType(entities, "sailpoint_identitynow.source_schedule")
	if entity == nil {
		t.Fatalf("missing source schedule entity in %#v", entities)
	}
	if got := entity.Attributes["cron_expression"]; got != "0 0 2 * * ?" {
		t.Fatalf("cron_expression = %q, want schedule expression", got)
	}
	if got := entity.Attributes["schedule_type"]; got != "ACCOUNT_AGGREGATION" {
		t.Fatalf("schedule_type = %q, want ACCOUNT_AGGREGATION", got)
	}
}

func TestSailpointIdentitynowAuditProjectionLinksUserResources(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.access_request_status", map[string]string{
		"actor_id":      "identity-actor",
		"actor_name":    "Riley Chen",
		"resource_id":   "identity-resource",
		"resource_name": "Morgan Alvarez",
		"resource_type": "user",
		"event_type":    "GRANT_ACCESS",
	})
	entities, links, err := sailpointIdentitynowAccessRequestStatusProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	actorURN := identityUserURN("tenant", "sailpoint_identitynow", "identity-actor", "")
	resourceURN := identityUserURN("tenant", "sailpoint_identitynow", "identity-resource", "")
	if !hasProjectedEntityURN(entities, actorURN) {
		t.Fatalf("missing actor user entity %q in %#v", actorURN, entities)
	}
	if !hasProjectedEntityURN(entities, resourceURN) {
		t.Fatalf("missing resource user entity %q in %#v", resourceURN, entities)
	}
	if hasProjectedEntityURN(entities, projectionURN("tenant", "sailpoint_identitynow_identity", "identity-resource")) {
		t.Fatalf("created disconnected identity resource entity in %#v", entities)
	}
	if !projectedLinksContain(links, actorURN, relationActedOn, resourceURN) {
		t.Fatalf("missing acted_on link %q -> %q in %#v", actorURN, resourceURN, links)
	}
}

func TestSailpointIdentitynowCertificationReviewProjectionUsesAccessType(t *testing.T) {
	tests := []struct {
		name           string
		accessType     string
		wantEntityType string
	}{
		{name: "entitlement", accessType: "ENTITLEMENT", wantEntityType: "sailpoint_identitynow.entitlement"},
		{name: "access profile", accessType: "ACCESS_PROFILE", wantEntityType: "sailpoint_identitynow.access_profile"},
		{name: "role", accessType: "ROLE", wantEntityType: "sailpoint_identitynow.role"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := sailpointIdentitynowEvent("sailpoint_identitynow.certification_access_review_items", map[string]string{
				"review_item_id":   "review-item-1",
				"certification_id": "certification-1",
				"identity_id":      "identity-1",
				"access_id":        "access-1",
				"access_name":      "Payroll Access",
				"access_type":      test.accessType,
			})
			entities, _, err := sailpointIdentitynowCertificationAccessReviewItemsProjections(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if !sailpointHasEntityType(entities, test.wantEntityType) {
				t.Fatalf("missing entity type %q in %#v", test.wantEntityType, entities)
			}
			if test.wantEntityType != "sailpoint_identitynow.entitlement" && sailpointHasEntityType(entities, "sailpoint_identitynow.entitlement") {
				t.Fatalf("created phantom entitlement entity for access_type=%s: %#v", test.accessType, entities)
			}
		})
	}
}

func TestSailpointIdentitynowCertificationReviewProjectionSkipsUnknownAccessType(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.certification_access_review_items", map[string]string{
		"review_item_id":   "review-item-1",
		"certification_id": "certification-1",
		"identity_id":      "identity-1",
		"access_id":        "access-1",
		"access_name":      "Payroll Access",
		"access_type":      "UNKNOWN",
	})
	entities, links, err := sailpointIdentitynowCertificationAccessReviewItemsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	for _, entityType := range []string{"sailpoint_identitynow.entitlement", "sailpoint_identitynow.access_profile", "sailpoint_identitynow.role"} {
		if sailpointHasEntityType(entities, entityType) {
			t.Fatalf("created access entity type %q for unknown access_type: %#v", entityType, entities)
		}
	}
	if len(entities) != 3 || len(links) != 2 {
		t.Fatalf("entities/links = %d/%d, want review item, certification, identity, and no access entity", len(entities), len(links))
	}
}

func sailpointHasEntityType(entities []*ports.ProjectedEntity, entityType string) bool {
	return sailpointEntityByType(entities, entityType) != nil
}

func sailpointEntityByType(entities []*ports.ProjectedEntity, entityType string) *ports.ProjectedEntity {
	for _, entity := range entities {
		if entity.EntityType == entityType {
			return entity
		}
	}
	return nil
}

func TestSailpointIdentitynowPersonalAccessTokenProjection(t *testing.T) {
	event := sailpointIdentitynowEvent("sailpoint_identitynow.personal_access_tokens", map[string]string{
		"credential_id":   "pat-1",
		"credential_name": "automation token",
		"credential_type": "personal_access_token",
		"subject_id":      "identity-1",
		"subject_name":    "Jane Access",
		"subject_type":    "user",
		"status":          "ACTIVE",
	})
	entities, links, err := sailpointIdentitynowPersonalAccessTokensProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) < 2 {
		t.Fatalf("entities = %d, want identity and credential", len(entities))
	}
	if len(links) == 0 {
		t.Fatal("expected credential assignment link")
	}
}

func sailpointIdentitynowEvent(kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "event-1",
		TenantId:   "tenant",
		SourceId:   "sailpoint_identitynow",
		Kind:       kind,
		Attributes: attrs,
	}
}

func sailpointProjectionAttrs() map[string]string {
	return map[string]string{
		"access_id":           "entitlement-1",
		"access_name":         "Payroll Admin",
		"access_profile_id":   "access-profile-1",
		"access_type":         "ENTITLEMENT",
		"account_id":          "account-1",
		"actor_id":            "identity-1",
		"actor_name":          "Jane Access",
		"campaign_id":         "campaign-1",
		"certification_id":    "certification-1",
		"credential_id":       "pat-1",
		"credential_name":     "Automation token",
		"credential_type":     "personal_access_token",
		"decision":            "APPROVED",
		"display_name":        "Jane Access",
		"email":               "jane.access@example.test",
		"entitlement_id":      "entitlement-1",
		"entitlement_name":    "Payroll Admin",
		"entitlement_value":   "payroll-admin",
		"event_type":          "ACCESS_REQUEST_COMPLETED",
		"group_id":            "workgroup-1",
		"group_name":          "Access Reviewers",
		"identity_id":         "identity-1",
		"identity_name":       "Jane Access",
		"identity_profile_id": "identity-profile-1",
		"lifecycle_state_id":  "lifecycle-state-1",
		"member_id":           "identity-1",
		"member_name":         "Jane Access",
		"native_identity":     "jane.access",
		"owner_id":            "owner-1",
		"owner_name":          "Control Owner",
		"policy_id":           "policy-1",
		"policy_name":         "Payroll Access",
		"policy_type":         "role",
		"resource_id":         "request-1",
		"resource_name":       "Payroll Access",
		"resource_type":       "access_request",
		"review_item_id":      "review-item-1",
		"role_id":             "role-1",
		"role_name":           "Payroll Reviewer",
		"schema_id":           "schema-1",
		"schema_name":         "Account",
		"segment_id":          "segment-1",
		"source_id":           "source-1",
		"source_name":         "Payroll",
		"subject_email":       "jane.access@example.test",
		"subject_id":          "identity-1",
		"subject_name":        "Jane Access",
		"subject_type":        "user",
		"user_id":             "identity-1",
	}
}

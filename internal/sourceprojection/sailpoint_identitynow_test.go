package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSailpointIdentitynowGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"sailpoint_identitynow.access_profile_entitlements",
		"sailpoint_identitynow.access_profiles",
		"sailpoint_identitynow.access_request_status",
		"sailpoint_identitynow.account_activities",
		"sailpoint_identitynow.account_entitlements",
		"sailpoint_identitynow.accounts",
		"sailpoint_identitynow.campaigns",
		"sailpoint_identitynow.certification_access_review_items",
		"sailpoint_identitynow.certifications",
		"sailpoint_identitynow.entitlements",
		"sailpoint_identitynow.identities",
		"sailpoint_identitynow.identity_entitlements",
		"sailpoint_identitynow.identity_profiles",
		"sailpoint_identitynow.identity_role_assignments",
		"sailpoint_identitynow.lifecycle_states",
		"sailpoint_identitynow.personal_access_tokens",
		"sailpoint_identitynow.role_assigned_identities",
		"sailpoint_identitynow.role_dimensions",
		"sailpoint_identitynow.role_entitlements",
		"sailpoint_identitynow.roles",
		"sailpoint_identitynow.segments",
		"sailpoint_identitynow.source_health",
		"sailpoint_identitynow.source_provisioning_policies",
		"sailpoint_identitynow.source_schedules",
		"sailpoint_identitynow.source_schemas",
		"sailpoint_identitynow.sources",
		"sailpoint_identitynow.workgroup_members",
		"sailpoint_identitynow.workgroups",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "sailpoint_identitynow",
				Kind:     kind,
			})
			if !errors.Is(err, errSailpointIdentitynowRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}

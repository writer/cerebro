package findings

import (
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIdentityFingerprintHelpers_TenantScoped(t *testing.T) {
	tenantA := "example-identity-helper-a"
	projection := findingProjectionContext{
		PrimaryActorURN:    identityProjectionURN(tenantA, "google_workspace_user", "1001"),
		PrimaryResourceURN: identityProjectionURN(tenantA, "google_workspace_user", "1001"),
	}
	helperCases := []struct {
		name   string
		event  *cerebrov1.EventEnvelope
		attrs  map[string]string
		inputs []string
	}{
		{
			name:  "identityUserFingerprintInputs",
			event: tenantScopedIdentityEvent("helper-user", tenantA, "google_workspace", "google_workspace.user", identityUserTenantScopedAttrs(), identityTrajectoryBaseTime),
			attrs: identityUserTenantScopedAttrs(),
			inputs: identityUserFingerprintInputs(
				tenantScopedIdentityEvent("helper-user", tenantA, "google_workspace", "google_workspace.user", identityUserTenantScopedAttrs(), identityTrajectoryBaseTime),
				identityUserTenantScopedAttrs(),
				projection,
			),
		},
		{
			name:  "identityAdminPrivilegeFingerprintInputs",
			event: tenantScopedIdentityEvent("helper-admin", tenantA, "google_workspace", "google_workspace.role_assignment", identityAdminTenantScopedAttrs(), identityTrajectoryBaseTime),
			attrs: identityAdminTenantScopedAttrs(),
			inputs: identityAdminPrivilegeFingerprintInputs(
				tenantScopedIdentityEvent("helper-admin", tenantA, "google_workspace", "google_workspace.role_assignment", identityAdminTenantScopedAttrs(), identityTrajectoryBaseTime),
				identityAdminTenantScopedAttrs(),
				projection,
			),
		},
		{
			name:  "identityAuthControlFingerprintInputs",
			event: tenantScopedIdentityEvent("helper-auth", tenantA, "okta", "okta.audit", identityAuthControlTenantScopedAttrs(), identityTrajectoryBaseTime),
			attrs: identityAuthControlTenantScopedAttrs(),
			inputs: identityAuthControlFingerprintInputs(
				tenantScopedIdentityEvent("helper-auth", tenantA, "okta", "okta.audit", identityAuthControlTenantScopedAttrs(), identityTrajectoryBaseTime),
				identityAuthControlTenantScopedAttrs(),
				projection,
			),
		},
		{
			name:  "identityAPITokenOrOAuthFingerprintInputs",
			event: tenantScopedIdentityEvent("helper-token", tenantA, "aws", "aws.access_key", identityTokenTenantScopedAttrs(), identityTrajectoryBaseTime),
			attrs: identityTokenTenantScopedAttrs(),
			inputs: identityAPITokenOrOAuthFingerprintInputs(
				tenantScopedIdentityEvent("helper-token", tenantA, "aws", "aws.access_key", identityTokenTenantScopedAttrs(), identityTrajectoryBaseTime),
				identityTokenTenantScopedAttrs(),
				projection,
			),
		},
		{
			name:  "identityExternalGroupMemberFingerprintInputs",
			event: tenantScopedIdentityEvent("helper-group", tenantA, "okta", "okta.group_membership", identityExternalGroupTenantScopedAttrs(), identityTrajectoryBaseTime),
			attrs: identityExternalGroupTenantScopedAttrs(),
			inputs: identityExternalGroupMemberFingerprintInputs(
				tenantScopedIdentityEvent("helper-group", tenantA, "okta", "okta.group_membership", identityExternalGroupTenantScopedAttrs(), identityTrajectoryBaseTime),
				identityExternalGroupTenantScopedAttrs(),
				projection,
			),
		},
	}
	for _, tc := range helperCases {
		if len(tc.inputs) == 0 {
			t.Fatalf("%s returned no fingerprint inputs for attrs %#v", tc.name, tc.attrs)
		}
		if got := strings.TrimSpace(tc.inputs[0]); got != tenantA {
			t.Fatalf("%s first fingerprint input = %q, want tenant_id %q", tc.name, got, tenantA)
		}
	}
}

func tenantScopedIdentityEvent(id string, tenantID string, sourceID string, kind string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	event := identitySignalEventAt(id, sourceID, kind, attrs, occurredAt)
	event.TenantId = tenantID
	return event
}

func identityUserTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":        "writer.com",
		"email":         "admin@writer.com",
		"is_admin":      "true",
		"mfa_enrolled":  "false",
		"primary_email": "admin@writer.com",
		"user_id":       "1001",
	}
}

func identityAdminTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":        "writer.com",
		"role_id":       "super-admin",
		"role_name":     "Super Admin",
		"status":        "ACTIVE",
		"subject_email": "admin@writer.com",
		"subject_id":    "1001",
		"subject_type":  "user",
	}
}

func identityAuthControlTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":                "writer.okta.com",
		"event_type":            "policy.lifecycle.update",
		"actor_email":           "admin@writer.com",
		"policy_id":             "pol-sign-on",
		"resource_id":           "pol-sign-on",
		"resource_type":         "policy",
		"auth_control_weakened": "true",
		"outcome_result":        "SUCCESS",
	}
}

func identityTokenTenantScopedAttrs() map[string]string {
	return map[string]string{
		"credential_id":   "AKIAEXAMPLE",
		"credential_type": "aws_access_key",
		"domain":          "123456789012",
		"status":          "ACTIVE",
		"user":            "arn:aws:iam::123456789012:user/admin",
		"subject_id":      "AIDADEV",
		"subject_type":    "user",
	}
}

func identityExternalGroupTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":         "writer.okta.com",
		"group_id":       "grp-security",
		"group_name":     "Security",
		"member_email":   "external@gmail.com",
		"member_status":  "ACTIVE",
		"member_type":    "user",
		"member_user_id": "00u-external",
	}
}

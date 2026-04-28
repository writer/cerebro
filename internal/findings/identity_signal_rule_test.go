package findings

import (
	"context"
	"slices"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestIdentitySignalRulesEmitJoinBackedFindings(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-role-assignment-1",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.role_assignment",
		Attributes: map[string]string{
			"domain":       "writer.com",
			"role_id":      "super-admin",
			"subject_id":   "1001",
			"subject_type": "user",
		},
	}
	records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_admin_role:super-admin")
	if got := records[0].Attributes["primary_actor_urn"]; got != "urn:cerebro:writer:google_workspace_user:1001" {
		t.Fatalf("primary_actor_urn = %q, want google workspace user", got)
	}
}

func TestIdentitySignalRulesJoinExternalGroupMemberToIdentifier(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "okta-runtime", SourceId: "okta", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-group-member-external",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.group_membership",
		Attributes: map[string]string{
			"domain":         "writer.okta.com",
			"group_id":       "grp-security",
			"member_email":   "external@gmail.com",
			"member_user_id": "00u-external",
			"member_type":    "user",
		},
	}
	records, err := rules[identityExternalGroupMemberRuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:okta_user:00u-external")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:okta_group:grp-security")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:external@gmail.com")
}

func TestIdentitySignalRulesDetectPrivilegedNoMFAUser(t *testing.T) {
	rules := identityRulesByID(t)
	runtime := &cerebrov1.SourceRuntime{Id: "google-workspace-runtime", SourceId: "google_workspace", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "google-user-admin-no-mfa",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.user",
		Attributes: map[string]string{
			"domain":        "writer.com",
			"email":         "admin@writer.com",
			"is_admin":      "true",
			"mfa_enrolled":  "false",
			"primary_email": "admin@writer.com",
			"user_id":       "1001",
		},
	}
	records, err := rules[identityPrivilegedAccountWithoutMFARuleID].Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:google_workspace_user:1001")
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:admin@writer.com")
}

func TestIdentitySignalRulesDetectCloudRoleAssignments(t *testing.T) {
	rules := identityRulesByID(t)
	for _, tt := range []struct {
		name        string
		sourceID    string
		kind        string
		attributes  map[string]string
		resourceURN string
	}{
		{
			name:     "aws",
			sourceID: "aws",
			kind:     "aws.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "123456789012",
				"role_id":       "AdministratorAccess",
				"role_name":     "AdministratorAccess",
				"subject_email": "admin@writer.com",
				"subject_id":    "AIDAADMIN",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:writer:aws_admin_role:AdministratorAccess",
		},
		{
			name:     "gcp",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "writer-prod",
				"role_id":       "roles/owner",
				"role_name":     "roles/owner",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
			},
			resourceURN: "urn:cerebro:writer:gcp_admin_role:roles/owner",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			assertFindingResourceURN(t, records[0].ResourceURNs, tt.resourceURN)
			assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:identifier:email:admin@writer.com")
		})
	}
}

func TestIdentitySignalRulesIgnoreReadOnlyCloudRoleAssignments(t *testing.T) {
	rules := identityRulesByID(t)
	for _, tt := range []struct {
		name       string
		sourceID   string
		kind       string
		attributes map[string]string
	}{
		{
			name:     "aws-readonly",
			sourceID: "aws",
			kind:     "aws.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "123456789012",
				"is_admin":      "false",
				"role_id":       "ReadOnlyAccess",
				"role_name":     "ReadOnlyAccess",
				"subject_email": "analyst@writer.com",
				"subject_id":    "analyst@writer.com",
				"subject_type":  "user",
			},
		},
		{
			name:     "gcp-viewer",
			sourceID: "gcp",
			kind:     "gcp.iam_role_assignment",
			attributes: map[string]string{
				"domain":        "writer-prod",
				"is_admin":      "false",
				"role_id":       "roles/viewer",
				"role_name":     "roles/viewer",
				"subject_email": "viewer@writer.com",
				"subject_id":    "viewer@writer.com",
				"subject_type":  "user",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{Id: tt.name + "-runtime", SourceId: tt.sourceID, TenantId: "writer"}
			event := &cerebrov1.EventEnvelope{Id: tt.name + "-role-assignment", TenantId: "writer", SourceId: tt.sourceID, Kind: tt.kind, Attributes: tt.attributes}
			records, err := rules[identityAdminPrivilegeGrantedRuleID].Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("len(records) = %d, want 0", len(records))
			}
		})
	}
}

func identityRulesByID(t *testing.T) map[string]Rule {
	t.Helper()
	rules := map[string]Rule{}
	for _, rule := range newIdentitySignalRules() {
		rules[rule.Spec().GetId()] = rule
	}
	return rules
}

func assertFindingResourceURN(t *testing.T, urns []string, expected string) {
	t.Helper()
	if !slices.Contains(urns, expected) {
		t.Fatalf("ResourceURNs missing %q: %v", expected, urns)
	}
}

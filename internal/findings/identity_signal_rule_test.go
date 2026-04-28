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

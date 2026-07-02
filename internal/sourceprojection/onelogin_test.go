package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestOneloginIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "onelogin", Kind: "onelogin.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := oneloginUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestOneloginIdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "onelogin", Kind: "onelogin.groups", Attributes: map[string]string{"group_id": "group-1", "group_email": "group@example.test", "group_name": "Group One"}}
	entities, _, err := oneloginGroupsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}

func TestOneloginAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "onelogin", Kind: "onelogin.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := oneloginAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func TestOneloginRuntimeDepthProjections(t *testing.T) {
	cases := []struct {
		name      string
		project   func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
		attrs     map[string]string
		wantLinks bool
	}{
		{
			name:    "roles",
			project: oneloginRolesProjections,
			attrs:   map[string]string{"group_id": "role-1", "group_name": "Role One", "role_id": "role-1"},
		},
		{
			name:    "apps",
			project: oneloginAppsProjections,
			attrs:   map[string]string{"app_id": "app-1", "app_name": "App One", "sign_on_mode": "saml"},
		},
		{
			name:      "user_apps",
			project:   oneloginUserAppsProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "app_id": "app-1", "app_name": "App One"},
			wantLinks: true,
		},
		{
			name:      "app_users",
			project:   oneloginAppUsersProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "subject_email": "user@example.test", "app_id": "app-1"},
			wantLinks: true,
		},
		{
			name:      "role_users",
			project:   oneloginRoleUsersProjections,
			attrs:     map[string]string{"group_id": "role-1", "member_user_id": "user-1", "member_email": "user@example.test", "member_type": "user"},
			wantLinks: true,
		},
		{
			name:      "mfa_devices",
			project:   oneloginMFADevicesProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "credential_id": "device-1", "credential_type": "OneLogin Protect"},
			wantLinks: true,
		},
		{
			name:      "privileges",
			project:   oneloginPrivilegesProjections,
			attrs:     map[string]string{"role_id": "privilege-1", "role_name": "User Administrator", "role_type": "privilege", "is_admin": "true", "entitlement_id": "privilege-1"},
			wantLinks: true,
		},
		{
			name:      "user_privileges",
			project:   oneloginUserPrivilegesProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "role_id": "privilege-1", "role_name": "User Administrator", "role_type": "privilege", "is_admin": "true"},
			wantLinks: true,
		},
		{
			name:      "delegated_privileges",
			project:   oneloginDelegatedPrivilegesProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "role_id": "privilege-1", "role_name": "User Administrator", "role_type": "delegated_privilege", "is_admin": "true"},
			wantLinks: true,
		},
		{
			name:      "role_admins",
			project:   oneloginRoleAdminsProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "role_id": "role-1", "role_name": "Directory Administrator", "role_type": "admin_role", "is_admin": "true"},
			wantLinks: true,
		},
		{
			name:      "role_apps",
			project:   oneloginRoleAppsProjections,
			attrs:     map[string]string{"subject_id": "role-1", "subject_type": "group", "app_id": "app-1", "app_name": "App One"},
			wantLinks: true,
		},
		{
			name:      "mappings",
			project:   oneloginMappingsProjections,
			attrs:     map[string]string{"policy_id": "user_mappings", "policy_rule_id": "mapping-1", "policy_name": "User mappings", "name": "Assign sales role", "group_include_ids": "group-1"},
			wantLinks: true,
		},
		{
			name:      "app_rules",
			project:   oneloginAppRulesProjections,
			attrs:     map[string]string{"policy_id": "app-1", "policy_rule_id": "rule-1", "policy_name": "OneLogin app rules", "name": "Require mapping"},
			wantLinks: true,
		},
		{
			name:      "privilege_users",
			project:   oneloginPrivilegeUsersProjections,
			attrs:     map[string]string{"subject_id": "user-1", "subject_type": "user", "role_id": "privilege-1", "role_type": "privilege", "is_admin": "true"},
			wantLinks: true,
		},
		{
			name:      "privilege_roles",
			project:   oneloginPrivilegeRolesProjections,
			attrs:     map[string]string{"subject_id": "role-1", "subject_type": "group", "role_id": "privilege-1", "role_type": "privilege", "is_admin": "true"},
			wantLinks: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "onelogin", Kind: "onelogin." + tc.name, Attributes: tc.attrs}
			entities, links, err := tc.project(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if len(entities) == 0 {
				t.Fatalf("entities = 0, want projection for %s", tc.name)
			}
			if tc.wantLinks && len(links) == 0 {
				t.Fatalf("links = 0, want graph links for %s", tc.name)
			}
		})
	}
}

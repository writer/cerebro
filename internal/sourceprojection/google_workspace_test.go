package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGoogleWorkspaceUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "google_workspace", Kind: "google_workspace.user", Attributes: map[string]string{"domain": "example.test", "user_id": "1001", "email": "admin@example.test", "primary_email": "admin@example.test", "display_name": "Admin User", "is_admin": "true", "mfa_enrolled": "false"}}
	entities, _, err := googleWorkspaceUserProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected Workspace user")
	}
}

func TestGoogleWorkspaceGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "google_workspace", Kind: "google_workspace.group", Attributes: map[string]string{"domain": "example.test", "group_id": "group-1", "group_email": "security@example.test", "group_name": "Security"}}
	entities, _, err := googleWorkspaceGroupProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected Workspace group")
	}
}

func TestGoogleWorkspaceGroupMemberProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "google_workspace", Kind: "google_workspace.group_member", Attributes: map[string]string{"domain": "example.test", "group_id": "security@example.test", "group_email": "security@example.test", "member_id": "1001", "member_email": "admin@example.test", "member_type": "user", "role": "OWNER"}}
	entities, links, err := googleWorkspaceGroupMemberProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want membership projection", len(entities), len(links))
	}
}

func TestGoogleWorkspaceRoleAssignmentProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "google_workspace", Kind: "google_workspace.role_assignment", Attributes: map[string]string{"domain": "example.test", "role_id": "super-admin", "subject_id": "1001", "subject_email": "admin@example.test", "subject_type": "user"}}
	entities, links, err := googleWorkspaceRoleAssignmentProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want role assignment projection", len(entities), len(links))
	}
}

func TestGoogleWorkspaceAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "google_workspace", Kind: "google_workspace.audit", Attributes: map[string]string{"domain": "example.test", "event_type": "CHANGE_TWO_STEP_VERIFICATION_ENFORCEMENT", "actor_id": "1001", "actor_email": "admin@example.test", "resource_id": "two_step", "resource_type": "security_setting"}}
	entities, links, err := googleWorkspaceAuditProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

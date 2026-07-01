package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestJiraIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "jira", Kind: "jira.users", Attributes: map[string]string{"user_id": "acct-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := jiraUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	assertJiraEntity(t, entities, projectionURN("tenant", "jira_user", "acct-1"), "jira.user")
}

func TestJiraGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "jira", Kind: "jira.groups", Attributes: map[string]string{"group_id": "group-1", "group_name": "jira-administrators"}}
	entities, _, err := jiraGroupsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	assertJiraEntity(t, entities, projectionURN("tenant", "jira_group", "group-1"), "jira.group")
}

func TestJiraGroupMembershipProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "jira", Kind: "jira.group_members", Attributes: map[string]string{"group_id": "group-1", "member_user_id": "acct-1", "member_email": "user@example.test", "member_name": "User One"}}
	entities, links, err := jiraGroupMembersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	userURN := projectionURN("tenant", "jira_user", "acct-1")
	groupURN := projectionURN("tenant", "jira_group", "group-1")
	assertJiraEntity(t, entities, userURN, "jira.user")
	assertJiraEntity(t, entities, groupURN, "jira.group")
	assertJiraLink(t, links, userURN, relationMemberOf, groupURN)
}

func TestJiraProjectProjectionLinksLeadAndEvidence(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "jira", Kind: "jira.projects", Attributes: map[string]string{"project_id": "10001", "project_key": "ENG", "project_name": "Engineering", "lead_user_id": "acct-lead", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := jiraProjectsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	projectURN := projectionURN("tenant", "jira_project", "10001")
	leadURN := projectionURN("tenant", "jira_user", "acct-lead")
	assertJiraEntity(t, entities, projectURN, "jira.project")
	assertJiraLink(t, links, projectURN, relationOwnedBy, leadURN)
	assertJiraLink(t, links, projectURN, relationHasEvidence, projectionURN("tenant", "runtime_evidence", "evidence-1"))
}

func TestJiraProjectRoleProjectionLinksRoleActors(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant",
		SourceId: "jira",
		Kind:     "jira.project_roles",
		Attributes: map[string]string{
			"admin":             "true",
			"project_id_or_key": "ENG",
			"role_id":           "10002",
			"role_name":         "Administrators",
		},
		Payload: []byte(`{"id":10002,"name":"Administrators","actors":[{"id":20001,"type":"atlassian-user-role-actor","displayName":"User One","actorUser":{"accountId":"acct-1"}},{"id":20002,"type":"atlassian-group-role-actor","displayName":"jira-administrators","actorGroup":{"groupId":"group-1","name":"jira-administrators"}}]}`),
	}
	entities, links, err := jiraProjectRolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	roleURN := projectionURN("tenant", "jira_admin_role", "ENG:10002")
	globalRoleURN := projectionURN("tenant", "jira_role", "10002")
	projectURN := projectionURN("tenant", "jira_project", "ENG")
	userURN := projectionURN("tenant", "jira_user", "acct-1")
	groupURN := projectionURN("tenant", "jira_group", "group-1")
	assertJiraEntity(t, entities, roleURN, "jira.admin_role")
	assertJiraEntity(t, entities, globalRoleURN, "jira.role")
	assertJiraLink(t, links, roleURN, relationRepresents, globalRoleURN)
	assertJiraLink(t, links, roleURN, relationBelongsTo, projectURN)
	assertJiraLink(t, links, userURN, relationCanAdmin, roleURN)
	assertJiraLink(t, links, groupURN, relationCanAdmin, roleURN)
}

func TestJiraPermissionSchemeProjectionLinksGrantsAndHolders(t *testing.T) {
	event := &cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "tenant",
		SourceId: "jira",
		Kind:     "jira.permission_schemes",
		Attributes: map[string]string{
			"policy_id":   "1001",
			"policy_name": "Default Permission Scheme",
			"policy_type": "permission_scheme",
		},
		Payload: []byte(`{"id":1001,"name":"Default Permission Scheme","permissions":[{"id":10,"permission":"BROWSE_PROJECTS","holder":{"type":"group","parameter":"group-1","value":"jira-administrators"}},{"id":11,"permission":"ADMINISTER_PROJECTS","holder":{"type":"projectRole","parameter":"10002","value":"Administrators"}}]}`),
	}
	entities, links, err := jiraPermissionSchemesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	policyURN := projectionURN("tenant", "jira_permission_scheme", "1001")
	groupURN := projectionURN("tenant", "jira_group", "jira-administrators")
	grantURN := projectionURN("tenant", "jira_permission_grant", "1001", "10")
	roleURN := projectionURN("tenant", "jira_role", "10002")
	roleGrantURN := projectionURN("tenant", "jira_permission_grant", "1001", "11")
	assertJiraEntity(t, entities, policyURN, "jira.permission_scheme")
	assertJiraEntity(t, entities, grantURN, "jira.permission_grant")
	assertJiraEntity(t, entities, roleURN, "jira.role")
	assertJiraLink(t, links, policyURN, relationGrantsEntitlement, grantURN)
	assertJiraLink(t, links, groupURN, relationCanPerform, grantURN)
	assertJiraLink(t, links, roleURN, relationCanPerform, roleGrantURN)
}

func TestJiraAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "jira", Kind: "jira.audit_events", Attributes: map[string]string{"event_type": "Project updated", "actor_id": "acct-1", "resource_id": "10001", "resource_name": "Engineering", "resource_type": "project"}}
	entities, links, err := jiraAuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
	assertJiraLink(t, links, projectionURN("tenant", "jira_user", "acct-1"), relationActedOn, projectionURN("tenant", "jira_project", "10001"))
}

func assertJiraEntity(t *testing.T, entities []*ports.ProjectedEntity, urn string, entityType string) {
	t.Helper()
	for _, entity := range entities {
		if entity.URN == urn && entity.EntityType == entityType {
			return
		}
	}
	t.Fatalf("missing entity %s type %s in %#v", urn, entityType, entities)
}

func assertJiraLink(t *testing.T, links []*ports.ProjectedLink, from string, relation string, to string) {
	t.Helper()
	for _, link := range links {
		if link.FromURN == from && link.Relation == relation && link.ToURN == to {
			return
		}
	}
	t.Fatalf("missing link %s --%s--> %s in %#v", from, relation, to, links)
}

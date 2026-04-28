package sourceprojection

import (
	"context"
	"encoding/json"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type projectionRecorder struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (r *projectionRecorder) Ping(context.Context) error {
	return nil
}

func (r *projectionRecorder) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	if r.entities == nil {
		r.entities = make(map[string]*ports.ProjectedEntity)
	}
	r.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (r *projectionRecorder) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if r.links == nil {
		r.links = make(map[string]*ports.ProjectedLink)
	}
	r.links[projectedLinkKey(link)] = cloneProjectedLink(link)
	return nil
}

func TestProjectGitHubPullRequest(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Payload: mustJSON(t, map[string]any{
			"title": "Add Okta runtime sync",
		}),
		Attributes: map[string]string{
			"author":      "alice",
			"owner":       "writer",
			"pull_number": "447",
			"repository":  "writer/cerebro",
			"state":       "open",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 5 {
		t.Fatalf("Project().EntitiesProjected = %d, want 5", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("Project().LinksProjected = %d, want 4", result.LinksProjected)
	}

	prURN := "urn:cerebro:writer:github_pull_request:writer/cerebro#447"
	identifierURN := "urn:cerebro:writer:identifier:login:alice"
	if _, ok := state.entities[prURN]; !ok {
		t.Fatalf("state entity %q missing", prURN)
	}
	if _, ok := graph.entities[prURN]; !ok {
		t.Fatalf("graph entity %q missing", prURN)
	}
	if _, ok := state.links["urn:cerebro:writer:github_user:alice|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("state identifier link missing for %q", identifierURN)
	}
}

func TestProjectGitHubDependabotAlert(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-dependabot-alert-7",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.dependabot_alert",
		Attributes: map[string]string{
			"advisory_ghsa_id":   "GHSA-xxxx-yyyy-zzzz",
			"alert_number":       "7",
			"ecosystem":          "go",
			"owner":              "writer",
			"package":            "golang.org/x/crypto",
			"repo":               "cerebro",
			"repository":         "writer/cerebro",
			"severity":           "high",
			"state":              "open",
			"vulnerability_type": "dependabot",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 5 {
		t.Fatalf("Project().EntitiesProjected = %d, want 5", result.EntitiesProjected)
	}
	if result.LinksProjected != 4 {
		t.Fatalf("Project().LinksProjected = %d, want 4", result.LinksProjected)
	}

	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	repoURN := "urn:cerebro:writer:github_repo:writer/cerebro"
	advisoryURN := "urn:cerebro:writer:github_advisory:GHSA-xxxx-yyyy-zzzz"
	packageURN := "urn:cerebro:writer:package:go:golang.org/x/crypto"
	if _, ok := state.entities[alertURN]; !ok {
		t.Fatalf("state entity %q missing", alertURN)
	}
	if _, ok := graph.entities[alertURN]; !ok {
		t.Fatalf("graph entity %q missing", alertURN)
	}
	if _, ok := state.links[alertURN+"|"+relationBelongsTo+"|"+repoURN]; !ok {
		t.Fatal("alert repository link missing")
	}
	if _, ok := state.links[alertURN+"|"+relationAffectedBy+"|"+advisoryURN]; !ok {
		t.Fatal("alert advisory link missing")
	}
	if _, ok := state.links[alertURN+"|"+relationAffects+"|"+packageURN]; !ok {
		t.Fatal("alert package link missing")
	}
}

func TestProjectGitHubAuditSOTASignalsToGraph(t *testing.T) {
	events := []struct {
		id       string
		attrs    map[string]string
		resource string
	}{
		{
			id: "github-audit-secret-scanning-disabled",
			attrs: map[string]string{
				"action":        "repository_secret_scanning.disable",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository_secret_scanning",
			},
			resource: "urn:cerebro:writer:github_repo:writer/cerebro",
		},
		{
			id: "github-audit-org-auth-modified",
			attrs: map[string]string{
				"action":        "org.disable_two_factor_requirement",
				"resource_id":   "writer",
				"resource_type": "org",
			},
			resource: "urn:cerebro:writer:github_resource:org:writer",
		},
		{
			id: "github-audit-ip-allow-list-disabled",
			attrs: map[string]string{
				"action":        "ip_allow_list.disable",
				"resource_id":   "writer",
				"resource_type": "ip_allow_list",
			},
			resource: "urn:cerebro:writer:github_resource:ip_allow_list:writer",
		},
		{
			id: "github-audit-app-installed",
			attrs: map[string]string{
				"action":        "integration_installation.create",
				"name":          "ci-deployer",
				"resource_id":   "writer",
				"resource_type": "integration_installation",
			},
			resource: "urn:cerebro:writer:github_resource:integration_installation:writer",
		},
		{
			id: "github-audit-pat-created",
			attrs: map[string]string{
				"action":        "personal_access_token.access_granted",
				"resource_id":   "octocat",
				"resource_type": "personal_access_token",
				"user":          "octocat",
			},
			resource: "urn:cerebro:writer:github_resource:personal_access_token:octocat",
		},
		{
			id: "github-audit-branch-policy-override",
			attrs: map[string]string{
				"action":        "protected_branch.policy_override",
				"branch":        "main",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "protected_branch",
			},
			resource: "urn:cerebro:writer:github_repo:writer/cerebro",
		},
		{
			id: "github-audit-ruleset-modified",
			attrs: map[string]string{
				"action":        "repository_ruleset.destroy",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository_ruleset",
				"ruleset_id":    "42",
				"ruleset_name":  "main protections",
			},
			resource: "urn:cerebro:writer:github_repo:writer/cerebro",
		},
		{
			id: "github-audit-webhook-modified",
			attrs: map[string]string{
				"action":        "hook.create",
				"hook_id":       "99",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "hook",
			},
			resource: "urn:cerebro:writer:github_repo:writer/cerebro",
		},
	}
	for _, tt := range events {
		t.Run(tt.id, func(t *testing.T) {
			state := &projectionRecorder{}
			graph := &projectionRecorder{}
			attrs := map[string]string{
				"actor": "admin",
				"org":   "writer",
			}
			for key, value := range tt.attrs {
				attrs[key] = value
			}
			_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         tt.id,
				TenantId:   "writer",
				SourceId:   "github",
				Kind:       "github.audit",
				Attributes: attrs,
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			actorURN := "urn:cerebro:writer:github_user:admin"
			if _, ok := graph.entities[actorURN]; !ok {
				t.Fatalf("graph actor %q missing", actorURN)
			}
			if _, ok := graph.entities[tt.resource]; !ok {
				t.Fatalf("graph resource %q missing", tt.resource)
			}
			if _, ok := graph.links[actorURN+"|"+relationActedOn+"|"+tt.resource]; !ok {
				t.Fatalf("graph acted_on link missing for %s -> %s: %#v", actorURN, tt.resource, graph.links)
			}
		})
	}
}

func TestProjectReusesCrossSourceIdentifierWithinTenant(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "github-audit-1",
			TenantId: "writer",
			SourceId: "github",
			Kind:     "github.audit",
			Attributes: map[string]string{
				"actor":         "alice@writer.com",
				"org":           "writer",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
			},
		},
		{
			Id:       "okta-user-1",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.user",
			Attributes: map[string]string{
				"domain":  "writer.okta.com",
				"email":   "alice@writer.com",
				"login":   "alice@writer.com",
				"status":  "ACTIVE",
				"user_id": "00u1",
			},
		},
	}

	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	if _, ok := state.entities[identifierURN]; !ok {
		t.Fatalf("identifier entity %q missing", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:github_user:alice@writer.com|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("github identifier link missing for %q", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:okta_user:00u1|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("okta identifier link missing for %q", identifierURN)
	}
}

func TestProjectIdentityProviderJoinEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "okta-user-admin",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.user",
			Attributes: map[string]string{
				"domain":  "writer.okta.com",
				"email":   "admin@writer.com",
				"login":   "admin@writer.com",
				"status":  "ACTIVE",
				"user_id": "00u-admin",
			},
		},
		{
			Id:       "google-user-admin",
			TenantId: "writer",
			SourceId: "google_workspace",
			Kind:     "google_workspace.user",
			Attributes: map[string]string{
				"domain":        "writer.com",
				"email":         "admin@writer.com",
				"primary_email": "admin@writer.com",
				"user_id":       "1001",
				"is_admin":      "true",
				"mfa_enrolled":  "false",
			},
		},
		{
			Id:       "google-admin-role",
			TenantId: "writer",
			SourceId: "google_workspace",
			Kind:     "google_workspace.role_assignment",
			Attributes: map[string]string{
				"domain":       "writer.com",
				"role_id":      "super-admin",
				"subject_id":   "1001",
				"subject_type": "user",
			},
		},
		{
			Id:       "aws-user-admin",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.iam_user",
			Attributes: map[string]string{
				"domain":       "123456789012",
				"email":        "admin@writer.com",
				"is_admin":     "true",
				"login":        "admin@writer.com",
				"mfa_enrolled": "false",
				"user_id":      "AIDAADMIN",
			},
		},
		{
			Id:       "aws-admin-policy",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.iam_role_assignment",
			Attributes: map[string]string{
				"domain":        "123456789012",
				"role_id":       "AdministratorAccess",
				"role_name":     "AdministratorAccess",
				"subject_email": "admin@writer.com",
				"subject_id":    "AIDAADMIN",
				"subject_type":  "user",
			},
		},
		{
			Id:       "gcp-owner-binding",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.iam_role_assignment",
			Attributes: map[string]string{
				"domain":        "writer-prod",
				"role_id":       "roles/owner",
				"role_name":     "roles/owner",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
			},
		},
		{
			Id:       "okta-group",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.group",
			Attributes: map[string]string{
				"domain":     "writer.okta.com",
				"group_id":   "grp-security",
				"group_name": "Security",
			},
		},
		{
			Id:       "okta-membership",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.group_membership",
			Attributes: map[string]string{
				"domain":         "writer.okta.com",
				"group_id":       "grp-security",
				"member_email":   "admin@writer.com",
				"member_user_id": "00u-admin",
				"member_type":    "user",
			},
		},
		{
			Id:       "google-group",
			TenantId: "writer",
			SourceId: "google_workspace",
			Kind:     "google_workspace.group",
			Attributes: map[string]string{
				"domain":      "writer.com",
				"group_id":    "group-1",
				"group_email": "security@writer.com",
				"group_name":  "Security",
			},
		},
		{
			Id:       "google-member",
			TenantId: "writer",
			SourceId: "google_workspace",
			Kind:     "google_workspace.group_member",
			Attributes: map[string]string{
				"domain":       "writer.com",
				"group_id":     "security@writer.com",
				"group_email":  "security@writer.com",
				"member_email": "admin@writer.com",
				"member_id":    "1001",
				"member_type":  "user",
				"role":         "OWNER",
			},
		},
		{
			Id:       "okta-app",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.application",
			Attributes: map[string]string{
				"app_id":   "app-prod",
				"app_name": "Production Console",
				"domain":   "writer.okta.com",
			},
		},
		{
			Id:       "okta-app-assignment",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.app_assignment",
			Attributes: map[string]string{
				"app_id":        "app-prod",
				"domain":        "writer.okta.com",
				"subject_email": "admin@writer.com",
				"subject_id":    "00u-admin",
				"subject_type":  "user",
			},
		},
		{
			Id:       "google-audit",
			TenantId: "writer",
			SourceId: "google_workspace",
			Kind:     "google_workspace.audit",
			Attributes: map[string]string{
				"actor_email":   "admin@writer.com",
				"actor_id":      "1001",
				"domain":        "writer.com",
				"event_type":    "CHANGE_TWO_STEP_VERIFICATION_ENFORCEMENT",
				"resource_id":   "two_step",
				"resource_type": "security_setting",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	identifierURN := "urn:cerebro:writer:identifier:email:admin@writer.com"
	oktaUserURN := "urn:cerebro:writer:okta_user:00u-admin"
	googleUserURN := "urn:cerebro:writer:google_workspace_user:1001"
	awsUserURN := "urn:cerebro:writer:aws_user:AIDAADMIN"
	gcpUserURN := "urn:cerebro:writer:gcp_user:admin@writer.com"
	assertProjectedLink(t, state, oktaUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, googleUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, awsUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, gcpUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, oktaUserURN, relationMemberOf, "urn:cerebro:writer:okta_group:grp-security")
	assertProjectedLink(t, state, googleUserURN, relationMemberOf, "urn:cerebro:writer:google_workspace_group:security@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:google_workspace_group:security@writer.com", relationHasIdentifier, "urn:cerebro:writer:identifier:email:security@writer.com")
	assertProjectedLink(t, state, oktaUserURN, relationAssignedTo, "urn:cerebro:writer:okta_application:app-prod")
	assertProjectedLink(t, state, googleUserURN, relationCanAdmin, "urn:cerebro:writer:google_workspace_admin_role:super-admin")
	assertProjectedLink(t, state, awsUserURN, relationCanAdmin, "urn:cerebro:writer:aws_admin_role:AdministratorAccess")
	assertProjectedLink(t, state, gcpUserURN, relationCanAdmin, "urn:cerebro:writer:gcp_admin_role:roles/owner")
	assertProjectedLink(t, state, googleUserURN, relationActedOn, "urn:cerebro:writer:google_workspace_security_setting:two_step")
}

func TestProjectCloudReadOnlyRoleAssignmentsAvoidAdminEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-readonly-policy",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.iam_role_assignment",
			Attributes: map[string]string{
				"domain":        "123456789012",
				"role_id":       "ReadOnlyAccess",
				"role_name":     "ReadOnlyAccess",
				"subject_email": "analyst@writer.com",
				"subject_id":    "analyst@writer.com",
				"subject_type":  "user",
			},
		},
		{
			Id:       "gcp-viewer-binding",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.iam_role_assignment",
			Attributes: map[string]string{
				"domain":        "writer-prod",
				"role_id":       "roles/viewer",
				"role_name":     "roles/viewer",
				"subject_email": "viewer@writer.com",
				"subject_id":    "viewer@writer.com",
				"subject_type":  "user",
			},
		},
		{
			Id:       "gcp-service-account",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.service_account",
			Attributes: map[string]string{
				"domain":         "writer-prod",
				"email":          "sa@writer-prod.iam.gserviceaccount.com",
				"principal_type": "service_account",
				"unique_id":      "sa-1",
				"user_id":        "sa@writer-prod.iam.gserviceaccount.com",
			},
		},
		{
			Id:       "gcp-service-owner",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.iam_role_assignment",
			Attributes: map[string]string{
				"domain":        "writer-prod",
				"is_admin":      "true",
				"role_id":       "roles/owner",
				"role_name":     "roles/owner",
				"subject_email": "sa@writer-prod.iam.gserviceaccount.com",
				"subject_id":    "sa@writer-prod.iam.gserviceaccount.com",
				"subject_type":  "service_account",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationAssignedTo, "urn:cerebro:writer:aws_role:ReadOnlyAccess")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationCanAdmin, "urn:cerebro:writer:aws_admin_role:ReadOnlyAccess")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_user:viewer@writer.com", relationAssignedTo, "urn:cerebro:writer:gcp_role:roles/viewer")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:gcp_user:viewer@writer.com", relationCanAdmin, "urn:cerebro:writer:gcp_admin_role:roles/viewer")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com", relationCanAdmin, "urn:cerebro:writer:gcp_admin_role:roles/owner")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com", relationHasIdentifier, "urn:cerebro:writer:identifier:email:sa@writer-prod.iam.gserviceaccount.com")
}

func assertProjectedLink(t *testing.T, recorder *projectionRecorder, fromURN string, relation string, toURN string) {
	t.Helper()
	key := fromURN + "|" + relation + "|" + toURN
	if _, ok := recorder.links[key]; !ok {
		t.Fatalf("projected link %q missing; links=%v", key, recorder.links)
	}
}

func assertProjectedLinkMissing(t *testing.T, recorder *projectionRecorder, fromURN string, relation string, toURN string) {
	t.Helper()
	key := fromURN + "|" + relation + "|" + toURN
	if _, ok := recorder.links[key]; ok {
		t.Fatalf("projected link %q unexpectedly present; links=%v", key, recorder.links)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return payload
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}

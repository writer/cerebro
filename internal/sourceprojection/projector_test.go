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
	if result.EntitiesProjected != 6 {
		t.Fatalf("Project().EntitiesProjected = %d, want 6", result.EntitiesProjected)
	}
	if result.LinksProjected != 6 {
		t.Fatalf("Project().LinksProjected = %d, want 6", result.LinksProjected)
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
		{
			Id:       "aws-cloudtrail-sso",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.cloudtrail",
			Attributes: map[string]string{
				"actor_alternate_id": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com",
				"actor_id":           "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com",
				"actor_type":         "AssumedRole",
				"domain":             "123456789012",
				"event_type":         "ListRoles",
				"resource_id":        "123456789012",
				"resource_type":      "account",
			},
		},
	}

	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	canonicalIdentityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	if _, ok := state.entities[identifierURN]; !ok {
		t.Fatalf("identifier entity %q missing", identifierURN)
	}
	if _, ok := state.entities[canonicalIdentityURN]; !ok {
		t.Fatalf("canonical identity entity %q missing", canonicalIdentityURN)
	}
	if _, ok := state.links["urn:cerebro:writer:github_user:alice@writer.com|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("github identifier link missing for %q", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:okta_user:00u1|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("okta identifier link missing for %q", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:github_user:alice@writer.com|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("github canonical identity link missing for %q", canonicalIdentityURN)
	}
	if _, ok := state.links["urn:cerebro:writer:okta_user:00u1|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("okta canonical identity link missing for %q", canonicalIdentityURN)
	}
	awsActorURN := "urn:cerebro:writer:aws_user:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com"
	if _, ok := state.links[awsActorURN+"|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("aws canonical identity link missing for %q", canonicalIdentityURN)
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
	canonicalIdentityURN := "urn:cerebro:writer:identity:email:admin@writer.com"
	oktaUserURN := "urn:cerebro:writer:okta_user:00u-admin"
	googleUserURN := "urn:cerebro:writer:google_workspace_user:1001"
	awsUserURN := "urn:cerebro:writer:aws_user:AIDAADMIN"
	gcpUserURN := "urn:cerebro:writer:gcp_user:admin@writer.com"
	assertProjectedLink(t, state, oktaUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, googleUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, awsUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, gcpUserURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, state, oktaUserURN, relationRepresentsIdentity, canonicalIdentityURN)
	assertProjectedLink(t, state, googleUserURN, relationRepresentsIdentity, canonicalIdentityURN)
	assertProjectedLink(t, state, awsUserURN, relationRepresentsIdentity, canonicalIdentityURN)
	assertProjectedLink(t, state, gcpUserURN, relationRepresentsIdentity, canonicalIdentityURN)
	assertProjectedLink(t, state, canonicalIdentityURN, relationHasIdentifier, identifierURN)
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
		{
			Id:       "aws-access-key",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.access_key",
			Attributes: map[string]string{
				"credential_id":   "AKIAEXAMPLE",
				"credential_type": "aws_access_key",
				"domain":          "123456789012",
				"subject_email":   "analyst@writer.com",
				"subject_id":      "analyst@writer.com",
				"subject_type":    "user",
			},
		},
		{
			Id:       "gcp-service-key",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.service_account_key",
			Attributes: map[string]string{
				"credential_id":   "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
				"credential_type": "gcp_service_account_key",
				"domain":          "writer-prod",
				"subject_email":   "sa@writer-prod.iam.gserviceaccount.com",
				"subject_id":      "sa@writer-prod.iam.gserviceaccount.com",
				"subject_type":    "service_account",
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
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationAssignedTo, "urn:cerebro:writer:aws_credential:AKIAEXAMPLE")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com", relationAssignedTo, "urn:cerebro:writer:gcp_credential:projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1")
}

func TestProjectAzureIdentityEdges(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "azure-user-admin",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.user",
			Attributes: map[string]string{
				"domain":         "tenant-1",
				"email":          "admin@writer.com",
				"login":          "admin@writer.com",
				"mfa_enrolled":   "false",
				"principal_type": "user",
				"user_id":        "user-1",
			},
		},
		{
			Id:       "azure-group",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.group",
			Attributes: map[string]string{
				"domain":      "tenant-1",
				"group_email": "security@writer.com",
				"group_id":    "group-1",
				"group_name":  "Security",
			},
		},
		{
			Id:       "azure-member",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.group_membership",
			Attributes: map[string]string{
				"domain":       "tenant-1",
				"group_id":     "group-1",
				"member_email": "admin@writer.com",
				"member_id":    "user-1",
				"member_type":  "user",
			},
		},
		{
			Id:       "azure-app",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.application",
			Attributes: map[string]string{
				"app_id":   "app-client-1",
				"app_name": "Prod App",
				"domain":   "tenant-1",
			},
		},
		{
			Id:       "azure-sp",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.service_principal",
			Attributes: map[string]string{
				"app_id":         "app-client-1",
				"display_name":   "Prod App",
				"domain":         "tenant-1",
				"login":          "app-client-1",
				"principal_type": "service_principal",
				"user_id":        "sp-1",
			},
		},
		{
			Id:       "azure-global-admin",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.directory_role_assignment",
			Attributes: map[string]string{
				"domain":        "tenant-1",
				"is_admin":      "true",
				"role_id":       "global-admin",
				"role_name":     "Global Administrator",
				"role_type":     "azure_directory_role",
				"subject_email": "admin@writer.com",
				"subject_id":    "user-1",
				"subject_type":  "user",
			},
		},
		{
			Id:       "azure-reader",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.iam_role_assignment",
			Attributes: map[string]string{
				"domain":       "tenant-1",
				"is_admin":     "false",
				"role_id":      "Reader",
				"role_name":    "Reader",
				"role_type":    "azure_rbac_role",
				"subject_id":   "sp-1",
				"subject_type": "service_principal",
			},
		},
		{
			Id:       "azure-credential",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.credential",
			Attributes: map[string]string{
				"credential_id":   "app-password-1",
				"credential_type": "azure_application_password",
				"domain":          "tenant-1",
				"subject_id":      "app-client-1",
				"subject_type":    "application",
			},
		},
		{
			Id:       "azure-audit",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.directory_audit",
			Attributes: map[string]string{
				"actor_email":   "admin@writer.com",
				"actor_id":      "user-1",
				"domain":        "tenant-1",
				"event_type":    "Update conditional access policy",
				"resource_id":   "policy-1",
				"resource_type": "conditional_access_policy",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	azureUserURN := "urn:cerebro:writer:azure_user:user-1"
	azureServicePrincipalURN := "urn:cerebro:writer:azure_service_principal:sp-1"
	azureApplicationURN := "urn:cerebro:writer:azure_application:app-client-1"
	assertProjectedLink(t, state, azureUserURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:admin@writer.com")
	assertProjectedLink(t, state, azureUserURN, relationMemberOf, "urn:cerebro:writer:azure_group:group-1")
	assertProjectedLink(t, state, azureUserURN, relationCanAdmin, "urn:cerebro:writer:azure_admin_role:global-admin")
	assertProjectedLink(t, state, azureServicePrincipalURN, relationAssignedTo, azureApplicationURN)
	assertProjectedLink(t, state, azureServicePrincipalURN, relationAssignedTo, "urn:cerebro:writer:azure_role:Reader")
	assertProjectedLinkMissing(t, state, azureServicePrincipalURN, relationCanAdmin, "urn:cerebro:writer:azure_admin_role:Reader")
	assertProjectedLink(t, state, azureApplicationURN, relationAssignedTo, "urn:cerebro:writer:azure_credential:app-password-1")
	assertProjectedLink(t, state, azureUserURN, relationActedOn, "urn:cerebro:writer:azure_conditional_access_policy:policy-1")
}

func TestProjectCloudExposureAndPrivilegePaths(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-public-sg",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.resource_exposure",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"exposed_to":        "public_internet",
				"exposure_id":       "sg-1-0",
				"exposure_type":     "public_network_ingress",
				"family":            "resource_exposure",
				"internet_exposed":  "true",
				"resource_id":       "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
				"resource_name":     "prod-web",
				"resource_provider": "aws",
				"resource_type":     "security_group",
				"source_cidr":       "0.0.0.0/0",
			},
		},
		{
			Id:       "aws-role-trust",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.iam_role_trust",
			Attributes: map[string]string{
				"domain":       "123456789012",
				"path_type":    "assume_role_trust",
				"relationship": "can_assume",
				"subject_id":   "arn:aws:iam::999999999999:role/ExternalAdmin",
				"subject_type": "role",
				"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
				"target_name":  "AdminRole",
				"target_type":  "role",
			},
		},
		{
			Id:       "gcp-impersonation",
			TenantId: "writer",
			SourceId: "gcp",
			Kind:     "gcp.service_account_impersonation",
			Attributes: map[string]string{
				"domain":        "writer-prod",
				"path_type":     "service_account_impersonation",
				"relationship":  "can_impersonate",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
				"target_email":  "sa@writer-prod.iam.gserviceaccount.com",
				"target_id":     "sa@writer-prod.iam.gserviceaccount.com",
				"target_type":   "service_account",
			},
		},
		{
			Id:       "azure-app-role",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.app_role_assignment",
			Attributes: map[string]string{
				"domain":       "tenant-1",
				"path_type":    "app_role_assignment",
				"relationship": "assigned_to",
				"role_id":      "role-1",
				"subject_id":   "sp-1",
				"subject_type": "service_principal",
				"target_id":    "sp-resource-1",
				"target_type":  "service_principal",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, "urn:cerebro:writer:aws_security_group:arn:aws:ec2:us-east-1:123456789012:security-group/sg-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_role:arn:aws:iam::999999999999:role/ExternalAdmin", relationCanAssume, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_user:admin@writer.com", relationCanImpersonate, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_service_principal:sp-1", relationAssignedTo, "urn:cerebro:writer:azure_service_principal:sp-resource-1")
}

func TestProjectEffectivePermissionsKubernetesRuntimeAndData(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-effective-admin",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.effective_permission",
			Attributes: map[string]string{
				"actions":       "*",
				"domain":        "123456789012",
				"effect":        "allow",
				"is_admin":      "true",
				"resource_id":   "123456789012",
				"resource_type": "account",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
			},
		},
		{
			Id:       "k8s-workload",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"cluster_id":           "prod-cluster",
				"namespace":            "payments",
				"service_account_name": "api",
				"workload_kind":        "Deployment",
				"workload_name":        "payments-api",
				"workload_uid":         "workload-1",
			},
		},
		{
			Id:       "k8s-workload-identity",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload_identity_binding",
			Attributes: map[string]string{
				"cloud_provider":       "gcp",
				"cluster_id":           "prod-cluster",
				"namespace":            "payments",
				"path_type":            "workload_identity",
				"relationship":         "can_impersonate",
				"service_account_name": "api",
				"target_email":         "payments-sa@writer-prod.iam.gserviceaccount.com",
				"target_id":            "payments-sa@writer-prod.iam.gserviceaccount.com",
				"target_type":          "service_account",
			},
		},
		{
			Id:       "runtime-evidence",
			TenantId: "writer",
			SourceId: "runtime",
			Kind:     "runtime.evidence",
			Attributes: map[string]string{
				"confidence":    "0.92",
				"evidence_id":   "evidence-1",
				"evidence_type": "credential_use",
				"resource_urn":  "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1",
				"verdict":       "confirmed",
			},
		},
		{
			Id:       "asset-crown-jewel",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.crown_jewel",
			Attributes: map[string]string{
				"contains_secrets":    "true",
				"crown_jewel":         "true",
				"data_classification": "restricted",
				"resource_id":         "prod-secrets",
				"resource_name":       "Production Secrets",
				"resource_type":       "secret_store",
				"source_provider":     "aws",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:admin@writer.com", relationCanPerform, "urn:cerebro:writer:aws_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1", relationRunsAs, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api", relationCanImpersonate, "urn:cerebro:writer:gcp_service_account:payments-sa@writer-prod.iam.gserviceaccount.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1", relationHasEvidence, "urn:cerebro:writer:runtime_evidence:evidence-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:runtime_evidence:evidence-1", relationObservedOn, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationHasClassification, "urn:cerebro:writer:data_classification:restricted")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationTaggedAs, "urn:cerebro:writer:asset_tag:crown_jewel")
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

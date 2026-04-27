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

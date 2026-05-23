package sourceprojection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type projectionRecorder struct {
	entities        map[string]*ports.ProjectedEntity
	links           map[string]*ports.ProjectedLink
	deletedEntities map[string]struct{}
	deletedLinks    map[string]*ports.ProjectedLink
	cleanupRequests []ports.ProjectionCleanupRequest
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

func (r *projectionRecorder) DeleteProjectedEntity(_ context.Context, urn string) error {
	if r.deletedEntities == nil {
		r.deletedEntities = make(map[string]struct{})
	}
	r.deletedEntities[urn] = struct{}{}
	delete(r.entities, urn)
	for key, link := range r.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(r.links, key)
		}
	}
	return nil
}

func (r *projectionRecorder) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	key := projectedLinkKey(link)
	if r.deletedLinks == nil {
		r.deletedLinks = map[string]*ports.ProjectedLink{}
	}
	r.deletedLinks[key] = cloneProjectedLink(link)
	if r.links != nil {
		delete(r.links, key)
	}
	return nil
}

func (r *projectionRecorder) CleanupProjectedEntities(_ context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	r.cleanupRequests = append(r.cleanupRequests, request)
	var result ports.ProjectionCleanupResult
	limit := cleanupBatchLimit(request)
	for urn, entity := range r.entities {
		if result.EntitiesDeleted >= limit {
			break
		}
		if !projectionRecorderCleanupMatches(request, entity) {
			continue
		}
		delete(r.entities, urn)
		result.EntitiesDeleted++
	}
	for key, link := range r.links {
		if _, ok := r.entities[link.FromURN]; !ok {
			delete(r.links, key)
			result.LinksDeleted++
			continue
		}
		if _, ok := r.entities[link.ToURN]; !ok {
			delete(r.links, key)
			result.LinksDeleted++
		}
	}
	return result, nil
}

func projectionRecorderCleanupMatches(request ports.ProjectionCleanupRequest, entity *ports.ProjectedEntity) bool {
	if request.TenantID != "" && entity.TenantID != request.TenantID {
		return false
	}
	if request.SourceID != "" && entity.SourceID != request.SourceID {
		return false
	}
	if request.RuntimeID != "" && entity.RuntimeID != request.RuntimeID {
		return false
	}
	if len(request.EntityTypes) != 0 {
		matchedType := false
		for _, entityType := range request.EntityTypes {
			if entity.EntityType == entityType {
				matchedType = true
				break
			}
		}
		if !matchedType {
			return false
		}
	}
	if len(request.URNPrefixes) == 0 {
		return true
	}
	for _, prefix := range request.URNPrefixes {
		if strings.HasPrefix(entity.URN, prefix) {
			return true
		}
	}
	return false
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

func TestProjectStampsRuntimeIDOnEntitiesAndLinks(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Attributes: map[string]string{
			"author":                            "alice",
			"owner":                             "writer",
			"pull_number":                       "447",
			"repository":                        "writer/cerebro",
			ports.EventAttributeSourceRuntimeID: "writer-github",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	for urn, entity := range state.entities {
		if got := entity.RuntimeID; got != "writer-github" {
			t.Fatalf("state entity %q RuntimeID = %q, want writer-github", urn, got)
		}
		if got := entity.Attributes[ports.EventAttributeSourceRuntimeID]; got != "writer-github" {
			t.Fatalf("state entity %q source_runtime_id = %q, want writer-github", urn, got)
		}
	}
	for key, link := range graph.links {
		if got := link.RuntimeID; got != "writer-github" {
			t.Fatalf("graph link %q RuntimeID = %q, want writer-github", key, got)
		}
		if got := link.Attributes[ports.EventAttributeSourceRuntimeID]; got != "writer-github" {
			t.Fatalf("graph link %q source_runtime_id = %q, want writer-github", key, got)
		}
	}
}

func TestProjectGitHubPullRequestWithoutOwnerDoesNotLinkEmptyOrg(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Attributes: map[string]string{
			"pull_number": "447",
			"repository":  "writer/cerebro",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	emptyOrgURN := "urn:cerebro:writer:github_org:"
	if _, ok := state.entities[emptyOrgURN]; ok {
		t.Fatalf("empty org entity %q should not be projected", emptyOrgURN)
	}
	for key := range state.links {
		if strings.Contains(key, emptyOrgURN) {
			t.Fatalf("empty org link %q should not be projected", key)
		}
	}
}

func TestProjectGitHubPullRequestWithoutRepositoryDoesNotLinkPlaceholderPR(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Attributes: map[string]string{
			"author":      "alice",
			"pull_number": "447",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	for key := range state.links {
		if strings.Contains(key, "github_pull_request:#447") {
			t.Fatalf("placeholder pull request link %q should not be projected", key)
		}
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
			"advisory_cve_id":    "CVE-2025-12345",
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
	if result.EntitiesProjected != 7 {
		t.Fatalf("Project().EntitiesProjected = %d, want 7", result.EntitiesProjected)
	}
	if result.LinksProjected != 8 {
		t.Fatalf("Project().LinksProjected = %d, want 8", result.LinksProjected)
	}

	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	repoURN := "urn:cerebro:writer:github_repo:writer/cerebro"
	advisoryURN := "urn:cerebro:writer:github_advisory:GHSA-xxxx-yyyy-zzzz"
	packageURN := "urn:cerebro:writer:package:go:golang.org/x/crypto"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:golang.org/x/crypto"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2025-12345"
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
	if _, ok := state.links[alertURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]; !ok {
		t.Fatal("alert canonical vulnerability link missing")
	}
	if _, ok := state.links[packageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]; !ok {
		t.Fatal("package canonical vulnerability link missing")
	}
	if _, ok := state.links[packageURN+"|"+relationRepresents+"|"+canonicalPackageURN]; !ok {
		t.Fatal("package canonical identity link missing")
	}
	if _, ok := state.links[canonicalPackageURN+"|"+relationAffectedBy+"|"+vulnerabilityURN]; !ok {
		t.Fatal("canonical package vulnerability link missing")
	}
}

func TestProjectOktaOAuthGrantAsApplicationTelemetry(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-oauth-grant",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":               "writer.okta.com",
			"event_type":           "app.oauth2.token.grant.access_token",
			"actor_id":             "0oa-client",
			"actor_type":           "PublicClientApp",
			"actor_display_name":   "Production Client",
			"resource_id":          "00u-user",
			"resource_type":        "User",
			"oauth_client_id":      "0oa-client",
			"oauth_client_label":   "Production Client",
			"oauth_client_type":    "PublicClientApp",
			"oauth_event_category": "runtime_grant",
			"grant_type":           "access_token",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	clientURN := "urn:cerebro:writer:okta_application:0oa-client"
	userURN := "urn:cerebro:writer:okta_user:00u-user"
	entity, ok := state.entities[clientURN]
	if !ok {
		t.Fatalf("OAuth client entity %q missing", clientURN)
	}
	if got := entity.Attributes["oauth_event_category"]; got != "runtime_grant" {
		t.Fatalf("oauth_event_category = %q, want runtime_grant", got)
	}
	assertProjectedLink(t, state, clientURN, relationActedOn, userURN)
	assertProjectedLink(t, state, clientURN, relationBelongsTo, "urn:cerebro:writer:okta_org:writer.okta.com")
}

func TestProjectOktaPolicyRule(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-policy-rule-pol-1-rul-1",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.policy_rule",
		Attributes: map[string]string{
			"policy_id":      "pol-1",
			"policy_rule_id": "rul-1",
			"policy_type":    "OKTA_SIGN_ON",
			"name":           "Require MFA",
			"status":         "INACTIVE",
			"priority":       "1",
			"system":         "false",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 1 {
		t.Fatalf("Project().EntitiesProjected = %d, want 1", result.EntitiesProjected)
	}

	wantURN := "urn:cerebro:writer:okta_policy_rule:pol-1:rul-1"
	entity, ok := state.entities[wantURN]
	if !ok {
		t.Fatalf("state entity %q missing", wantURN)
	}
	if got := entity.EntityType; got != "okta.policy_rule" {
		t.Fatalf("EntityType = %q, want okta.policy_rule", got)
	}
	if got := entity.Label; got != "Require MFA" {
		t.Fatalf("Label = %q, want Require MFA", got)
	}
	wantAttributes := map[string]string{
		"policy_id":      "pol-1",
		"policy_rule_id": "rul-1",
		"policy_type":    "OKTA_SIGN_ON",
		"name":           "Require MFA",
		"status":         "INACTIVE",
		"priority":       "1",
		"system":         "false",
	}
	for key, want := range wantAttributes {
		if got := entity.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestProjectOktaAuditSuppressesEphemeralOAuthResources(t *testing.T) {
	tests := []struct {
		name         string
		eventType    string
		resourceType string
		grantType    string
		category     string
	}{
		{
			name:         "access token",
			eventType:    "app.oauth2.token.grant.access_token",
			resourceType: "access_token",
			grantType:    "access_token",
			category:     "runtime_grant",
		},
		{
			name:         "camel case access token",
			eventType:    "app.oauth2.token.grant.access_token",
			resourceType: "AccessToken",
			grantType:    "access_token",
			category:     "runtime_grant",
		},
		{
			name:         "kebab case access token with event fallback",
			eventType:    "app.oauth2.token.grant.access_token",
			resourceType: "access-token",
			grantType:    "access_token",
		},
		{
			name:         "refresh token",
			eventType:    "app.oauth2.token.grant.refresh_token",
			resourceType: "refresh_token",
			grantType:    "refresh_token",
			category:     "runtime_grant",
		},
		{
			name:         "authorization code with event fallback",
			eventType:    "app.oauth2.authorize.code",
			resourceType: "AuthorizationCode",
			grantType:    "authorization_code",
		},
		{
			name:         "id token",
			eventType:    "app.oauth2.token.grant.id_token",
			resourceType: "IdToken",
			grantType:    "id_token",
			category:     "runtime_grant",
		},
		{
			name:         "code",
			eventType:    "app.oauth2.authorize.code",
			resourceType: "code",
			grantType:    "authorization_code",
			category:     "runtime_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)

			_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:       "okta-oauth-token",
				TenantId: "writer",
				SourceId: "okta",
				Kind:     "okta.audit",
				Attributes: map[string]string{
					"domain":               "writer.okta.com",
					"event_type":           tt.eventType,
					"actor_id":             "0oa-client",
					"actor_type":           "PublicClientApp",
					"actor_display_name":   "Production Client",
					"resource_id":          "token-123",
					"resource_type":        tt.resourceType,
					"oauth_client_id":      "0oa-client",
					"oauth_client_label":   "Production Client",
					"oauth_client_type":    "PublicClientApp",
					"oauth_event_category": tt.category,
					"grant_type":           tt.grantType,
				},
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}

			clientURN := "urn:cerebro:writer:okta_application:0oa-client"
			actorURN := "urn:cerebro:writer:okta_actor:publicclientapp:0oa-client"
			resourceURN := oktaResourceURN("writer", tt.resourceType, "token-123")
			if _, ok := state.entities[resourceURN]; ok {
				t.Fatalf("ephemeral resource entity %q unexpectedly projected", resourceURN)
			}
			assertProjectedLinkMissing(t, state, clientURN, relationActedOn, resourceURN)
			assertProjectedLinkMissing(t, state, actorURN, relationActedOn, resourceURN)
			assertProjectedLinkMissing(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:okta_org:writer.okta.com")
			assertProjectedLink(t, state, actorURN, relationActedOn, clientURN)

			link := state.links[actorURN+"|"+relationActedOn+"|"+clientURN]
			if got := link.Attributes["grant_type"]; got != tt.grantType {
				t.Fatalf("grant_type = %q, want %q", got, tt.grantType)
			}
			if tt.category != "" {
				if got := link.Attributes["oauth_event_category"]; got != tt.category {
					t.Fatalf("oauth_event_category = %q, want %q", got, tt.category)
				}
			}
		})
	}
}

func TestProjectOktaAuditDeletesPreviouslyProjectedEphemeralOAuthResource(t *testing.T) {
	resourceURN := "urn:cerebro:writer:okta_resource:access_token:token-123"
	clientURN := "urn:cerebro:writer:okta_application:0oa-client"
	oldLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "okta",
		FromURN:  clientURN,
		Relation: relationActedOn,
		ToURN:    resourceURN,
	}
	state := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{resourceURN: {
			URN:        resourceURN,
			TenantID:   "writer",
			SourceID:   "okta",
			EntityType: "okta.resource",
			Label:      "token-123",
		}},
		links: map[string]*ports.ProjectedLink{projectedLinkKey(oldLink): oldLink},
	}
	graph := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{resourceURN: {
			URN:        resourceURN,
			TenantID:   "writer",
			SourceID:   "okta",
			EntityType: "okta.resource",
			Label:      "token-123",
		}},
		links: map[string]*ports.ProjectedLink{projectedLinkKey(oldLink): oldLink},
	}
	service := New(state, graph)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-oauth-token",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":               "writer.okta.com",
			"event_type":           "app.oauth2.token.grant.access_token",
			"actor_id":             "0oa-client",
			"actor_type":           "PublicClientApp",
			"actor_display_name":   "Production Client",
			"resource_id":          "token-123",
			"resource_type":        "access_token",
			"oauth_client_id":      "**********",
			"oauth_client_label":   "Production Client",
			"oauth_client_type":    "PublicClientApp",
			"oauth_event_category": "runtime_grant",
			"grant_type":           "access_token",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesDeleted != 1 {
		t.Fatalf("EntitiesDeleted = %d, want 1", result.EntitiesDeleted)
	}
	for name, recorder := range map[string]*projectionRecorder{"state": state, "graph": graph} {
		if _, ok := recorder.deletedEntities[resourceURN]; !ok {
			t.Fatalf("%s did not delete %q", name, resourceURN)
		}
		if _, ok := recorder.entities[resourceURN]; ok {
			t.Fatalf("%s retained deleted entity %q", name, resourceURN)
		}
		if _, ok := recorder.links[projectedLinkKey(oldLink)]; ok {
			t.Fatalf("%s retained deleted link %q", name, projectedLinkKey(oldLink))
		}
	}
}

func TestProjectOktaAuditRunsScopedEphemeralOAuthResourceCleanup(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:access_token:old-token"
	otherRuntimeURN := "urn:cerebro:writer:okta_resource:access_token:other-runtime-token"
	clientURN := "urn:cerebro:writer:okta_application:0oa-client"
	oldLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "okta",
		FromURN:  clientURN,
		Relation: relationActedOn,
		ToURN:    staleURN,
	}
	graph := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{
			clientURN: {
				URN:        clientURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.application",
				Label:      "Production Client",
			},
			staleURN: {
				URN:        staleURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "old-token",
			},
			otherRuntimeURN: {
				URN:        otherRuntimeURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "other-runtime",
				EntityType: "okta.resource",
				Label:      "other-runtime-token",
			},
		},
		links: map[string]*ports.ProjectedLink{projectedLinkKey(oldLink): oldLink},
	}
	service := New(nil, graph)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-oauth-token",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "okta-audit-runtime",
			"domain":                            "writer.okta.com",
			"event_type":                        "app.oauth2.token.grant.access_token",
			"actor_id":                          "0oa-client",
			"actor_type":                        "PublicClientApp",
			"actor_display_name":                "Production Client",
			"resource_id":                       "token-123",
			"resource_type":                     "access_token",
			"oauth_client_id":                   "**********",
			"oauth_client_label":                "Production Client",
			"oauth_client_type":                 "PublicClientApp",
			"oauth_event_category":              "runtime_grant",
			"grant_type":                        "access_token",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesDeleted == 0 {
		t.Fatalf("EntitiesDeleted = 0, want cleanup deletions")
	}
	if got := len(graph.cleanupRequests); got != 1 {
		t.Fatalf("cleanup requests = %d, want 1", got)
	}
	request := graph.cleanupRequests[0]
	if request.TenantID != "writer" || request.SourceID != "okta" || request.RuntimeID != "okta-audit-runtime" {
		t.Fatalf("cleanup request scope = (%q, %q, %q), want writer/okta/okta-audit-runtime", request.TenantID, request.SourceID, request.RuntimeID)
	}
	if !stringSliceContains(request.EntityTypes, "okta.resource") {
		t.Fatalf("cleanup request entity types = %#v, want okta.resource", request.EntityTypes)
	}
	if !stringSliceContains(request.URNPrefixes, "urn:cerebro:writer:okta_resource:access_token:") {
		t.Fatalf("cleanup request prefixes = %#v, missing access_token prefix", request.URNPrefixes)
	}
	if _, ok := graph.entities[staleURN]; ok {
		t.Fatalf("stale scoped cleanup entity %q still present", staleURN)
	}
	if _, ok := graph.links[projectedLinkKey(oldLink)]; ok {
		t.Fatalf("stale scoped cleanup link still present")
	}
	if _, ok := graph.entities[otherRuntimeURN]; !ok {
		t.Fatalf("other runtime token was deleted")
	}
}

func TestProjectOktaAuditRunsScopedEphemeralOAuthCleanupOnNonGrantEvent(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:refresh_token:old-token"
	state := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{
			staleURN: {
				URN:        staleURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "old-token",
			},
		},
	}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-user-update",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "okta-audit-runtime",
			"domain":                            "writer.okta.com",
			"event_type":                        "user.account.update_profile",
			"actor_id":                          "00u-admin",
			"actor_type":                        "User",
			"resource_id":                       "00u-user",
			"resource_type":                     "User",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesDeleted == 0 {
		t.Fatalf("EntitiesDeleted = 0, want cleanup deletions from non-grant event")
	}
	if got := len(state.cleanupRequests); got != 1 {
		t.Fatalf("state cleanup calls = %d, want 1", got)
	}
	if _, ok := state.entities[staleURN]; ok {
		t.Fatalf("state retained stale cleanup token")
	}
}

func TestCleanupProjectedEntitiesRepeatsUntilExhausted(t *testing.T) {
	graph := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-1": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-1",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-1",
			},
			"urn:cerebro:writer:okta_resource:access_token:token-2": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-2",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-2",
			},
		},
	}
	service := New(nil, graph)

	result, err := service.cleanupProjectedEntities(context.Background(), []ports.ProjectionCleanupRequest{{
		TenantID:    "writer",
		SourceID:    "okta",
		RuntimeID:   "okta-audit-runtime",
		EntityTypes: []string{"okta.resource"},
		URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
		Limit:       1,
	}})
	if err != nil {
		t.Fatalf("cleanupProjectedEntities() error = %v", err)
	}
	if result.EntitiesDeleted != 2 {
		t.Fatalf("EntitiesDeleted = %d, want 2", result.EntitiesDeleted)
	}
	if got := len(graph.cleanupRequests); got != 3 {
		t.Fatalf("cleanup calls = %d, want 3 calls to confirm exhaustion", got)
	}
	if len(graph.entities) != 0 {
		t.Fatalf("graph retained %d cleanup entities", len(graph.entities))
	}
}

func TestCleanupProjectedEntitiesRunsAgainstStateStore(t *testing.T) {
	state := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-1": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-1",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-1",
			},
		},
	}
	service := New(state, nil)

	result, err := service.cleanupProjectedEntities(context.Background(), []ports.ProjectionCleanupRequest{{
		TenantID:    "writer",
		SourceID:    "okta",
		RuntimeID:   "okta-audit-runtime",
		EntityTypes: []string{"okta.resource"},
		URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
		Limit:       1000,
	}})
	if err != nil {
		t.Fatalf("cleanupProjectedEntities() error = %v", err)
	}
	if result.EntitiesDeleted != 1 {
		t.Fatalf("EntitiesDeleted = %d, want 1", result.EntitiesDeleted)
	}
	if got := len(state.cleanupRequests); got != 1 {
		t.Fatalf("state cleanup calls = %d, want 1", got)
	}
	if len(state.entities) != 0 {
		t.Fatalf("state retained %d cleanup entities", len(state.entities))
	}
}

func TestProjectOktaAuditRunsScopedCleanupForLaterStaleResources(t *testing.T) {
	state := &projectionRecorder{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:stale-token": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:stale-token",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "stale-token",
			},
		},
	}
	service := New(state, nil)
	event := func(id string, resourceID string) *cerebrov1.EventEnvelope {
		return &cerebrov1.EventEnvelope{
			Id:       id,
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.audit",
			Attributes: map[string]string{
				ports.EventAttributeSourceRuntimeID: "okta-audit-runtime",
				"domain":                            "writer.okta.com",
				"event_type":                        "app.oauth2.token.grant.access_token",
				"actor_id":                          "0oa-client",
				"actor_type":                        "PublicClientApp",
				"actor_display_name":                "Production Client",
				"resource_id":                       resourceID,
				"resource_type":                     "access_token",
				"oauth_client_id":                   "**********",
				"oauth_client_label":                "Production Client",
				"oauth_client_type":                 "PublicClientApp",
				"oauth_event_category":              "runtime_grant",
				"grant_type":                        "access_token",
			},
		}
	}

	if _, err := service.Project(context.Background(), event("okta-oauth-token-1", "token-1")); err != nil {
		t.Fatalf("Project(first) error = %v", err)
	}
	state.entities["urn:cerebro:writer:okta_resource:access_token:later-stale-token"] = &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:okta_resource:access_token:later-stale-token",
		TenantID:   "writer",
		SourceID:   "okta",
		RuntimeID:  "okta-audit-runtime",
		EntityType: "okta.resource",
		Label:      "later-stale-token",
	}
	if _, err := service.Project(context.Background(), event("okta-oauth-token-2", "token-2")); err != nil {
		t.Fatalf("Project(second) error = %v", err)
	}
	if got := len(state.cleanupRequests); got != 2 {
		t.Fatalf("state cleanup calls = %d, want cleanup on each projection pass", got)
	}
	if len(state.entities) == 0 {
		return
	}
	for _, urn := range []string{
		"urn:cerebro:writer:okta_resource:access_token:stale-token",
		"urn:cerebro:writer:okta_resource:access_token:later-stale-token",
	} {
		if _, ok := state.entities[urn]; ok {
			t.Fatalf("state retained stale cleanup token %q", urn)
		}
	}
}

func TestProjectOktaAuditDoesNotSuppressBroadTokenResources(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-token-like-resource",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":               "writer.okta.com",
			"event_type":           "app.oauth2.token.grant.access_token",
			"actor_id":             "0oa-client",
			"actor_type":           "PublicClientApp",
			"resource_id":          "token-123",
			"resource_type":        "Token",
			"oauth_client_id":      "0oa-client",
			"oauth_client_label":   "Production Client",
			"oauth_client_type":    "PublicClientApp",
			"oauth_event_category": "runtime_grant",
			"grant_type":           "access_token",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	resourceURN := "urn:cerebro:writer:okta_resource:token:token-123"
	if _, ok := state.entities[resourceURN]; !ok {
		t.Fatalf("broad token resource entity %q missing", resourceURN)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:okta_application:0oa-client", relationActedOn, resourceURN)
}

func TestProjectOktaAuditKeepsCredentialChangeResources(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-api-token-create",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":               "writer.okta.com",
			"event_type":           "system.api_token.create",
			"actor_id":             "00u-admin",
			"actor_type":           "User",
			"actor_alternate_id":   "admin@writer.com",
			"resource_id":          "token-123",
			"resource_type":        "Token",
			"oauth_event_category": "credential_change",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	resourceURN := "urn:cerebro:writer:okta_resource:token:token-123"
	if _, ok := state.entities[resourceURN]; !ok {
		t.Fatalf("credential change resource entity %q missing", resourceURN)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:okta_user:00u-admin", relationActedOn, resourceURN)
}

func TestProjectOktaAuditSuppressesSelfActedOnEdge(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-self",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.audit",
		Attributes: map[string]string{
			"domain":             "writer.okta.com",
			"event_type":         "user.session.start",
			"actor_id":           "00u-user",
			"actor_type":         "User",
			"actor_alternate_id": "alice@writer.com",
			"resource_id":        "00u-user",
			"resource_type":      "User",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	userURN := "urn:cerebro:writer:okta_user:00u-user"
	assertProjectedLinkMissing(t, state, userURN, relationActedOn, userURN)
}

func TestProjectOktaAuditActedOnEdgesCarryTemporalContext(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.May, 12, 1, 2, 3, 0, time.UTC)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "okta-action",
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"domain":             "writer.okta.com",
			"event_type":         "user.lifecycle.update",
			"actor_id":           "00u-actor",
			"actor_type":         "User",
			"actor_alternate_id": "admin@writer.com",
			"resource_id":        "00u-target",
			"resource_type":      "User",
			"outcome_result":     "SUCCESS",
			"transaction_id":     "txn-1",
			"client_ip":          "203.0.113.10",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:okta_user:00u-actor"
	targetURN := "urn:cerebro:writer:okta_user:00u-target"
	link, ok := state.links[actorURN+"|"+relationActedOn+"|"+targetURN]
	if !ok {
		t.Fatalf("acted_on link missing for %s -> %s: %#v", actorURN, targetURN, state.links)
	}
	for key, want := range map[string]string{
		"at":             occurred.Format(time.RFC3339),
		"event_type":     "user.lifecycle.update",
		"outcome_result": "SUCCESS",
		"transaction_id": "txn-1",
		"client_ip":      "203.0.113.10",
	} {
		if got := link.Attributes[key]; got != want {
			t.Fatalf("link.Attributes[%q] = %q, want %q", key, got, want)
		}
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
			if strings.Contains(tt.resource, "github_repo") {
				attrs := graph.entities[tt.resource].Attributes
				if attrs["repository"] != "writer/cerebro" || attrs["resource_type"] != tt.attrs["resource_type"] {
					t.Fatalf("repo attributes = %#v, want repository and resource_type", attrs)
				}
			}
			if _, ok := graph.links[actorURN+"|"+relationActedOn+"|"+tt.resource]; !ok {
				t.Fatalf("graph acted_on link missing for %s -> %s: %#v", actorURN, tt.resource, graph.links)
			}
		})
	}
}

// TestProjectGitHubAuditStampsAtOnActedOn pins the contract that the projector
// writes the audit event's OccurredAt onto the github acted_on edge. The
// deprovisioned-Okta-active-in-GitHub rule treats the absence of `at` as
// "stale or pre-fix history" and refuses to fire on it, so dropping this stamp
// would cause real, current GitHub activity to look indistinguishable from
// pre-offboarding history and the rule would silently stop emitting findings.
func TestProjectGitHubAuditStampsAtOnActedOn(t *testing.T) {
	graph := &projectionRecorder{}
	occurred := time.Date(2025, time.March, 4, 10, 30, 0, 0, time.UTC)
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-acted-on-at",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "git.clone",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:github_user:alice"
	resourceURN := "urn:cerebro:writer:github_repo:writer/cerebro"
	link, ok := graph.links[actorURN+"|"+relationActedOn+"|"+resourceURN]
	if !ok {
		t.Fatalf("acted_on link missing for %s -> %s: %#v", actorURN, resourceURN, graph.links)
	}
	if got, want := link.Attributes["at"], occurred.Format(time.RFC3339); got != want {
		t.Fatalf("acted_on attributes[at] = %q, want %q (recency window in deprovisioned-okta rule depends on this stamp)", got, want)
	}
	if got, want := link.Attributes["action"], "git.clone"; got != want {
		t.Fatalf("acted_on attributes[action] = %q, want %q (preserving existing payload alongside `at`)", got, want)
	}
}

// represents_identity edges must also carry the OccurredAt as `at` so identity-
// aware rules can age out stale identifier links left behind by upsert-only
// graph ingest. The deprovisioned-Okta-active-in-GitHub rule joins through both
// the okta-side and github-side represents_identity edges; if either lacks `at`,
// the rule cannot prove the identifier link is current and refuses to fire.
func TestProjectGitHubAuditStampsAtOnRepresentsIdentity(t *testing.T) {
	graph := &projectionRecorder{}
	occurred := time.Date(2025, time.March, 4, 11, 15, 0, 0, time.UTC)
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-represents-identity-at",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "git.clone",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:github_user:alice"
	identityURN := "urn:cerebro:writer:identity:login:alice"
	link, ok := graph.links[actorURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", actorURN, identityURN, graph.links)
	}
	if got, want := link.Attributes["at"], occurred.Format(time.RFC3339); got != want {
		t.Fatalf("represents_identity attributes[at] = %q, want %q (rename-stale join filter depends on this)", got, want)
	}
}

// okta.user inventory events derive OccurredAt from profile-history fields
// (LastUpdated/Created/Activated/StatusChanged/LastLogin/PasswordChanged), so
// for any user whose profile has been static for longer than the graph-rule
// recency window the event arrives with an OccurredAt that is already older
// than that window. Stamping the represents_identity edge with that history
// timestamp makes a fresh inventory sync look stale to identity-aware rules
// and silently drops unchanged-but-deprovisioned offenders. The projector
// therefore stamps okta.user represents_identity edges with the projection's
// own clock, so any current inventory link is always recent regardless of
// when the user's profile was last edited.
func TestProjectOktaUserStampsObservationTimeOnRepresentsIdentity(t *testing.T) {
	graph := &projectionRecorder{}
	historicalProfileEdit := time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)
	before := time.Now().UTC()
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "okta-user-stale-profile",
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.user",
		OccurredAt: timestamppb.New(historicalProfileEdit),
		Attributes: map[string]string{
			"domain":  "writer.okta.com",
			"email":   "alice@writer.com",
			"login":   "alice@writer.com",
			"status":  "DEPROVISIONED",
			"user_id": "00u1",
		},
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	userURN := "urn:cerebro:writer:okta_user:00u1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	link, ok := graph.links[userURN+"|"+relationRepresentsIdentity+"|"+identityURN]
	if !ok {
		t.Fatalf("represents_identity link missing for %s -> %s: %#v", userURN, identityURN, graph.links)
	}
	raw, present := link.Attributes["at"]
	if !present || raw == "" {
		t.Fatalf("represents_identity attributes[at] missing; rule needs observation time to age out renamed identifier links")
	}
	stamped, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("represents_identity attributes[at] = %q is not RFC3339: %v", raw, err)
	}
	if stamped.Equal(historicalProfileEdit) {
		t.Fatalf("represents_identity attributes[at] = %q matches the historical profile timestamp; sources/okta sets event.OccurredAt from profile fields, so the projector must stamp observation time instead to keep unchanged-but-deprovisioned users in the recency window", raw)
	}
	// Allow a small clock-skew margin around the projection call.
	if stamped.Before(before.Add(-time.Second)) || stamped.After(after.Add(time.Second)) {
		t.Fatalf("represents_identity attributes[at] = %v not within projection window [%v, %v]; expected observation-time stamp", stamped, before, after)
	}
}

// TestProjectGitHubAuditOmitsAtWhenOccurredAtMissing covers the legacy contract:
// historical events backfilled without OccurredAt must not pollute the edge with
// a placeholder timestamp. The rule reads a missing `at` as "I cannot prove this
// is recent" and skips it; emitting a synthetic `at` would defeat that.
func TestProjectGitHubAuditOmitsAtWhenOccurredAtMissing(t *testing.T) {
	graph := &projectionRecorder{}
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-acted-on-no-at",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "git.clone",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:github_user:alice"
	resourceURN := "urn:cerebro:writer:github_repo:writer/cerebro"
	link, ok := graph.links[actorURN+"|"+relationActedOn+"|"+resourceURN]
	if !ok {
		t.Fatalf("acted_on link missing for %s -> %s: %#v", actorURN, resourceURN, graph.links)
	}
	if got, exists := link.Attributes["at"]; exists {
		t.Fatalf("acted_on attributes[at] = %q present without event OccurredAt; rule must be able to distinguish recent vs unstamped edges", got)
	}
}

func TestProjectGitHubAuditSkipsAutomationActorsFromIdentityGraph(t *testing.T) {
	cases := []struct {
		name  string
		actor string
		attrs map[string]string
	}{
		{
			name:  "actor_is_bot true",
			actor: "dependabot[bot]",
			attrs: map[string]string{"actor_is_bot": "true", "actor_type": "Bot"},
		},
		{
			name:  "bot suffix defense in depth",
			actor: "coderabbitai[bot]",
			attrs: map[string]string{"actor_is_bot": "false"},
		},
		{
			name:  "actor_type bot",
			actor: "renovate",
			attrs: map[string]string{"actor_type": "Bot"},
		},
		{
			name:  "actor_is_agent true",
			actor: "fine-grained-token-agent",
			attrs: map[string]string{"actor_is_agent": "true"},
		},
		{
			name:  "unresolved non public key",
			actor: "pullrequest[bot]",
			attrs: map[string]string{"actor_type": "Unresolved"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{
				"actor":         tc.actor,
				"action":        "repository_vulnerability_alert.create",
				"org":           "writer",
				"org_id":        "8090724",
				"repo":          "writer/cerebro",
				"resource_id":   "writer/cerebro",
				"resource_type": "repository",
			}
			for key, value := range tc.attrs {
				attrs[key] = value
			}
			graph := &projectionRecorder{}
			_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "github-audit-automation-" + tc.actor,
				TenantId:   "writer",
				SourceId:   "github",
				Kind:       "github.audit",
				OccurredAt: timestamppb.New(time.Date(2025, time.March, 4, 10, 30, 0, 0, time.UTC)),
				Attributes: attrs,
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			actorURN := "urn:cerebro:writer:github_user:" + tc.actor
			if _, ok := graph.entities[actorURN]; ok {
				t.Fatalf("automation actor %q should not be projected as github.user: %#v", actorURN, graph.entities[actorURN])
			}
			if _, ok := graph.links[actorURN+"|"+relationActedOn+"|urn:cerebro:writer:github_repo:writer/cerebro"]; ok {
				t.Fatalf("automation actor %q should not emit acted_on repo links", actorURN)
			}
			for key := range graph.links {
				if strings.HasPrefix(key, actorURN+"|") {
					t.Fatalf("automation actor %q emitted identity graph link %q", actorURN, key)
				}
			}
		})
	}
}

func TestProjectGitHubAuditSkipsSyntheticTargetUsersFromIdentityGraph(t *testing.T) {
	for _, targetLogin := range []string{"pullrequest[bot]", "Renovate[Bot]", "deploy_key", "deploy-key"} {
		t.Run(targetLogin, func(t *testing.T) {
			graph := &projectionRecorder{}
			_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "github-audit-target-" + targetLogin,
				TenantId:   "writer",
				SourceId:   "github",
				Kind:       "github.audit",
				OccurredAt: timestamppb.New(time.Date(2025, time.March, 4, 10, 30, 0, 0, time.UTC)),
				Attributes: map[string]string{
					"actor":         "alice",
					"action":        "team.add_member",
					"org":           "writer",
					"repo":          "writer/cerebro",
					"resource_id":   "writer/cerebro",
					"resource_type": "repository",
					"user":          targetLogin,
				},
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			targetURN := "urn:cerebro:writer:github_user:" + targetLogin
			if _, ok := graph.entities[targetURN]; ok {
				t.Fatalf("synthetic target %q should not be projected as github.user", targetURN)
			}
			for key := range graph.links {
				if strings.HasPrefix(key, targetURN+"|") {
					t.Fatalf("synthetic target %q emitted identity graph link %q", targetURN, key)
				}
			}
		})
	}
}

// Plain human-shaped target logins are still GitHub identities and must keep
// projecting into the identity graph. Target-context events legitimately have
// no actor_type because the audit event's actor_* fields describe the issuer,
// not the recipient.
func TestProjectGitHubAuditDoesNotStampActorTypeOnHumanTargetUser(t *testing.T) {
	graph := &projectionRecorder{}
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-target-human",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(time.Date(2025, time.March, 4, 10, 30, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "team.add_member",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
			"user":          "joechu-writer",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	targetURN := "urn:cerebro:writer:github_user:joechu-writer"
	entity, ok := graph.entities[targetURN]
	if !ok {
		t.Fatalf("github.user target entity %q missing in graph: %#v", targetURN, graph.entities)
	}
	if got, exists := entity.Attributes["actor_type"]; exists {
		t.Fatalf("target github.user attributes[actor_type] = %q present for human-shaped login; rule would silently suppress real shadow accounts", got)
	}
}

// `org_id` is a small but important field on the github.org node: it pins
// the numeric ID GitHub stamps on every audit event for the org. The rule
// uses it to disambiguate the org-as-actor pattern (where actor_id ==
// org_id and the event represents a system-level action with no human
// actor) from real user activity.
func TestProjectGitHubAuditStampsOrgIDOnGithubOrg(t *testing.T) {
	graph := &projectionRecorder{}
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-org-id",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "git.clone",
			"org":           "writer",
			"org_id":        "8090724",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	orgURN := "urn:cerebro:writer:github_org:writer"
	entity, ok := graph.entities[orgURN]
	if !ok {
		t.Fatalf("github.org entity %q missing", orgURN)
	}
	if got, want := entity.Attributes["org_id"], "8090724"; got != want {
		t.Fatalf("github.org attributes[org_id] = %q, want %q", got, want)
	}
}

// GitHub's audit log API names the org itself as the audit actor on
// system-level events (e.g. `integration_installation.version_updated`).
// The actor_id on those events equals the org_id, and there is no human
// user behind the action. Minting a `github.user:<org>` node would create
// a phantom identity that no rule could ever bridge back to Okta — the org
// is not a user. The projector must therefore route the acted_on edge
// from the github.org node and skip the github.user mint entirely,
// mirroring cartography's GitHubUser vs GitHubOrganization separation.
func TestProjectGitHubAuditRoutesActedOnFromOrgWhenActorIsOrgSelf(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-org-self",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(time.Date(2025, time.March, 4, 10, 30, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"actor":         "writer",
			"actor_id":      "8090724",
			"action":        "integration_installation.version_updated",
			"org":           "writer",
			"org_id":        "8090724",
			"resource_id":   "writer",
			"resource_type": "integration_installation",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	orgURN := "urn:cerebro:writer:github_org:writer"
	resourceURN := "urn:cerebro:writer:github_resource:integration_installation:writer"
	phantomUserURN := "urn:cerebro:writer:github_user:writer"
	if _, ok := graph.entities[phantomUserURN]; ok {
		t.Fatalf("phantom github.user %q minted for org-as-actor event; projector must route through github.org instead", phantomUserURN)
	}
	if _, ok := graph.entities[orgURN]; !ok {
		t.Fatalf("github.org entity %q missing", orgURN)
	}
	if _, ok := graph.entities[resourceURN]; !ok {
		t.Fatalf("resource entity %q missing", resourceURN)
	}
	link, ok := graph.links[orgURN+"|"+relationActedOn+"|"+resourceURN]
	if !ok {
		t.Fatalf("acted_on link missing for %s -> %s (org-as-actor must route the edge from github.org): %#v", orgURN, resourceURN, graph.links)
	}
	if got, want := link.Attributes["action"], "integration_installation.version_updated"; got != want {
		t.Fatalf("acted_on attributes[action] = %q, want %q", got, want)
	}
	if link.Attributes["at"] == "" {
		t.Fatalf("acted_on attributes[at] empty; rule needs the recency stamp on org-as-actor edges too")
	}
}

// When actor_id != org_id, the projector must continue to mint a github.user
// for the actor — this is the normal user-action path. A regression in the
// org-self detection (e.g. mis-comparing strings or treating empty IDs as
// equal) would silently drop every real user from the graph; this test
// pins the correct branch.
func TestProjectGitHubAuditMintsGithubUserWhenActorIsNotOrgSelf(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-user-actor",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":         "alice",
			"actor_id":      "111",
			"action":        "git.clone",
			"org":           "writer",
			"org_id":        "8090724",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:github_user:alice"
	resourceURN := "urn:cerebro:writer:github_repo:writer/cerebro"
	if _, ok := graph.entities[actorURN]; !ok {
		t.Fatalf("github.user entity %q missing for user actor; org-self detection must not trip when IDs differ", actorURN)
	}
	if _, ok := graph.links[actorURN+"|"+relationActedOn+"|"+resourceURN]; !ok {
		t.Fatalf("acted_on link missing for %s -> %s; user actor path must still mint the edge", actorURN, resourceURN)
	}
}

// Events arriving with no actor_id at all (e.g. backfilled legacy rows) must
// fall through to the user-actor mint, not the org-self routing. We
// explicitly require BOTH actor_id and org_id to be non-empty and equal
// before suppressing the github.user — equality of two empty strings would
// otherwise silently route every legacy event from github.org.
func TestProjectGitHubAuditDoesNotTreatMissingActorIDsAsOrgSelf(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-no-actor-id",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":         "alice",
			"action":        "git.clone",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	actorURN := "urn:cerebro:writer:github_user:alice"
	if _, ok := graph.entities[actorURN]; !ok {
		t.Fatalf("github.user entity %q missing; legacy events without actor_id must NOT be treated as org-as-actor", actorURN)
	}
}

// Git audit rows can name non-user credentials as the actor. Live data shows
// deploy-key access as actor=deploy_key, actor_id missing, user_id=0, and
// programmatic_access_type="Public Key (User/Deploy)"; /users/deploy_key
// returns 404, so the source stamps actor_type=Unresolved. The projector must
// preserve that access evidence as a github.credential, not as a
// github.user, otherwise identity rules will chase a non-user credential that
// can never have an Okta bridge.
func TestProjectGitHubAuditProjectsUnresolvedPublicKeyAsCredential(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	occurred := time.Date(2026, time.May, 9, 14, 56, 28, 0, time.UTC)
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-deploy-key",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"actor":                    "deploy_key",
			"actor_type":               "Unresolved",
			"action":                   "git.clone",
			"org":                      "WriterInternal",
			"org_id":                   "112636266",
			"programmatic_access_type": "Public Key (User/Deploy)",
			"repo":                     "WriterInternal/k8s",
			"resource_id":              "WriterInternal/k8s",
			"resource_type":            "repository",
			"transport_protocol_name":  "ssh",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	userURN := "urn:cerebro:writer:github_user:deploy_key"
	if _, ok := graph.entities[userURN]; ok {
		t.Fatalf("github.user %q minted for unresolved public-key credential; deploy keys must be modeled as credentials", userURN)
	}
	credentialURN := "urn:cerebro:writer:github_credential:deploy_key@WriterInternal/k8s"
	credential, ok := graph.entities[credentialURN]
	if !ok {
		t.Fatalf("github.credential entity %q missing: %#v", credentialURN, graph.entities)
	}
	if got, want := credential.EntityType, "github.credential"; got != want {
		t.Fatalf("credential entity_type = %q, want %q", got, want)
	}
	for key, want := range map[string]string{
		"actor":                    "deploy_key",
		"credential_type":          "public_key",
		"programmatic_access_type": "Public Key (User/Deploy)",
		"repository":               "WriterInternal/k8s",
		"transport_protocol_name":  "ssh",
	} {
		if got := credential.Attributes[key]; got != want {
			t.Fatalf("credential attributes[%s] = %q, want %q", key, got, want)
		}
	}
	resourceURN := "urn:cerebro:writer:github_repo:WriterInternal/k8s"
	link, ok := graph.links[credentialURN+"|"+relationActedOn+"|"+resourceURN]
	if !ok {
		t.Fatalf("acted_on link missing for credential %s -> %s: %#v", credentialURN, resourceURN, graph.links)
	}
	if got, want := link.Attributes["programmatic_access_type"], "Public Key (User/Deploy)"; got != want {
		t.Fatalf("acted_on attributes[programmatic_access_type] = %q, want %q", got, want)
	}
	if got, want := link.Attributes["at"], occurred.Format(time.RFC3339); got != want {
		t.Fatalf("acted_on attributes[at] = %q, want %q", got, want)
	}

	_, err = New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "github-audit-deploy-key-other-repo",
		TenantId:   "writer",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(occurred.Add(time.Minute)),
		Attributes: map[string]string{
			"actor":                    "deploy_key",
			"actor_type":               "Unresolved",
			"action":                   "git.clone",
			"org":                      "WriterInternal",
			"programmatic_access_type": "Public Key (User/Deploy)",
			"repo":                     "WriterInternal/other",
			"resource_id":              "WriterInternal/other",
			"resource_type":            "repository",
			"transport_protocol_name":  "ssh",
		},
	})
	if err != nil {
		t.Fatalf("Project() second repo error = %v", err)
	}
	otherCredentialURN := "urn:cerebro:writer:github_credential:deploy_key@WriterInternal/other"
	if _, ok := graph.entities[otherCredentialURN]; !ok {
		t.Fatalf("github.credential entity %q missing for same deploy_key actor on another repo", otherCredentialURN)
	}
}

// Missing actor_id alone is not enough to call an audit actor a credential:
// GitHub git audit rows for real users can also omit actor_id. The source
// resolves those actors through /users/{login} and stamps actor_type=User, and
// the projector must keep the normal github.user path so real user access is
// still evaluated by identity rules.
func TestProjectGitHubAuditKeepsResolvedUserPublicKeyAsGithubUser(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-user-public-key",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":                    "brandon-writer",
			"actor_type":               "User",
			"action":                   "git.push",
			"org":                      "WriterInternal",
			"org_id":                   "112636266",
			"programmatic_access_type": "Public Key (User/Deploy)",
			"repo":                     "WriterInternal/be.llm-gateway",
			"resource_id":              "WriterInternal/be.llm-gateway",
			"resource_type":            "repository",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	userURN := "urn:cerebro:writer:github_user:brandon-writer"
	if _, ok := graph.entities[userURN]; !ok {
		t.Fatalf("github.user %q missing for resolved User public-key actor", userURN)
	}
	for urn := range graph.entities {
		if strings.Contains(urn, "github_credential:brandon-writer") {
			t.Fatalf("github.credential %q minted for resolved User actor; public-key users must stay github.user identities", urn)
		}
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
				"actor":                    "alice",
				"external_identity_nameid": "alice@writer.com",
				"org":                      "writer",
				"repo":                     "writer/cerebro",
				"resource_id":              "writer/cerebro",
				"resource_type":            "repository",
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
	if _, ok := state.links["urn:cerebro:writer:github_user:alice|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("github identifier link missing for %q", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:okta_user:00u1|"+relationHasIdentifier+"|"+identifierURN]; !ok {
		t.Fatalf("okta identifier link missing for %q", identifierURN)
	}
	if _, ok := state.links["urn:cerebro:writer:github_user:alice|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("github canonical identity link missing for %q", canonicalIdentityURN)
	}
	if _, ok := state.links["urn:cerebro:writer:okta_user:00u1|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("okta canonical identity link missing for %q", canonicalIdentityURN)
	}
	awsActorURN := "urn:cerebro:writer:aws_user:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com"
	if _, ok := state.links[awsActorURN+"|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("aws canonical identity link missing for %q", canonicalIdentityURN)
	}
	githubIdentityLink := state.links["urn:cerebro:writer:github_user:alice|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]
	if got := githubIdentityLink.Attributes["evidence_type"]; got != "shared_identifier" {
		t.Fatalf("github identity evidence_type = %q, want shared_identifier", got)
	}
	if got := githubIdentityLink.Attributes["confidence"]; got != "0.95" {
		t.Fatalf("github identity confidence = %q, want 0.95", got)
	}
	if got := githubIdentityLink.Attributes["source_event_id"]; got != "github-audit-1" {
		t.Fatalf("github identity source_event_id = %q, want github-audit-1", got)
	}
	awsIdentityLink := state.links[awsActorURN+"|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]
	if got := awsIdentityLink.Attributes["match_type"]; got != "extracted_email" {
		t.Fatalf("aws identity match_type = %q, want extracted_email", got)
	}
	if got := awsIdentityLink.Attributes["confidence"]; got != "0.85" {
		t.Fatalf("aws identity confidence = %q, want 0.85", got)
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
			Id:       "aws-public-endpoint",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.public_endpoint",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"endpoint_id":       "eni-1",
				"endpoint_type":     "public_network_interface",
				"external_exposure": "true",
				"host":              "ec2-203-0-113-10.compute-1.amazonaws.com",
				"internet_exposed":  "true",
				"ip":                "203.0.113.10",
				"public":            "true",
				"resource_id":       "eni-1",
				"resource_name":     "prod-web-eni",
				"resource_provider": "aws",
				"resource_type":     "network_interface",
				"target_host":       "d111111abcdef8.cloudfront.net",
				"alternate_hosts":   "app.writer.com",
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
			Id:       "azure-public-nsg",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.resource_exposure",
			Attributes: map[string]string{
				"domain":            "tenant-1",
				"exposed_to":        "public_internet",
				"exposure_id":       "nsg-1-0",
				"exposure_type":     "public_network_ingress",
				"internet_exposed":  "true",
				"resource_id":       "nsg-1",
				"resource_name":     "prod-nsg",
				"resource_provider": "azure",
				"resource_type":     "network_security_group",
				"source_cidr":       "0.0.0.0/0",
				"subscription_id":   "sub-1",
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
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_security_group:arn:aws:ec2:us-east-1:123456789012:security-group/sg-1", relationCanReach, "urn:cerebro:writer:aws_public_principal:public_internet")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_security_group:arn:aws:ec2:us-east-1:123456789012:security-group/sg-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_network_security_group:nsg-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:azure_network_security_group:nsg-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:tenant-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, "urn:cerebro:writer:aws_network_interface:eni-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationCanReach, "urn:cerebro:writer:aws_public_principal:public_internet")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationRepresents, "urn:cerebro:writer:internet_host:ec2-203-0-113-10.compute-1.amazonaws.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationRepresents, "urn:cerebro:writer:internet_host:d111111abcdef8.cloudfront.net")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationRepresents, "urn:cerebro:writer:internet_host:app.writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationRepresents, "urn:cerebro:writer:internet_ip:203.0.113.10")
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
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_account:123456789012", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
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
		RuntimeID:  entity.RuntimeID,
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
		RuntimeID:  link.RuntimeID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}

func projectedLinkKey(link *ports.ProjectedLink) string {
	return link.FromURN + "|" + link.Relation + "|" + link.ToURN
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

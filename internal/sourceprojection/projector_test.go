package sourceprojection

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
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

func (r *projectionRecorder) GetProjectedEntity(_ context.Context, urn string) (*ports.ProjectedEntity, error) {
	if r == nil || r.entities == nil {
		return nil, nil
	}
	return cloneProjectedEntity(r.entities[urn]), nil
}

func (r *projectionRecorder) GetProjectedRuntimeEvidenceBySourceEvent(_ context.Context, tenantID string, sourceRuntimeID string, sourceEventID string) (*ports.ProjectedEntity, error) {
	if r == nil || r.entities == nil {
		return nil, nil
	}
	for _, entity := range r.entities {
		if entity == nil || entity.EntityType != "runtime.evidence" {
			continue
		}
		if entity.TenantID != tenantID {
			continue
		}
		if entity.Attributes[ports.EventAttributeSourceRuntimeID] != sourceRuntimeID {
			continue
		}
		if entity.Attributes["source_event_id"] != sourceEventID {
			continue
		}
		return cloneProjectedEntity(entity), nil
	}
	return nil, nil
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

func TestProjectionRetractionReason(t *testing.T) {
	cases := []struct {
		name  string
		links []*ports.ProjectedLink
		want  string
	}{
		{
			name: "cloudflare dns reassignment",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "cloudflare_dns_record_zone_reassigned"},
			}},
			want: "cloudflare_dns_record_zone_reassigned",
		},
		{
			name: "endpoint owner",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "endpoint_owner_id"},
			}},
			want: "endpoint_owner_id",
		},
		{
			name: "trivy resolved vulnerability",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "trivy_vulnerability_resolved"},
			}},
			want: "trivy_vulnerability_resolved",
		},
		{
			name: "tailscale deauthorized device",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "tailscale_device_deauthorized"},
			}},
			want: "tailscale_device_deauthorized",
		},
		{
			name: "tailscale disabled grant",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "tailscale_grant_disabled"},
			}},
			want: "tailscale_grant_disabled",
		},
		{
			name: "tailscale device blocks incoming",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "tailscale_device_blocks_incoming"},
			}},
			want: "tailscale_device_blocks_incoming",
		},
		{
			name: "mixed",
			links: []*ports.ProjectedLink{
				{Attributes: map[string]string{"retraction": "endpoint_owner_id"}},
				{Attributes: map[string]string{"retraction": "cloudflare_dns_record_zone_reassigned"}},
			},
			want: "mixed",
		},
		{
			name: "unknown",
			links: []*ports.ProjectedLink{{
				Attributes: map[string]string{"retraction": "legacy"},
			}},
			want: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectionRetractionReason(tc.links); got != tc.want {
				t.Fatalf("projectionRetractionReason() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIdentifierEvidenceAttributesMarksEmailAsGlobalCrossSource(t *testing.T) {
	attrs := identifierEvidenceAttributes(" Alice@Writer.COM ", "identifier.email", "alice@writer.com", "event-1", nil)

	if got := attrs["identity_quality"]; got != "stable_email" {
		t.Fatalf("identity_quality = %q, want stable_email", got)
	}
	if got := attrs["identity_scope"]; got != "global" {
		t.Fatalf("identity_scope = %q, want global", got)
	}
	if got := attrs["cross_source_identity"]; got != "true" {
		t.Fatalf("cross_source_identity = %q, want true", got)
	}
	if got := attrs["confidence"]; got != "0.95" {
		t.Fatalf("confidence = %q, want 0.95", got)
	}
}

func TestIdentifierEvidenceAttributesMarksLoginAsSourceLocalWeak(t *testing.T) {
	attrs := identifierEvidenceAttributes("alice", "identifier.login", "alice", "event-1", nil)

	if got := attrs["identity_quality"]; got != "weak_login" {
		t.Fatalf("identity_quality = %q, want weak_login", got)
	}
	if got := attrs["identity_scope"]; got != "source_local" {
		t.Fatalf("identity_scope = %q, want source_local", got)
	}
	if got := attrs["cross_source_identity"]; got != "false" {
		t.Fatalf("cross_source_identity = %q, want false", got)
	}
	if got := attrs["confidence"]; got != "0.60" {
		t.Fatalf("confidence = %q, want 0.60", got)
	}
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
	// 7 = 6 prior edges + the new identifier.login -> identity.login
	// represents_identity edge introduced when addIdentifierLink learned to
	// emit the reverse pointer that keeps identifier <-> identity twins joined.
	if result.LinksProjected != 7 {
		t.Fatalf("Project().LinksProjected = %d, want 7", result.LinksProjected)
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

func TestProjectGitHubOrgMemberLinksLoginIdentity(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-org-member-1",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.org_member",
		OccurredAt: timestamppb.New(time.Date(
			2026, 4, 23, 12, 0, 0, 0, time.UTC,
		)),
		Attributes: map[string]string{
			"owner":   "writer",
			"login":   "alice",
			"role":    "member",
			"user_id": "123",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	memberURN := "urn:cerebro:writer:github_user:alice"
	identityURN := "urn:cerebro:writer:identity:login:alice"
	identifierURN := "urn:cerebro:writer:identifier:login:alice"
	assertProjectedLink(t, graph, memberURN, relationBelongsTo, "urn:cerebro:writer:github_org:writer")
	assertProjectedLink(t, graph, memberURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, graph, memberURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, graph, identityURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, graph, identifierURN, relationRepresentsIdentity, identityURN)
}

func TestProjectGitHubOrgInstallationPreservesPolicyEvidenceFields(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-org-installation-1",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.org_installation",
		OccurredAt: timestamppb.New(time.Date(
			2026, 4, 23, 12, 0, 0, 0, time.UTC,
		)),
		Attributes: map[string]string{
			"app_slug":             "security-bot",
			"created_at":           "2026-04-22T00:00:00Z",
			"events":               "push,pull_request",
			"installation_id":      "123",
			"owner":                "writer",
			"permissions":          "administration:write,contents:write,members:read,metadata:read",
			"repository_selection": "all",
			"target_type":          "Organization",
			"updated_at":           "2026-04-23T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	installationURN := "urn:cerebro:writer:github_installation:123"
	entity := graph.entities[installationURN]
	if entity == nil || entity.EntityType != "github.org_installation" {
		t.Fatalf("github org installation entity missing: %#v", entity)
	}
	wantAttrs := map[string]string{
		"app_slug":             "security-bot",
		"created_at":           "2026-04-22T00:00:00Z",
		"events":               "push,pull_request",
		"installation_id":      "123",
		"permissions":          "administration:write,contents:write,members:read,metadata:read",
		"repository_selection": "all",
		"target_type":          "Organization",
		"updated_at":           "2026-04-23T00:00:00Z",
	}
	for key, want := range wantAttrs {
		if got := entity.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, graph, installationURN, relationBelongsTo, "urn:cerebro:writer:github_org:writer")
}

func TestProjectGitHubCodeRepositoryLinksOwnerAndLegacyRepo(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-code-repository-1",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.code.repository",
		Attributes: map[string]string{
			"default_branch": "main",
			"html_url":       "https://github.com/writer/cerebro",
			"owner_login":    "writer",
			"repo_id":        "1",
			"repository":     "writer/cerebro",
			"resource_id":    "1",
			"resource_type":  "code_repository",
			"visibility":     "public",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	codeRepoURN := "urn:cerebro:writer:github_code_repository:1"
	orgURN := "urn:cerebro:writer:github_org:writer"
	if entity := state.entities[codeRepoURN]; entity == nil || entity.EntityType != "github.code.repository" {
		t.Fatalf("github code repository entity missing: %#v", entity)
	}
	if got := state.entities[codeRepoURN].Attributes["owner_login"]; got != "writer" {
		t.Fatalf("code repository owner_login = %q, want writer", got)
	}
	assertProjectedLink(t, state, codeRepoURN, relationBelongsTo, orgURN)
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
			"advisory_cve_id":          "CVE-2025-12345",
			"advisory_ghsa_id":         "GHSA-xxxx-yyyy-zzzz",
			"alert_number":             "7",
			"dependency_scope":         "runtime",
			"ecosystem":                "go",
			"first_patched_version":    "v0.36.0",
			"manifest_path":            "go.mod",
			"owner":                    "writer",
			"package":                  "golang.org/x/crypto",
			"repo":                     "cerebro",
			"repository":               "writer/cerebro",
			"severity":                 "high",
			"state":                    "open",
			"vulnerable_version_range": "< v0.36.0",
			"vulnerability_type":       "dependabot",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 9 {
		t.Fatalf("Project().EntitiesProjected = %d, want 9", result.EntitiesProjected)
	}
	if result.LinksProjected != 18 {
		t.Fatalf("Project().LinksProjected = %d, want 18", result.LinksProjected)
	}

	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	repoURN := "urn:cerebro:writer:github_code_repository:writer/cerebro"
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
	for key, want := range map[string]string{
		"dependency_scope":         "runtime",
		"first_patched_version":    "v0.36.0",
		"manifest_path":            "go.mod",
		"vulnerable_version_range": "< v0.36.0",
	} {
		if got := graph.entities[alertURN].Attributes[key]; got != want {
			t.Fatalf("alert attributes[%q] = %q, want %q", key, got, want)
		}
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

func TestProjectGitHubDependabotAlertLinksRepoScopedDependency(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-dependabot-alert-manifest",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.dependabot_alert",
		Attributes: map[string]string{
			"alert_number":  "7",
			"ecosystem":     "go",
			"manifest_path": "go.mod",
			"owner":         "writer",
			"package":       "golang.org/x/crypto",
			"repository":    "writer/cerebro",
			"state":         "open",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	repoURN := "urn:cerebro:writer:github_code_repository:writer/cerebro"
	manifestURN := "urn:cerebro:writer:github_dependency_manifest:writer/cerebro:go.mod"
	dependencyURN := "urn:cerebro:writer:github_dependency:writer/cerebro:go.mod:go:golang.org/x/crypto"
	packageURN := "urn:cerebro:writer:package:go:golang.org/x/crypto"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:golang.org/x/crypto"
	assertProjectedLink(t, state, manifestURN, relationBelongsTo, repoURN)
	assertProjectedLink(t, state, dependencyURN, relationBelongsTo, manifestURN)
	assertProjectedLink(t, state, manifestURN, relationContains, dependencyURN)
	assertProjectedLink(t, state, repoURN, relationContains, dependencyURN)
	assertProjectedLink(t, state, repoURN, relationContains, packageURN)
	assertProjectedLink(t, state, repoURN, relationContains, canonicalPackageURN)
	assertProjectedLink(t, state, dependencyURN, relationRepresents, packageURN)
	assertProjectedLink(t, state, dependencyURN, relationRepresents, canonicalPackageURN)
	assertProjectedLink(t, state, alertURN, relationAffects, dependencyURN)
	assertProjectedLink(t, state, alertURN, relationAffects, canonicalPackageURN)
}

func TestProjectGitHubDependabotAlertLinksDismissedByActor(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-dependabot-alert-dismissed",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.dependabot_alert",
		Attributes: map[string]string{
			"alert_number":    "7",
			"dismissed_by":    "alice",
			"dismissed_by_id": "123",
			"owner":           "writer",
			"repository":      "writer/cerebro",
			"state":           "dismissed",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	actorURN := "urn:cerebro:writer:github_user:alice"
	alertURN := "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7"
	identityURN := "urn:cerebro:writer:identity:login:alice"
	identifierURN := "urn:cerebro:writer:identifier:login:alice"
	assertProjectedLink(t, graph, actorURN, relationActedOn, alertURN)
	assertProjectedLink(t, graph, actorURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, graph, actorURN, relationHasIdentifier, identifierURN)
	if got := graph.entities[actorURN].Attributes["user_id"]; got != "123" {
		t.Fatalf("github actor user_id = %q, want 123", got)
	}
	if got := graph.links[actorURN+"|"+relationActedOn+"|"+alertURN].Attributes["actor_role"]; got != "dismissed_by" {
		t.Fatalf("actor_role = %q, want dismissed_by", got)
	}
}

func TestProjectGitHubSecretScanningAlertLinksResolverAndBypasser(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-secret-scanning-alert-resolved",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.secret_scanning_alert",
		Attributes: map[string]string{
			"alert_number":                   "42",
			"owner":                          "writer",
			"push_protection_bypassed":       "true",
			"push_protection_bypassed_by":    "bob",
			"push_protection_bypassed_by_id": "456",
			"repository":                     "writer/cerebro",
			"resolved_by":                    "alice",
			"resolved_by_id":                 "123",
			"state":                          "resolved",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	alertURN := "urn:cerebro:writer:github_secret_scanning_alert:writer:42"
	resolverURN := "urn:cerebro:writer:github_user:alice"
	bypasserURN := "urn:cerebro:writer:github_user:bob" // #nosec G101 -- test URN fixture, not a secret.
	assertProjectedLink(t, graph, resolverURN, relationActedOn, alertURN)
	assertProjectedLink(t, graph, resolverURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:login:alice")
	assertProjectedLink(t, graph, resolverURN, relationHasIdentifier, "urn:cerebro:writer:identifier:login:alice")
	assertProjectedLink(t, graph, bypasserURN, relationActedOn, alertURN)
	assertProjectedLink(t, graph, bypasserURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:login:bob")
	assertProjectedLink(t, graph, bypasserURN, relationHasIdentifier, "urn:cerebro:writer:identifier:login:bob")
	if got := graph.links[resolverURN+"|"+relationActedOn+"|"+alertURN].Attributes["actor_role"]; got != "resolved_by" {
		t.Fatalf("resolver actor_role = %q, want resolved_by", got)
	}
	if got := graph.links[bypasserURN+"|"+relationActedOn+"|"+alertURN].Attributes["actor_role"]; got != "push_protection_bypassed_by" {
		t.Fatalf("bypasser actor_role = %q, want push_protection_bypassed_by", got)
	}
}

func TestProjectGitHubSecretScanningAlertPreservesMultipleActorRolesForSameUser(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-secret-scanning-alert-same-actor",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.secret_scanning_alert",
		Attributes: map[string]string{
			"alert_number":                   "43",
			"owner":                          "writer",
			"push_protection_bypassed":       "true",
			"push_protection_bypassed_by":    "alice",
			"push_protection_bypassed_by_id": "123",
			"repository":                     "writer/cerebro",
			"resolved_by":                    "alice",
			"resolved_by_id":                 "123",
			"state":                          "resolved",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	alertURN := "urn:cerebro:writer:github_secret_scanning_alert:writer:43"
	actorURN := "urn:cerebro:writer:github_user:alice"
	assertProjectedLink(t, graph, actorURN, relationActedOn, alertURN)
	link := graph.links[actorURN+"|"+relationActedOn+"|"+alertURN]
	if got := link.Attributes["actor_role"]; got != "resolved_by,push_protection_bypassed_by" {
		t.Fatalf("actor_role = %q, want both roles", got)
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

func TestProjectOktaAuditLinksTargetApplication(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, 5, 7, 19, 54, 46, 0, time.UTC)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "okta-sso",
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(occurred),
		Attributes: map[string]string{
			"domain":           "writer.okta.com",
			"event_type":       "user.authentication.sso",
			"actor_id":         "00u-user",
			"actor_type":       "User",
			"target_app_id":    "0oa-prod",
			"target_app_label": "Production Console",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:okta_user:00u-user"
	appURN := "urn:cerebro:writer:okta_application:0oa-prod"
	entity, ok := state.entities[appURN]
	if !ok {
		t.Fatalf("target app entity %q missing", appURN)
	}
	if got := entity.Label; got != "Production Console" {
		t.Fatalf("target app label = %q, want Production Console", got)
	}
	assertProjectedLink(t, state, appURN, relationBelongsTo, "urn:cerebro:writer:okta_org:writer.okta.com")
	assertProjectedLink(t, state, userURN, relationActedOn, appURN)
	link := state.links[userURN+"|"+relationActedOn+"|"+appURN]
	if got := link.Attributes["target_app_id"]; got != "0oa-prod" {
		t.Fatalf("acted_on target_app_id = %q, want 0oa-prod", got)
	}
	if got := link.Attributes["at"]; got != occurred.Format(time.RFC3339) {
		t.Fatalf("acted_on at = %q, want %q", got, occurred.Format(time.RFC3339))
	}
}

func TestProjectOktaApplicationIncludesLifecycleAttributes(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "okta-application-0oa-client",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.application",
		Attributes: map[string]string{
			"app_id":                         "0oa-client",
			"app_name":                       "Production Client",
			"client_id":                      "0oa-client-id",
			"domain":                         "writer.okta.com",
			"post_logout_redirect_uri_hosts": "logout.example.com",
			"redirect_uri_hosts":             "app.example.com",
			"status":                         "ACTIVE",
			"sign_on_mode":                   "OPENID_CONNECT",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 6 {
		t.Fatalf("Project().EntitiesProjected = %d, want 6", result.EntitiesProjected)
	}

	clientURN := "urn:cerebro:writer:okta_application:0oa-client"
	orgURN := "urn:cerebro:writer:okta_org:writer.okta.com"
	entity, ok := state.entities[clientURN]
	if !ok {
		t.Fatalf("state entity %q missing", clientURN)
	}
	wantAttributes := map[string]string{
		"app_id":                         "0oa-client",
		"app_name":                       "Production Client",
		"client_id":                      "0oa-client-id",
		"domain":                         "writer.okta.com",
		"post_logout_redirect_uri_hosts": "logout.example.com",
		"redirect_uri_hosts":             "app.example.com",
		"status":                         "ACTIVE",
		"sign_on_mode":                   "OPENID_CONNECT",
	}
	for key, want := range wantAttributes {
		if got := entity.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, clientURN, relationBelongsTo, orgURN)
	assertProjectedLink(t, state, clientURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:app.example.com")
	assertProjectedLink(t, state, clientURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:logout.example.com")
	assertProjectedLink(t, state, clientURN, relationContains, "urn:cerebro:writer:okta_oauth_client:0oa-client-id")
	assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:app.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:logout.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
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
			"app_exclude_ids":          "app-legacy",
			"app_include_ids":          "app-prod",
			"client_include_ids":       "0oa-client,ALL_CLIENTS",
			"domain":                   "writer.okta.com",
			"group_include_ids":        "EVERYONE,grp-security",
			"idp_ids":                  "idp-saml",
			"name":                     "Require MFA",
			"network_zone_exclude_ids": "zone-untrusted",
			"network_zone_include_ids": "zone-corp",
			"policy_id":                "pol-1",
			"policy_name":              "Production Sign-On",
			"policy_rule_id":           "rul-1",
			"policy_type":              "OKTA_SIGN_ON",
			"priority":                 "1",
			"status":                   "INACTIVE",
			"system":                   "false",
			"user_exclude_ids":         "00u-breakglass",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected != 11 {
		t.Fatalf("Project().EntitiesProjected = %d, want 11", result.EntitiesProjected)
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
	policyURN := "urn:cerebro:writer:okta_policy:pol-1"
	policy := state.entities[policyURN]
	if policy == nil || policy.EntityType != "okta.policy" {
		t.Fatalf("policy entity missing or wrong type: %#v", policy)
	}
	if got := policy.Label; got != "Production Sign-On" {
		t.Fatalf("policy Label = %q, want Production Sign-On", got)
	}
	assertProjectedLink(t, state, wantURN, relationBelongsTo, policyURN)
	assertProjectedLink(t, state, policyURN, relationBelongsTo, "urn:cerebro:writer:okta_org:writer.okta.com")
	assertProjectedLink(t, state, wantURN, relationTargeted, "urn:cerebro:writer:okta_application:app-prod")
	assertProjectedLink(t, state, wantURN, relationTargeted, "urn:cerebro:writer:okta_application:app-legacy")
	assertProjectedLink(t, state, wantURN, relationTargeted, "urn:cerebro:writer:okta_group:grp-security")
	assertProjectedLink(t, state, wantURN, relationTargeted, "urn:cerebro:writer:okta_user:00u-breakglass")
	assertProjectedLink(t, state, wantURN, relationDependsOn, "urn:cerebro:writer:okta_identity_provider:idp-saml")
	assertProjectedLink(t, state, wantURN, relationDependsOn, "urn:cerebro:writer:okta_network_zone:zone-corp")
	assertProjectedLink(t, state, wantURN, relationDependsOn, "urn:cerebro:writer:okta_network_zone:zone-untrusted")
	assertProjectedLink(t, state, wantURN, relationDependsOn, "urn:cerebro:writer:okta_oauth_client:0oa-client")
	assertProjectedLinkMissing(t, state, wantURN, relationTargeted, "urn:cerebro:writer:okta_group:EVERYONE")
	assertProjectedLinkMissing(t, state, wantURN, relationDependsOn, "urn:cerebro:writer:okta_oauth_client:ALL_CLIENTS")
}

func TestProjectOktaDurableConfigurationEntities(t *testing.T) {
	tests := []struct {
		name           string
		kind           string
		attributes     map[string]string
		wantURN        string
		wantEntityType string
		wantLabel      string
		wantAttrs      map[string]string
		wantEntities   uint32
	}{
		{
			name: "api token",
			kind: "okta.api_token",
			attributes: map[string]string{
				"api_token_id":             "tok-admin",
				"client_name":              "Okta API",
				"domain":                   "writer.okta.com",
				"name":                     "Admin automation",
				"network_connection":       "ZONE",
				"network_zone_include_ids": "zone-corp",
				"token_id":                 "tok-admin",
				"user_id":                  "00u1",
			},
			wantURN:        "urn:cerebro:writer:okta_api_token:tok-admin",
			wantEntityType: "okta.api_token",
			wantLabel:      "Admin automation",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"api_token_id":             "tok-admin",
				"client_name":              "Okta API",
				"name":                     "Admin automation",
				"network_connection":       "ZONE",
				"network_zone_include_ids": "zone-corp",
				"token_id":                 "tok-admin",
				"user_id":                  "00u1",
			},
		},
		{
			name: "authorization server",
			kind: "okta.authorization_server",
			attributes: map[string]string{
				"authorization_server_id": "aus-api",
				"domain":                  "writer.okta.com",
				"issuer":                  "https://login.example.com/oauth2/aus-api",
				"issuer_host":             "login.example.com",
				"name":                    "API Gateway",
				"status":                  "ACTIVE",
			},
			wantURN:        "urn:cerebro:writer:okta_authorization_server:aus-api",
			wantEntityType: "okta.authorization_server",
			wantLabel:      "API Gateway",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"authorization_server_id": "aus-api",
				"issuer":                  "https://login.example.com/oauth2/aus-api",
				"issuer_host":             "login.example.com",
				"name":                    "API Gateway",
				"status":                  "ACTIVE",
			},
		},
		{
			name: "brand",
			kind: "okta.brand",
			attributes: map[string]string{
				"brand_id":                   "brand-prod",
				"custom_privacy_policy_host": "privacy.example.com",
				"custom_privacy_policy_url":  "https://privacy.example.com/policy",
				"domain":                     "writer.okta.com",
				"is_default":                 "true",
				"name":                       "Writer Login",
			},
			wantURN:        "urn:cerebro:writer:okta_brand:brand-prod",
			wantEntityType: "okta.brand",
			wantLabel:      "Writer Login",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"brand_id":                   "brand-prod",
				"custom_privacy_policy_host": "privacy.example.com",
				"custom_privacy_policy_url":  "https://privacy.example.com/policy",
				"is_default":                 "true",
				"name":                       "Writer Login",
			},
		},
		{
			name: "device assurance",
			kind: "okta.device_assurance",
			attributes: map[string]string{
				"device_assurance_id":     "device-assurance-macos",
				"domain":                  "writer.okta.com",
				"name":                    "Managed macOS",
				"platform":                "MACOS",
				"secure_hardware_present": "true",
			},
			wantURN:        "urn:cerebro:writer:okta_device_assurance:device-assurance-macos",
			wantEntityType: "okta.device_assurance",
			wantLabel:      "Managed macOS",
			wantEntities:   2,
			wantAttrs: map[string]string{
				"device_assurance_id":     "device-assurance-macos",
				"name":                    "Managed macOS",
				"platform":                "MACOS",
				"secure_hardware_present": "true",
			},
		},
		{
			name: "event hook",
			kind: "okta.event_hook",
			attributes: map[string]string{
				"domain":              "writer.okta.com",
				"event_hook_id":       "hook-event-prod",
				"name":                "Security event egress",
				"status":              "ACTIVE",
				"uri":                 "https://hooks.example.com/okta/events",
				"uri_host":            "hooks.example.com",
				"verification_status": "VERIFIED",
			},
			wantURN:        "urn:cerebro:writer:okta_event_hook:hook-event-prod",
			wantEntityType: "okta.event_hook",
			wantLabel:      "Security event egress",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"event_hook_id":       "hook-event-prod",
				"name":                "Security event egress",
				"status":              "ACTIVE",
				"uri":                 "https://hooks.example.com/okta/events",
				"uri_host":            "hooks.example.com",
				"verification_status": "VERIFIED",
			},
		},
		{
			name: "identity provider",
			kind: "okta.identity_provider",
			attributes: map[string]string{
				"domain":        "writer.okta.com",
				"acs_type":      "HTTP-POST",
				"idp_id":        "idp-saml",
				"issuer":        "https://idp.example.com",
				"name":          "Partner SAML IdP",
				"protocol_type": "SAML2",
				"status":        "ACTIVE",
				"type":          "SAML2",
			},
			wantURN:        "urn:cerebro:writer:okta_identity_provider:idp-saml",
			wantEntityType: "okta.identity_provider",
			wantLabel:      "Partner SAML IdP",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"acs_type":      "HTTP-POST",
				"idp_id":        "idp-saml",
				"issuer":        "https://idp.example.com",
				"name":          "Partner SAML IdP",
				"protocol_type": "SAML2",
				"status":        "ACTIVE",
				"type":          "SAML2",
			},
		},
		{
			name: "inline hook",
			kind: "okta.inline_hook",
			attributes: map[string]string{
				"domain":         "writer.okta.com",
				"inline_hook_id": "hook-inline-prod",
				"name":           "Token transform",
				"status":         "ACTIVE",
				"type":           "com.okta.oauth2.tokens.transform",
				"uri":            "https://token-hooks.example.com/transform",
				"uri_host":       "token-hooks.example.com",
			},
			wantURN:        "urn:cerebro:writer:okta_inline_hook:hook-inline-prod",
			wantEntityType: "okta.inline_hook",
			wantLabel:      "Token transform",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"inline_hook_id": "hook-inline-prod",
				"name":           "Token transform",
				"status":         "ACTIVE",
				"type":           "com.okta.oauth2.tokens.transform",
				"uri":            "https://token-hooks.example.com/transform",
				"uri_host":       "token-hooks.example.com",
			},
		},
		{
			name: "log stream",
			kind: "okta.log_stream",
			attributes: map[string]string{
				"domain":           "writer.okta.com",
				"log_stream_id":    "logstream-splunk",
				"name":             "Splunk Cloud",
				"splunk_host":      "https://splunk.example.com/services/collector",
				"splunk_host_host": "splunk.example.com",
				"status":           "ACTIVE",
				"type":             "splunk_cloud_logstreaming",
			},
			wantURN:        "urn:cerebro:writer:okta_log_stream:logstream-splunk",
			wantEntityType: "okta.log_stream",
			wantLabel:      "Splunk Cloud",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"log_stream_id":    "logstream-splunk",
				"name":             "Splunk Cloud",
				"splunk_host":      "https://splunk.example.com/services/collector",
				"splunk_host_host": "splunk.example.com",
				"status":           "ACTIVE",
				"type":             "splunk_cloud_logstreaming",
			},
		},
		{
			name: "network zone",
			kind: "okta.network_zone",
			attributes: map[string]string{
				"domain":          "writer.okta.com",
				"gateway_count":   "1",
				"gateway_values":  "203.0.113.0/24",
				"name":            "Corporate VPN",
				"network_zone_id": "zone-corp",
				"status":          "ACTIVE",
				"type":            "IP",
				"usage":           "POLICY",
				"zone_id":         "zone-corp",
			},
			wantURN:        "urn:cerebro:writer:okta_network_zone:zone-corp",
			wantEntityType: "okta.network_zone",
			wantLabel:      "Corporate VPN",
			wantEntities:   2,
			wantAttrs: map[string]string{
				"gateway_count":   "1",
				"gateway_values":  "203.0.113.0/24",
				"network_zone_id": "zone-corp",
				"status":          "ACTIVE",
				"type":            "IP",
				"usage":           "POLICY",
				"zone_id":         "zone-corp",
			},
		},
		{
			name: "trusted origin",
			kind: "okta.trusted_origin",
			attributes: map[string]string{
				"cors":              "true",
				"domain":            "writer.okta.com",
				"name":              "Production Console",
				"origin":            "https://app.example.com",
				"origin_host":       "app.example.com",
				"redirect":          "true",
				"scope_count":       "2",
				"scope_types":       "CORS,REDIRECT",
				"status":            "ACTIVE",
				"trusted_origin_id": "origin-prod",
			},
			wantURN:        "urn:cerebro:writer:okta_trusted_origin:origin-prod",
			wantEntityType: "okta.trusted_origin",
			wantLabel:      "Production Console",
			wantEntities:   4,
			wantAttrs: map[string]string{
				"cors":              "true",
				"origin":            "https://app.example.com",
				"origin_host":       "app.example.com",
				"redirect":          "true",
				"scope_count":       "2",
				"scope_types":       "CORS,REDIRECT",
				"status":            "ACTIVE",
				"trusted_origin_id": "origin-prod",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "okta-durable-" + tt.name,
				TenantId:   "writer",
				SourceId:   "okta",
				Kind:       tt.kind,
				Attributes: tt.attributes,
			})
			if err != nil {
				t.Fatalf("Project() error = %v", err)
			}
			if result.EntitiesProjected != tt.wantEntities {
				t.Fatalf("Project().EntitiesProjected = %d, want %d", result.EntitiesProjected, tt.wantEntities)
			}
			entity, ok := state.entities[tt.wantURN]
			if !ok {
				t.Fatalf("state entity %q missing", tt.wantURN)
			}
			if got := entity.EntityType; got != tt.wantEntityType {
				t.Fatalf("EntityType = %q, want %q", got, tt.wantEntityType)
			}
			if got := entity.Label; got != tt.wantLabel {
				t.Fatalf("Label = %q, want %q", got, tt.wantLabel)
			}
			for key, want := range tt.wantAttrs {
				if got := entity.Attributes[key]; got != want {
					t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
				}
			}
			assertProjectedLink(t, state, tt.wantURN, relationBelongsTo, "urn:cerebro:writer:okta_org:writer.okta.com")
			switch tt.name {
			case "api token":
				assertProjectedLink(t, state, "urn:cerebro:writer:okta_user:00u1", relationAssignedTo, tt.wantURN)
				assertProjectedLink(t, state, tt.wantURN, relationDependsOn, "urn:cerebro:writer:okta_network_zone:zone-corp")
			case "authorization server":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:login.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:login.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "brand":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:privacy.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:privacy.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "event hook":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:hooks.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:hooks.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "identity provider":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:idp.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:idp.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "inline hook":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:token-hooks.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:token-hooks.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "log stream":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:splunk.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:splunk.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			case "trusted origin":
				assertProjectedLink(t, state, tt.wantURN, relationHasIdentifier, "urn:cerebro:writer:internet_host:app.example.com")
				assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:app.example.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:example.com")
			}
		})
	}
}

func TestProjectOktaThreatInsightLinksExcludedNetworkZones(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := &cerebrov1.EventEnvelope{
		Id:       "okta-threat-insight",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.threat_insight",
		Attributes: map[string]string{
			"action":             "block",
			"domain":             "writer.okta.com",
			"exclude_zone_count": "1",
		},
		Payload: []byte(`{"domain":"writer.okta.com","action":"block","exclude_zones":["zone-corp"]}`),
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	threatInsightURN := "urn:cerebro:writer:okta_threat_insight:writer.okta.com"
	zoneURN := "urn:cerebro:writer:okta_network_zone:zone-corp"
	orgURN := "urn:cerebro:writer:okta_org:writer.okta.com"
	if entity := state.entities[zoneURN]; entity == nil || entity.EntityType != "okta.network_zone" {
		t.Fatalf("excluded network zone entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, threatInsightURN, relationDependsOn, zoneURN)
	assertProjectedLink(t, state, zoneURN, relationBelongsTo, orgURN)
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
			Attributes: map[string]string{ // #nosec G101 -- test event type contains an access_token label, not credential material.
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

func TestProjectOktaAuditTargetUserLinksAlternateIDIdentity(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	service := New(state, graph)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:         "okta-target-user",
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, time.May, 12, 1, 2, 3, 0, time.UTC)),
		Attributes: map[string]string{
			"domain":              "writer.okta.com",
			"event_type":          "user.lifecycle.update",
			"actor_id":            "00u-admin",
			"actor_type":          "User",
			"actor_alternate_id":  "admin@writer.com",
			"resource_id":         "00u-target",
			"resource_type":       "User",
			"target_id":           "00u-target",
			"target_type":         "User",
			"target_alternate_id": "alice@writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:okta_user:00u-target"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"
	assertProjectedLink(t, graph, "urn:cerebro:writer:okta_user:00u-admin", relationActedOn, targetURN)
	assertProjectedLink(t, graph, targetURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, graph, targetURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, graph, identityURN, relationHasIdentifier, identifierURN)
	assertProjectedLink(t, graph, identifierURN, relationRepresentsIdentity, identityURN)
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
			resource: "urn:cerebro:writer:github_code_repository:writer/cerebro",
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
			resource: "urn:cerebro:writer:github_code_repository:writer/cerebro",
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
			resource: "urn:cerebro:writer:github_code_repository:writer/cerebro",
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
			resource: "urn:cerebro:writer:github_code_repository:writer/cerebro",
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
			entity, ok := graph.entities[tt.resource]
			if !ok {
				t.Fatalf("graph resource %q missing", tt.resource)
			}
			if got := entity.Attributes["action"]; got != tt.attrs["action"] {
				t.Fatalf("resource attributes[action] = %q, want %q", got, tt.attrs["action"])
			}
			for _, key := range []string{"branch", "hook_id", "ruleset_id", "ruleset_name"} {
				if want := tt.attrs[key]; want != "" {
					if got := entity.Attributes[key]; got != want {
						t.Fatalf("resource attributes[%q] = %q, want %q", key, got, want)
					}
				}
			}
			if strings.Contains(tt.resource, "github_code_repository") {
				attrs := entity.Attributes
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
	resourceURN := "urn:cerebro:writer:github_code_repository:writer/cerebro"
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
			"department":      "Design",
			"domain":          "writer.okta.com",
			"email":           "alice@writer.com",
			"employee_number": "E-1001",
			"job_title":       "Product Designer",
			"login":           "alice@writer.com",
			"manager":         "manager@example.com",
			"manager_id":      "00u-manager",
			"organization":    "Writer",
			"status":          "DEPROVISIONED",
			"user_id":         "00u1",
			"user_type":       "employee",
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
	entity := graph.entities[userURN]
	for key, want := range map[string]string{
		"department":      "Design",
		"employee_number": "E-1001",
		"job_title":       "Product Designer",
		"manager":         "manager@example.com",
		"manager_id":      "00u-manager",
		"organization":    "Writer",
		"user_type":       "employee",
	} {
		if got := entity.Attributes[key]; got != want {
			t.Fatalf("user entity attributes[%q] = %q, want %q", key, got, want)
		}
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
	resourceURN := "urn:cerebro:writer:github_code_repository:writer/cerebro"
	link, ok := graph.links[actorURN+"|"+relationActedOn+"|"+resourceURN]
	if !ok {
		t.Fatalf("acted_on link missing for %s -> %s: %#v", actorURN, resourceURN, graph.links)
	}
	if got, exists := link.Attributes["at"]; exists {
		t.Fatalf("acted_on attributes[at] = %q present without event OccurredAt; rule must be able to distinguish recent vs unstamped edges", got)
	}
}

func TestProjectGitHubAuditProjectsAutomationActorsAsCredentials(t *testing.T) {
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
			credentialID := githubAutomationCredentialID(attrs)
			credentialURN := "urn:cerebro:writer:github_credential:" + credentialID
			credential := graph.entities[credentialURN]
			if credential == nil {
				t.Fatalf("automation actor should project github.credential %q; got entities=%#v", credentialURN, graph.entities)
			}
			if got := credential.EntityType; got != "github.credential" {
				t.Fatalf("credential entity_type = %q, want github.credential", got)
			}
			assertProjectedLink(t, graph, credentialURN, relationActedOn, "urn:cerebro:writer:github_code_repository:writer/cerebro")
			for key := range graph.links {
				if strings.HasPrefix(key, actorURN+"|") {
					t.Fatalf("automation actor %q emitted identity graph link %q", actorURN, key)
				}
			}
		})
	}
}

func TestGitHubAutomationCredentialIDSkipsEmptyFallback(t *testing.T) {
	if got := githubAutomationCredentialID(map[string]string{}); got != "" {
		t.Fatalf("githubAutomationCredentialID(empty) = %q, want empty", got)
	}
}

func TestProjectGitHubAuditSkipsSparseAutomationCredential(t *testing.T) {
	graph := &projectionRecorder{}
	_, err := New(nil, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-sparse-automation",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor_is_bot": "true",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if credential := graph.entities["urn:cerebro:writer:github_credential"]; credential != nil {
		t.Fatalf("sparse automation event should not create placeholder credential: %#v", credential)
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
	resourceURN := "urn:cerebro:writer:github_code_repository:writer/cerebro"
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
	credentialURN := "urn:cerebro:writer:github_credential:deploy_key@WriterInternal/k8s" // #nosec G101 -- test credential URN fixture, not a secret.
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
	resourceURN := "urn:cerebro:writer:github_code_repository:WriterInternal/k8s"
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
	otherCredentialURN := "urn:cerebro:writer:github_credential:deploy_key@WriterInternal/other" // #nosec G101 -- test credential URN fixture, not a secret.
	if _, ok := graph.entities[otherCredentialURN]; !ok {
		t.Fatalf("github.credential entity %q missing for same deploy_key actor on another repo", otherCredentialURN)
	}
}

func TestProjectGitHubAuditProjectsProgrammaticResourceAsCredential(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-pat",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":                    "octocat",
			"action":                   "personal_access_token.access_granted",
			"org":                      "writer",
			"programmatic_access_type": "Fine-grained personal access token",
			"resource_id":              "octocat",
			"resource_type":            "personal_access_token",
			"scope":                    "organization",
			"token_id":                 "555",
			"user":                     "octocat",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	credentialURN := "urn:cerebro:writer:github_credential:personal_access_token:555" // #nosec G101 -- test credential URN fixture, not credential material.
	credential, ok := graph.entities[credentialURN]
	if !ok {
		t.Fatalf("github.credential entity %q missing: %#v", credentialURN, graph.entities)
	}
	for key, want := range map[string]string{
		"credential_type":          "personal_access_token",
		"programmatic_access_type": "Fine-grained personal access token",
		"resource_type":            "personal_access_token",
		"status":                   "active",
		"token_id":                 "555",
	} {
		if got := credential.Attributes[key]; got != want {
			t.Fatalf("credential attributes[%s] = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, graph, credentialURN, relationBelongsTo, "urn:cerebro:writer:github_org:writer")

	_, err = New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-pat-expired",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":          "octocat",
			"action":         "personal_access_token.access_granted",
			"operation_type": "expired",
			"org":            "writer",
			"resource_id":    "octocat",
			"resource_type":  "personal_access_token",
			"scope":          "organization",
			"token_id":       "555",
		},
	})
	if err != nil {
		t.Fatalf("Project() expired error = %v", err)
	}
	if got := graph.entities[credentialURN].Attributes["status"]; got != "inactive" {
		t.Fatalf("expired credential status = %q, want inactive", got)
	}
}

func TestProjectGitHubAuditProjectsSelfHostedRunnerState(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-runner",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"action":              "repo.register_self_hosted_runner",
			"org":                 "writer",
			"repo":                "writer/cerebro",
			"resource_id":         "writer/cerebro",
			"resource_type":       "repo",
			"runner_ephemeral":    "false",
			"runner_host_trusted": "false",
			"runner_id":           "777",
			"runner_name":         "prod-runner-1",
			"runner_registered":   "true",
			"runner_scope":        "repo:writer/cerebro",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	runnerURN := "urn:cerebro:writer:github_runner:repo:writer/cerebro:777"
	runner, ok := graph.entities[runnerURN]
	if !ok {
		t.Fatalf("github.runner entity %q missing: %#v", runnerURN, graph.entities)
	}
	for key, want := range map[string]string{
		"host_trusted":      "false",
		"runner_ephemeral":  "false",
		"runner_id":         "777",
		"runner_scope":      "repo:writer/cerebro",
		"runner_scope_type": "repo",
		"runner_status":     "active",
	} {
		if got := runner.Attributes[key]; got != want {
			t.Fatalf("runner attributes[%s] = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, graph, runnerURN, relationBelongsTo, "urn:cerebro:writer:github_code_repository:writer/cerebro")

	_, err = New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-runner-remove",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"action":       "repo.remove_self_hosted_runner",
			"org":          "writer",
			"repo":         "writer/cerebro",
			"runner_id":    "777",
			"runner_scope": "repo:writer/cerebro",
		},
	})
	if err != nil {
		t.Fatalf("Project() remove error = %v", err)
	}
	if got := graph.entities[runnerURN].Attributes["runner_status"]; got != "inactive" {
		t.Fatalf("removed runner status = %q, want inactive", got)
	}
}

func TestProjectGitHubAuditSkipsWorkflowJobHostedRunnerInventory(t *testing.T) {
	state := &projectionRecorder{}
	graph := &projectionRecorder{}
	_, err := New(state, graph).Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "github-audit-workflow-job",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"action":                  "workflows.prepared_workflow_job",
			"org":                     "writer",
			"repo":                    "writer/cerebro",
			"resource_id":             "writer/cerebro",
			"resource_type":           "repo",
			"runner_group_name":       "GitHub Actions",
			"runner_id":               "1002207767",
			"runner_name":             "GitHub Actions 1002207767",
			"runner_scope":            "repo:writer/cerebro",
			"source_runtime_id":       "writer-github-audit",
			"transport_protocol_name": "ssh",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	for urn, entity := range graph.entities {
		if entity.EntityType == "github.runner" {
			t.Fatalf("unexpected github.runner entity %q from workflow job audit row: %#v", urn, entity)
		}
	}
}

func TestGitHubSelfHostedRunnerAuditActionClassifiesAssetLifecycleOnly(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{action: "repo.register_self_hosted_runner", want: true},
		{action: "repo.remove_self_hosted_runner", want: true},
		{action: "org.register_self_hosted_runner", want: true},
		{action: "business.remove_self_hosted_runner", want: true},
		{action: "workflows.prepared_workflow_job", want: false},
		{action: "workflows.completed_workflow_run", want: false},
		{action: "repo.runner_group_updated", want: false},
		{action: "repo.register_runner", want: false},
		{action: "", want: false},
	} {
		if got := githubSelfHostedRunnerAuditAction(tc.action); got != tc.want {
			t.Fatalf("githubSelfHostedRunnerAuditAction(%q) = %v, want %v", tc.action, got, tc.want)
		}
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
		{
			Id:       "aws-iam-role-sso",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.iam_role",
			Attributes: map[string]string{
				"arn":            "arn:aws:iam::123456789012:role/AWSReservedSSO_admin",
				"domain":         "123456789012",
				"login":          "AWSReservedSSO_admin",
				"principal_type": "role",
				"user_id":        "AROASSOADMIN",
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
	awsActorURN := "urn:cerebro:writer:aws_assumed_role_session:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com"
	if entity := state.entities[awsActorURN]; entity == nil || entity.EntityType != "aws.assumed_role_session" {
		t.Fatalf("aws assumed-role session entity = %#v, want aws.assumed_role_session", entity)
	}
	if _, ok := state.entities["urn:cerebro:writer:aws_user:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice@writer.com"]; ok {
		t.Fatalf("aws assumed-role CloudTrail actor must not be projected as aws.user")
	}
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
	awsScopedIdentityURN := "urn:cerebro:writer:identity:login:aws:123456789012:role:awsreservedsso_admin"
	awsRoleURN := "urn:cerebro:writer:aws_role:AROASSOADMIN"
	if _, ok := state.links[awsActorURN+"|"+relationRepresentsIdentity+"|"+awsScopedIdentityURN]; !ok {
		t.Fatalf("aws assumed-role scoped identity link missing for %q", awsScopedIdentityURN)
	}
	if _, ok := state.links[awsRoleURN+"|"+relationRepresentsIdentity+"|"+awsScopedIdentityURN]; !ok {
		t.Fatalf("aws iam role scoped identity link missing for %q", awsScopedIdentityURN)
	}

	// Reverse pointer keeps identity traversal symmetric: starting at the
	// identifier.email node, queries must be able to reach the canonical
	// identity without going through the original actor. Without this edge
	// 1:1 identifier <-> identity twins look like orphan pairs.
	if _, ok := state.links[identifierURN+"|"+relationRepresentsIdentity+"|"+canonicalIdentityURN]; !ok {
		t.Fatalf("identifier -> identity represents_identity link missing: %v", state.links)
	}
}

func TestProjectGitHubAuditActorEmailEmitsEmailIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := &cerebrov1.EventEnvelope{
		Id:       "github-audit-email",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.audit",
		Attributes: map[string]string{
			"actor":         "alice",
			"actor_email":   "alice@writer.com",
			"org":           "writer",
			"repo":          "writer/cerebro",
			"resource_id":   "writer/cerebro",
			"resource_type": "repository",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	actorURN := "urn:cerebro:writer:github_user:alice"
	emailIdentityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	loginIdentityURN := "urn:cerebro:writer:identity:login:alice"
	if _, ok := state.links[actorURN+"|"+relationRepresentsIdentity+"|"+emailIdentityURN]; !ok {
		t.Fatalf("github actor email identity link missing for %q", emailIdentityURN)
	}
	if _, ok := state.links[actorURN+"|"+relationRepresentsIdentity+"|"+loginIdentityURN]; !ok {
		t.Fatalf("github actor login identity link missing for %q", loginIdentityURN)
	}
}

func TestProjectAWSCloudTrailActorEmailPreservesAlternateIdentifier(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := &cerebrov1.EventEnvelope{
		Id:         "aws-cloudtrail-email",
		TenantId:   "writer",
		SourceId:   "aws",
		Kind:       "aws.cloudtrail",
		OccurredAt: timestamppb.New(time.Date(2026, time.June, 5, 17, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"actor_alternate_id": "AWSReservedSSO_admin/alice",
			"actor_email":        "alice@writer.com",
			"actor_id":           "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice",
			"actor_type":         "AssumedRole",
			"domain":             "123456789012",
			"event_type":         "ListRoles",
			"resource_id":        "123456789012",
			"resource_type":      "account",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	actorURN := "urn:cerebro:writer:aws_assumed_role_session:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice"
	if entity := state.entities[actorURN]; entity == nil || entity.EntityType != "aws.assumed_role_session" {
		t.Fatalf("aws assumed-role session entity = %#v, want aws.assumed_role_session", entity)
	}
	if _, ok := state.entities["urn:cerebro:writer:aws_user:arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_admin/alice"]; ok {
		t.Fatalf("aws assumed-role CloudTrail actor must not be projected as aws.user")
	}
	emailIdentityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	alternateIdentifierURN := "urn:cerebro:writer:identifier:login:awsreservedsso_admin/alice"
	if _, ok := state.links[actorURN+"|"+relationRepresentsIdentity+"|"+emailIdentityURN]; !ok {
		t.Fatalf("aws actor email identity link missing for %q", emailIdentityURN)
	}
	if _, ok := state.links[actorURN+"|"+relationHasIdentifier+"|"+alternateIdentifierURN]; !ok {
		t.Fatalf("aws actor alternate identifier link missing for %q", alternateIdentifierURN)
	}
	resourceURN := "urn:cerebro:writer:aws_account:123456789012"
	actedOn := state.links[actorURN+"|"+relationActedOn+"|"+resourceURN]
	if actedOn == nil {
		t.Fatalf("aws acted_on link missing for %q", resourceURN)
	}
	if got, want := actedOn.Attributes["at"], "2026-06-05T17:00:00Z"; got != want {
		t.Fatalf("aws acted_on attributes[at] = %q, want %q", got, want)
	}
}

func TestProjectAWSCloudTrailRoleResourceLinksCanonicalRole(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	roleARN := "arn:aws:iam::123456789012:role/AdminRole"
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-cloudtrail-role-resource",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.cloudtrail",
		Attributes: map[string]string{
			"domain":        "123456789012",
			"event_type":    "ListRolePolicies",
			"resource_id":   roleARN,
			"resource_type": "resource",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:aws_resource:" + roleARN
	roleURN := "urn:cerebro:writer:aws_role:" + roleARN
	assertProjectedEntityType(t, state, resourceURN, "aws.resource")
	assertProjectedEntityType(t, state, roleURN, "aws.role")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, resourceURN, relationRepresents, roleURN)
}

func TestProjectGCPAuditResourceLinksProject(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	resourceID := "projects/writer-prod/locations/us-central1/keyRings/ring-1/cryptoKeys/key-1"
	event := &cerebrov1.EventEnvelope{
		Id:       "gcp-audit-resource",
		TenantId: "writer",
		SourceId: "gcp",
		Kind:     "gcp.audit",
		Attributes: map[string]string{
			"event_type":    "GetCryptoKey",
			"resource_id":   resourceID,
			"resource_type": "audited_resource",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	resourceURN := "urn:cerebro:writer:gcp_audited_resource:" + resourceID
	assertProjectedEntityType(t, state, resourceURN, "gcp.audited.resource")
	assertProjectedLink(t, state, resourceURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
}

func TestProjectGoogleWorkspaceAuditTargetEmailLinksIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "google-workspace-audit-target-email",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.audit",
		Attributes: map[string]string{
			"actor_email":   "admin@example.com",
			"actor_id":      "admin-1",
			"event_name":    "USER_SETTINGS_CHANGE",
			"resource_type": "user",
			"target_email":  "alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:google_workspace_user:alice@example.com"
	targetIdentityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	assertProjectedLink(t, state, "urn:cerebro:writer:google_workspace_user:admin-1", relationActedOn, targetURN)
	assertProjectedLink(t, state, targetURN, relationRepresentsIdentity, targetIdentityURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:identifier:email:alice@example.com", relationRepresentsIdentity, targetIdentityURN)
}

func TestProjectGoogleWorkspaceAuditTargetEmailNormalizesResourceURN(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "google-workspace-audit-target-email-case",
		TenantId: "writer",
		SourceId: "google_workspace",
		Kind:     "google_workspace.audit",
		Attributes: map[string]string{
			"actor_email":   "admin@example.com",
			"actor_id":      "admin-1",
			"event_name":    "USER_SETTINGS_CHANGE",
			"resource_type": "user",
			"target_email":  "Alice@Example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	targetURN := "urn:cerebro:writer:google_workspace_user:alice@example.com"
	unnormalizedTargetURN := "urn:cerebro:writer:google_workspace_user:Alice@Example.com"
	targetIdentityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	assertProjectedLink(t, state, "urn:cerebro:writer:google_workspace_user:admin-1", relationActedOn, targetURN)
	assertProjectedLink(t, state, targetURN, relationRepresentsIdentity, targetIdentityURN)
	if _, ok := state.entities[unnormalizedTargetURN]; ok {
		t.Fatalf("projected unnormalized target entity %q", unnormalizedTargetURN)
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
	assertProjectedLink(t, state, identifierURN, relationRepresentsIdentity, canonicalIdentityURN)
	assertProjectedLink(t, state, oktaUserURN, relationMemberOf, "urn:cerebro:writer:okta_group:grp-security")
	assertProjectedLink(t, state, googleUserURN, relationMemberOf, "urn:cerebro:writer:google_workspace_group:security@writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:google_workspace_group:security@writer.com", relationHasIdentifier, "urn:cerebro:writer:identifier:email:security@writer.com")
	assertProjectedLink(t, state, oktaUserURN, relationAssignedTo, "urn:cerebro:writer:okta_application:app-prod")
	assertProjectedLink(t, state, googleUserURN, relationCanAdmin, "urn:cerebro:writer:google_workspace_admin_role:super-admin")
	assertProjectedLink(t, state, awsUserURN, relationCanAdmin, "urn:cerebro:writer:aws_admin_role:AdministratorAccess")
	assertProjectedLink(t, state, gcpUserURN, relationCanAdmin, "urn:cerebro:writer:gcp_admin_role:roles/owner")
	assertProjectedLink(t, state, googleUserURN, relationActedOn, "urn:cerebro:writer:google_workspace_security_setting:two_step")
	assertProjectedLink(t, state, awsUserURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_admin_role:AdministratorAccess", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLinkMissing(t, state, gcpUserURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
}

func TestProjectOktaEffectiveEntitlementGraph(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	occurred := time.Date(2026, time.June, 14, 12, 0, 0, 0, time.UTC)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:         "okta-group-app-assignment",
			TenantId:   "writer",
			SourceId:   "okta",
			Kind:       "okta.app_assignment",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"app_id":       "app-admin",
				"app_name":     "AWS Admin Console",
				"scope":        "AdministratorAccess",
				"status":       "ACTIVE",
				"subject_id":   "grp-security",
				"subject_name": "Security Engineering",
				"subject_type": "group",
			},
		},
		{
			Id:         "okta-admin-role",
			TenantId:   "writer",
			SourceId:   "okta",
			Kind:       "okta.admin_role",
			OccurredAt: timestamppb.New(occurred),
			Attributes: map[string]string{
				"role_id":       "SUPER_ADMIN",
				"role_name":     "Super Administrator",
				"role_type":     "SUPER_ADMIN",
				"subject_email": "admin@writer.com",
				"subject_id":    "00u-admin",
				"subject_type":  "user",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	groupURN := "urn:cerebro:writer:okta_group:grp-security"
	appURN := "urn:cerebro:writer:okta_application:app-admin"
	appEntitlementURN := "urn:cerebro:writer:okta_entitlement:AdministratorAccess"
	cloudAdminCapabilityURN := "urn:cerebro:writer:privileged_capability:cloud_admin"
	assertProjectedLink(t, state, groupURN, relationAssignedTo, appURN)
	assertProjectedLink(t, state, appURN, relationGrantsEntitlement, appEntitlementURN)
	assertProjectedLink(t, state, appEntitlementURN, relationConfersCapability, cloudAdminCapabilityURN)
	link := state.links[appURN+"|"+relationGrantsEntitlement+"|"+appEntitlementURN]
	if link.Attributes["event_id"] != "okta-group-app-assignment" || link.Attributes["at"] != occurred.Format(time.RFC3339Nano) {
		t.Fatalf("entitlement link attributes = %#v, want source event context", link.Attributes)
	}

	userURN := "urn:cerebro:writer:okta_user:00u-admin"
	roleURN := "urn:cerebro:writer:okta_admin_role:SUPER_ADMIN"
	roleEntitlementURN := "urn:cerebro:writer:okta_entitlement:admin_role:SUPER_ADMIN"
	identityAdminCapabilityURN := "urn:cerebro:writer:privileged_capability:identity_admin"
	assertProjectedLink(t, state, userURN, relationCanAdmin, roleURN)
	assertProjectedLink(t, state, roleURN, relationGrantsEntitlement, roleEntitlementURN)
	assertProjectedLink(t, state, roleEntitlementURN, relationConfersCapability, identityAdminCapabilityURN)
	if entity := state.entities[appEntitlementURN]; entity == nil || entity.EntityType != "okta.entitlement" {
		t.Fatalf("app entitlement entity missing or wrong type: %#v", entity)
	}
	if entity := state.entities[cloudAdminCapabilityURN]; entity == nil || entity.EntityType != "privileged.capability" {
		t.Fatalf("capability entity missing or wrong type: %#v", entity)
	}
}

func TestProjectOktaEntitlementOmitsAtWhenOccurredAtUnset(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-app-assignment-no-time",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.app_assignment",
		Attributes: map[string]string{
			"app_id":       "app-prod",
			"app_name":     "Production Console",
			"subject_id":   "00u-admin",
			"subject_type": "user",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	link := state.links["urn:cerebro:writer:okta_application:app-prod|"+relationGrantsEntitlement+"|urn:cerebro:writer:okta_entitlement:app_assignment:app-prod"]
	if link == nil {
		t.Fatal("app entitlement link missing")
	}
	if _, ok := link.Attributes["at"]; ok {
		t.Fatalf("link at attribute = %q, want omitted for unset OccurredAt", link.Attributes["at"])
	}
}

func TestProjectOktaReadOnlyAdminNamedAppDoesNotInferCloudAdmin(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "okta-readonly-admin-app",
		TenantId: "writer",
		SourceId: "okta",
		Kind:     "okta.app_assignment",
		Attributes: map[string]string{
			"app_id":       "app-view",
			"app_name":     "Admin View",
			"scope":        "read_only",
			"subject_id":   "00u-analyst",
			"subject_type": "user",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	entitlementURN := "urn:cerebro:writer:okta_entitlement:read_only"
	assertProjectedLink(t, state, entitlementURN, relationConfersCapability, "urn:cerebro:writer:privileged_capability:app_access")
	assertProjectedLinkMissing(t, state, entitlementURN, relationConfersCapability, "urn:cerebro:writer:privileged_capability:cloud_admin")
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
			Attributes: map[string]string{ // #nosec G101 -- test service-account key attributes are identifiers, not key material.
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
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_role:ReadOnlyAccess", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_credential:AKIAEXAMPLE", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com", relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_credential:projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
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
				"app_id":          "app-client-1",
				"display_name":    "Prod App",
				"domain":          "tenant-1",
				"login":           "app-client-1",
				"principal_type":  "service_principal",
				"subscription_id": "sub-1",
				"user_id":         "sp-1",
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
				"domain":          "tenant-1",
				"is_admin":        "false",
				"role_id":         "Reader",
				"role_name":       "Reader",
				"role_type":       "azure_rbac_role",
				"subscription_id": "sub-1",
				"subject_id":      "sp-1",
				"subject_type":    "service_principal",
			},
		},
		{
			Id:       "azure-credential",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.credential",
			Attributes: map[string]string{ // #nosec G101 -- test Azure credential attributes are identifiers, not secret material.
				"credential_id":   "app-password-1",
				"credential_type": "azure_application_password",
				"domain":          "tenant-1",
				"subscription_id": "sub-1",
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
		{
			Id:       "azure-activity",
			TenantId: "writer",
			SourceId: "azure",
			Kind:     "azure.activity_log",
			Attributes: map[string]string{
				"actor_id":      "sp-1",
				"event_type":    "Microsoft.Compute/virtualMachines/write",
				"resource_id":   "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1",
				"resource_name": "vm-1",
				"resource_type": "virtual_machine",
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
	assertProjectedLink(t, state, azureServicePrincipalURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_role:Reader", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_credential:app-password-1", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLinkMissing(t, state, azureUserURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:tenant-1")
	azureVMURN := "urn:cerebro:writer:azure_virtual_machine:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1"
	resourceGroupURN := "urn:cerebro:writer:azure_resource_group:sub-1:rg-prod"
	assertProjectedLink(t, state, azureVMURN, relationBelongsTo, resourceGroupURN)
	assertProjectedLink(t, state, resourceGroupURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
}

func TestProjectAzureActivitySkipsResourceGroupWithoutSubscription(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "azure-activity-no-subscription",
		TenantId: "writer",
		SourceId: "azure",
		Kind:     "azure.activity_log",
		Attributes: map[string]string{
			"event_type":     "Microsoft.Compute/virtualMachines/write",
			"resource_group": "rg-prod",
			"resource_id":    "vm-1",
			"resource_type":  "virtual_machine",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:azure_virtual_machine:vm-1", relationBelongsTo, "urn:cerebro:writer:azure_resource_group:rg-prod")
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
				"domain":               "123456789012",
				"endpoint_id":          "eni-1",
				"endpoint_type":        "public_network_interface",
				"external_exposure":    "true",
				"host":                 "ec2-203-0-113-10.compute-1.amazonaws.com",
				"internet_exposed":     "true",
				"ip":                   "203.0.113.10",
				"public":               "true",
				"resource_id":          "eni-1",
				"resource_name":        "prod-web-eni",
				"resource_provider":    "aws",
				"resource_type":        "network_interface",
				"target_host":          "d111111abcdef8.cloudfront.net",
				"alternate_hosts":      "app.writer.com",
				"attached_instance_id": "i-network-1",
			},
		},
		{
			Id:       "aws-public-eip",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.public_endpoint",
			Attributes: map[string]string{
				"associated_instance_id": "i-eip-1",
				"domain":                 "123456789012",
				"endpoint_id":            "eipalloc-1",
				"endpoint_type":          "public_ip",
				"external_exposure":      "true",
				"internet_exposed":       "true",
				"ip":                     "203.0.113.20",
				"public":                 "true",
				"resource_id":            "eipalloc-1",
				"resource_name":          "eipalloc-1",
				"resource_provider":      "aws",
				"resource_type":          "elastic_ip",
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
	assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:app.writer.com", relationBelongsTo, "urn:cerebro:writer:internet_domain:writer.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:d111111abcdef8.cloudfront.net", relationBelongsTo, "urn:cerebro:writer:internet_domain:d111111abcdef8.cloudfront.net")
	assertProjectedLink(t, state, "urn:cerebro:writer:internet_host:ec2-203-0-113-10.compute-1.amazonaws.com", relationResolvesTo, "urn:cerebro:writer:internet_ip:203.0.113.10")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationAttachedTo, "urn:cerebro:writer:aws_ec2_instance:i-network-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_elastic_ip:eipalloc-1", relationAssociatedWith, "urn:cerebro:writer:aws_ec2_instance:i-eip-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_role:arn:aws:iam::999999999999:role/ExternalAdmin", relationCanAssume, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_role:arn:aws:iam::999999999999:role/ExternalAdmin", relationRepresentsIdentity, "urn:cerebro:writer:identity:login:aws:999999999999:role:externaladmin")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_user:admin@writer.com", relationCanImpersonate, "urn:cerebro:writer:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_service_principal:sp-1", relationAssignedTo, "urn:cerebro:writer:azure_service_principal:sp-resource-1")
}

func TestProjectAWSComputeInventoryDepth(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-ec2-instance-i-123",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.ec2_instance",
			Attributes: map[string]string{
				"domain":                "123456789012",
				"eks_cluster_name":      "prod-eks",
				"eks_node":              "true",
				"eks_nodegroup_name":    "managed-linux",
				"eks_nodegroup_type":    "managed",
				"instance_id":           "i-123",
				"network_interface_ids": "eni-1",
				"region":                "us-east-1",
				"resource_id":           "i-123",
				"resource_name":         "prod-web",
				"resource_provider":     "aws",
				"resource_type":         "ec2_instance",
				"role_arn":              "arn:aws:iam::123456789012:role/WebInstanceRole",
				"role_name":             "WebInstanceRole",
				"security_group_ids":    "sg-1",
				"subnet_id":             "subnet-1",
				"vpc_id":                "vpc-1",
			},
		},
		{
			Id:       "aws-lambda-function-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.lambda_function",
			Attributes: map[string]string{
				"domain":             "123456789012",
				"function_arn":       "arn:aws:lambda:us-east-1:123456789012:function:orders",
				"function_name":      "orders",
				"resource_id":        "arn:aws:lambda:us-east-1:123456789012:function:orders",
				"resource_provider":  "aws",
				"resource_type":      "lambda_function",
				"role_arn":           "arn:aws:iam::123456789012:role/LambdaOrdersRole",
				"role_name":          "LambdaOrdersRole",
				"security_group_ids": "sg-lambda",
				"subnet_ids":         "subnet-lambda",
				"vpc_id":             "vpc-1",
			},
		},
		{
			Id:       "aws-ecs-service-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.ecs_service",
			Attributes: map[string]string{
				"cluster_arn":                     "arn:aws:ecs:us-east-1:123456789012:cluster/prod",
				"cluster_name":                    "prod",
				"domain":                          "123456789012",
				"assign_public_ip":                "ENABLED",
				"capacity_providers":              "FARGATE_SPOT",
				"fargate_service":                 "true",
				"launch_type_effective":           "FARGATE",
				"load_balancer_target_group_arns": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/orders/123",
				"resource_id":                     "arn:aws:ecs:us-east-1:123456789012:service/prod/orders",
				"resource_name":                   "orders",
				"resource_provider":               "aws",
				"resource_type":                   "ecs_service",
				"service_arn":                     "arn:aws:ecs:us-east-1:123456789012:service/prod/orders",
				"service_name":                    "orders",
				"task_definition_arn":             "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
			},
		},
		{
			Id:       "aws-ecs-task-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.ecs_task",
			Attributes: map[string]string{
				"cluster_arn":                "arn:aws:ecs:us-east-1:123456789012:cluster/prod",
				"cluster_name":               "prod",
				"domain":                     "123456789012",
				"capacity_provider_name":     "FARGATE_SPOT",
				"ephemeral_storage_size_gib": "40",
				"fargate_task":               "true",
				"launch_type":                "FARGATE",
				"network_interface_ids":      "eni-task",
				"resource_id":                "arn:aws:ecs:us-east-1:123456789012:task/prod/abcd1234",
				"resource_name":              "abcd1234",
				"resource_provider":          "aws",
				"resource_type":              "ecs_task",
				"security_group_ids":         "sg-task",
				"service_arn":                "arn:aws:ecs:us-east-1:123456789012:service/prod/orders",
				"service_name":               "orders",
				"subnet_ids":                 "subnet-task",
				"task_arn":                   "arn:aws:ecs:us-east-1:123456789012:task/prod/abcd1234",
				"task_definition_arn":        "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
				"vpc_id":                     "vpc-1",
			},
		},
		{
			Id:       "aws-ecs-task-definition-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.ecs_task_definition",
			Attributes: map[string]string{
				"domain":                     "123456789012",
				"awsvpc_required":            "true",
				"container_count":            "1",
				"ephemeral_storage_size_gib": "40",
				"execution_role_arn":         "arn:aws:iam::123456789012:role/ECSExecutionRole",
				"execution_role_name":        "ECSExecutionRole",
				"fargate_compatible":         "true",
				"resource_id":                "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
				"resource_name":              "orders",
				"resource_provider":          "aws",
				"resource_type":              "ecs_task_definition",
				"task_definition_arn":        "arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7",
				"runtime_cpu_architecture":   "ARM64",
				"task_role_arn":              "arn:aws:iam::123456789012:role/ECSTaskRole",
				"task_role_name":             "ECSTaskRole",
			},
		},
		{
			Id:       "aws-eks-cluster-prod",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.eks_cluster",
			Attributes: map[string]string{
				"cluster_arn":            "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
				"cluster_name":           "prod-eks",
				"domain":                 "123456789012",
				"endpoint_public_access": "true",
				"public_access_cidrs":    "0.0.0.0/0",
				"resource_id":            "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
				"resource_name":          "prod-eks",
				"resource_provider":      "aws",
				"resource_type":          "eks_cluster",
				"role_arn":               "arn:aws:iam::123456789012:role/EKSClusterRole",
				"role_name":              "EKSClusterRole",
				"security_group_ids":     "sg-eks,sg-eks-control",
				"subnet_ids":             "subnet-eks",
				"vpc_id":                 "vpc-1",
			},
		},
		{
			Id:       "aws-eks-nodegroup-managed-linux",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.eks_nodegroup",
			Attributes: map[string]string{
				"cluster_arn":        "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
				"cluster_name":       "prod-eks",
				"domain":             "123456789012",
				"desired_size":       "3",
				"health_issue_codes": "AsgInstanceLaunchFailures",
				"label_keys":         "workload",
				"nodegroup_arn":      "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid",
				"nodegroup_name":     "managed-linux",
				"resource_id":        "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid",
				"resource_name":      "managed-linux",
				"resource_provider":  "aws",
				"resource_type":      "eks_nodegroup",
				"role_arn":           "arn:aws:iam::123456789012:role/EKSNodeRole",
				"role_name":          "EKSNodeRole",
				"subnet_ids":         "subnet-eks",
			},
		},
		{
			Id:       "aws-eks-fargate-profile-payments",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.eks_fargate_profile",
			Attributes: map[string]string{
				"cluster_arn":          "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
				"cluster_name":         "prod-eks",
				"domain":               "123456789012",
				"fargate_profile_arn":  "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-eks/payments/uuid",
				"fargate_profile_name": "payments",
				"resource_id":          "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-eks/payments/uuid",
				"resource_name":        "payments",
				"resource_provider":    "aws",
				"resource_type":        "eks_fargate_profile",
				"role_arn":             "arn:aws:iam::123456789012:role/EKSFargatePodExecutionRole",
				"role_name":            "EKSFargatePodExecutionRole",
				"selector_namespaces":  "payments",
				"subnet_ids":           "subnet-eks",
			},
		},
		{
			Id:       "aws-eks-pod-identity-payments-api",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.eks_pod_identity_association",
			Attributes: map[string]string{
				"association_arn": "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-eks/a-123",
				"association_id":  "a-123",
				"cluster_arn":     "arn:aws:eks:us-east-1:123456789012:cluster/prod-eks",
				"cluster_name":    "prod-eks",
				"domain":          "123456789012",
				"namespace":       "payments",
				"resource_id":     "arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-eks/a-123",
				"resource_name":   "api",
				"resource_type":   "eks_pod_identity_association",
				"role_arn":        "arn:aws:iam::123456789012:role/EKSPaymentsPodRole",
				"role_name":       "EKSPaymentsPodRole",
				"service_account": "api",
			},
		},
		{
			Id:       "aws-ec2-instance-i-456",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.ec2_instance",
			Attributes: map[string]string{
				"domain":             "123456789012",
				"eks_cluster_name":   "prod-eks",
				"eks_node":           "true",
				"eks_nodegroup_name": "managed-linux",
				"instance_id":        "i-456",
				"region":             "us-east-1",
				"resource_id":        "i-456",
				"resource_name":      "later-node",
				"resource_provider":  "aws",
				"resource_type":      "ec2_instance",
				"state":              "running",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	ec2URN := "urn:cerebro:writer:aws_ec2_instance:i-123"
	lambdaURN := "urn:cerebro:writer:aws_lambda_function:arn:aws:lambda:us-east-1:123456789012:function:orders"
	ecsServiceURN := "urn:cerebro:writer:aws_ecs_service:arn:aws:ecs:us-east-1:123456789012:service/prod/orders"
	ecsTaskURN := "urn:cerebro:writer:aws_ecs_task:arn:aws:ecs:us-east-1:123456789012:task/prod/abcd1234"
	ecsTaskDefinitionURN := "urn:cerebro:writer:aws_ecs_task_definition:arn:aws:ecs:us-east-1:123456789012:task-definition/orders:7"
	eksClusterURN := "urn:cerebro:writer:aws_eks_cluster:arn:aws:eks:us-east-1:123456789012:cluster/prod-eks"
	eksClusterNameURN := "urn:cerebro:writer:aws_eks_cluster:prod-eks"
	eksNodegroupURN := "urn:cerebro:writer:aws_eks_nodegroup:arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid"
	eksNodegroupNameURN := "urn:cerebro:writer:aws_eks_nodegroup:prod-eks:managed-linux"
	eksFargateProfileURN := "urn:cerebro:writer:aws_eks_fargate_profile:arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-eks/payments/uuid"
	eksPodIdentityURN := "urn:cerebro:writer:aws_eks_pod_identity_association:arn:aws:eks:us-east-1:123456789012:podidentityassociation/prod-eks/a-123"
	kubernetesNamespaceURN := "urn:cerebro:writer:kubernetes_namespace:123456789012:prod-eks:payments"
	kubernetesServiceAccountURN := "urn:cerebro:writer:kubernetes_service_account:123456789012:prod-eks:payments:api"
	if entity := state.entities[ec2URN]; entity == nil || entity.EntityType != "aws.ec2.instance" {
		t.Fatalf("ec2 entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, ec2URN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, ec2URN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/WebInstanceRole")
	assertProjectedLink(t, state, ec2URN, relationBelongsTo, "urn:cerebro:writer:aws_vpc:vpc-1")
	assertProjectedLink(t, state, ec2URN, relationBelongsTo, "urn:cerebro:writer:aws_subnet:subnet-1")
	assertProjectedLink(t, state, ec2URN, relationMemberOf, "urn:cerebro:writer:aws_security_group:sg-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-1", relationAttachedTo, ec2URN)
	assertProjectedLink(t, state, ec2URN, relationBelongsTo, eksClusterNameURN)
	assertProjectedLink(t, state, eksClusterNameURN, relationRepresents, eksClusterURN)
	assertProjectedLink(t, state, ec2URN, relationBelongsTo, eksNodegroupNameURN)
	assertProjectedLink(t, state, eksNodegroupNameURN, relationRepresents, eksNodegroupURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_ec2_instance:i-456", relationBelongsTo, eksNodegroupNameURN)
	assertProjectedLink(t, state, lambdaURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/LambdaOrdersRole")
	assertProjectedLink(t, state, lambdaURN, relationMemberOf, "urn:cerebro:writer:aws_security_group:sg-lambda")
	if got := state.entities[ecsServiceURN].Attributes["fargate_service"]; got != "true" {
		t.Fatalf("ecs service fargate_service = %q, want true", got)
	}
	if got := state.entities[ecsServiceURN].Attributes["launch_type_effective"]; got != "FARGATE" {
		t.Fatalf("ecs service launch_type_effective = %q, want FARGATE", got)
	}
	assertProjectedLink(t, state, ecsServiceURN, relationBelongsTo, "urn:cerebro:writer:aws_ecs_cluster:arn:aws:ecs:us-east-1:123456789012:cluster/prod")
	assertProjectedLink(t, state, ecsServiceURN, relationDependsOn, ecsTaskDefinitionURN)
	if got := state.entities[ecsTaskURN].Attributes["fargate_task"]; got != "true" {
		t.Fatalf("ecs task fargate_task = %q, want true", got)
	}
	if got := state.entities[ecsTaskURN].Attributes["ephemeral_storage_size_gib"]; got != "40" {
		t.Fatalf("ecs task ephemeral_storage_size_gib = %q, want 40", got)
	}
	assertProjectedLink(t, state, ecsTaskURN, relationBelongsTo, "urn:cerebro:writer:aws_ecs_cluster:arn:aws:ecs:us-east-1:123456789012:cluster/prod")
	assertProjectedLink(t, state, ecsTaskURN, relationBelongsTo, ecsServiceURN)
	assertProjectedLink(t, state, ecsTaskURN, relationDependsOn, ecsTaskDefinitionURN)
	assertProjectedLink(t, state, ecsTaskURN, relationMemberOf, "urn:cerebro:writer:aws_security_group:sg-task")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_network_interface:eni-task", relationAttachedTo, ecsTaskURN)
	if got := state.entities[ecsTaskDefinitionURN].Attributes["fargate_compatible"]; got != "true" {
		t.Fatalf("ecs task definition fargate_compatible = %q, want true", got)
	}
	if got := state.entities[ecsTaskDefinitionURN].Attributes["awsvpc_required"]; got != "true" {
		t.Fatalf("ecs task definition awsvpc_required = %q, want true", got)
	}
	assertProjectedLink(t, state, ecsTaskDefinitionURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/ECSTaskRole")
	assertProjectedLink(t, state, ecsTaskDefinitionURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/ECSExecutionRole")
	assertProjectedLink(t, state, eksClusterURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/EKSClusterRole")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, eksClusterURN)
	if got := state.entities[eksNodegroupURN].Attributes["desired_size"]; got != "3" {
		t.Fatalf("eks nodegroup desired_size = %q, want 3", got)
	}
	if got := state.entities[eksNodegroupURN].Attributes["health_issue_codes"]; got != "AsgInstanceLaunchFailures" {
		t.Fatalf("eks nodegroup health_issue_codes = %q, want AsgInstanceLaunchFailures", got)
	}
	if got := state.entities[eksNodegroupURN].Attributes["resource_id"]; got != "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-eks/managed-linux/uuid" {
		t.Fatalf("eks nodegroup resource_id = %q, want nodegroup ARN", got)
	}
	if got := state.entities[eksNodegroupURN].Attributes["resource_type"]; got != "eks_nodegroup" {
		t.Fatalf("eks nodegroup resource_type = %q, want eks_nodegroup", got)
	}
	assertProjectedLink(t, state, eksNodegroupURN, relationBelongsTo, eksClusterURN)
	assertProjectedLink(t, state, eksNodegroupURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/EKSNodeRole")
	assertProjectedLink(t, state, eksFargateProfileURN, relationBelongsTo, eksClusterURN)
	assertProjectedLink(t, state, eksFargateProfileURN, relationRunsAs, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/EKSFargatePodExecutionRole")
	assertProjectedLink(t, state, eksFargateProfileURN, relationSupports, kubernetesNamespaceURN)
	assertProjectedLink(t, state, eksPodIdentityURN, relationBelongsTo, eksClusterURN)
	assertProjectedLink(t, state, eksPodIdentityURN, relationBelongsTo, kubernetesNamespaceURN)
	assertProjectedLink(t, state, eksPodIdentityURN, relationSupports, kubernetesServiceAccountURN)
	assertProjectedLink(t, state, kubernetesServiceAccountURN, relationCanAssume, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/EKSPaymentsPodRole")
}

func TestProjectAWSRuntimeEventResources(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-stepfunctions-state-machine-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.stepfunctions_state_machine",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       "arn:aws:states:us-east-1:123456789012:stateMachine:orders-workflow",
				"resource_name":     "orders-workflow",
				"resource_provider": "aws",
				"resource_type":     "stepfunctions_state_machine",
			},
		},
		{
			Id:       "aws-eventbridge-rule-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.eventbridge_rule",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       "arn:aws:events:us-east-1:123456789012:rule/orders/send-to-fulfillment",
				"resource_name":     "send-to-fulfillment",
				"resource_provider": "aws",
				"resource_type":     "eventbridge_rule",
			},
		},
		{
			Id:       "aws-scheduler-schedule-orders",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.scheduler_schedule",
			Attributes: map[string]string{
				"domain":            "123456789012",
				"resource_id":       "arn:aws:scheduler:us-east-1:123456789012:schedule/orders/hourly-reconcile",
				"resource_name":     "hourly-reconcile",
				"resource_provider": "aws",
				"resource_type":     "scheduler_schedule",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	for urn, entityType := range map[string]string{
		projectionURN("writer", "aws_stepfunctions_state_machine", "arn:aws:states:us-east-1:123456789012:stateMachine:orders-workflow"): "aws.stepfunctions.state.machine",
		projectionURN("writer", "aws_eventbridge_rule", "arn:aws:events:us-east-1:123456789012:rule/orders/send-to-fulfillment"):         "aws.eventbridge.rule",
		projectionURN("writer", "aws_scheduler_schedule", "arn:aws:scheduler:us-east-1:123456789012:schedule/orders/hourly-reconcile"):   "aws.scheduler.schedule",
	} {
		if entity := state.entities[urn]; entity == nil || entity.EntityType != entityType {
			t.Fatalf("projected entity %q = %#v, want type %q", urn, entity, entityType)
		}
		assertProjectedLink(t, state, urn, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	}
}

func TestProjectAWSOrganizationsHierarchyAndPolicies(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "aws-organizations-root-r-root",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.organizations_root",
			Attributes: map[string]string{
				"domain":       "111111111111",
				"policy_types": "SERVICE_CONTROL_POLICY:ENABLED",
				"resource_id":  "r-root",
				"root_arn":     "arn:aws:organizations::111111111111:root/o-exampleorgid/r-root",
				"root_id":      "r-root",
				"root_name":    "Root",
			},
		},
		{
			Id:       "aws-organizations-ou-security",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.organizations_organizational_unit",
			Attributes: map[string]string{
				"domain":      "111111111111",
				"ou_arn":      "arn:aws:organizations::111111111111:ou/o-exampleorgid/ou-r-root-security",
				"ou_id":       "ou-r-root-security",
				"ou_name":     "Security",
				"parent_id":   "r-root",
				"parent_type": "ROOT",
				"resource_id": "ou-r-root-security",
			},
		},
		{
			Id:       "aws-organizations-account-security",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.organizations_account",
			Attributes: map[string]string{
				"account_arn":   "arn:aws:organizations::111111111111:account/o-exampleorgid/222222222222",
				"account_email": "security@example.com",
				"account_id":    "222222222222",
				"account_name":  "Security",
				"domain":        "111111111111",
				"parent_id":     "ou-r-root-security",
				"parent_type":   "ORGANIZATIONAL_UNIT",
				"resource_id":   "222222222222",
				"state":         "ACTIVE",
			},
		},
		{
			Id:       "aws-organizations-policy-deny-leave",
			TenantId: "writer",
			SourceId: "aws",
			Kind:     "aws.organizations_policy",
			Attributes: map[string]string{
				"domain":       "111111111111",
				"policy_id":    "p-service-control",
				"policy_name":  "DenyLeaveOrganization",
				"policy_type":  "SERVICE_CONTROL_POLICY",
				"resource_id":  "p-service-control",
				"target_ids":   "ou-r-root-security,222222222222",
				"target_names": "Security,Security",
				"target_types": "ORGANIZATIONAL_UNIT,ACCOUNT",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	rootURN := "urn:cerebro:writer:aws_organizations_root:r-root"
	ouURN := "urn:cerebro:writer:aws_organizations_organizational_unit:ou-r-root-security"
	accountURN := "urn:cerebro:writer:aws_organizations_account:222222222222"
	policyURN := "urn:cerebro:writer:aws_organizations_policy:p-service-control"
	if entity := state.entities[rootURN]; entity == nil || entity.EntityType != "aws.organizations.root" {
		t.Fatalf("root entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, ouURN, relationBelongsTo, rootURN)
	assertProjectedLink(t, state, accountURN, relationBelongsTo, ouURN)
	assertProjectedLink(t, state, accountURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:222222222222")
	assertProjectedLink(t, state, policyURN, relationAttachedTo, ouURN)
	assertProjectedLink(t, state, policyURN, relationAttachedTo, accountURN)
}

func TestProjectAWSRestrictedEKSClusterDoesNotCreatePublicReachability(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	clusterURN := "urn:cerebro:writer:aws_eks_cluster:arn:aws:eks:us-east-1:123456789012:cluster/restricted-eks"
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-eks-cluster-restricted",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.eks_cluster",
		Attributes: map[string]string{
			"cluster_arn":            "arn:aws:eks:us-east-1:123456789012:cluster/restricted-eks",
			"cluster_name":           "restricted-eks",
			"domain":                 "123456789012",
			"endpoint_public_access": "true",
			"public_access_cidrs":    "203.0.113.0/24",
			"resource_id":            "arn:aws:eks:us-east-1:123456789012:cluster/restricted-eks",
			"resource_name":          "restricted-eks",
			"resource_provider":      "aws",
			"resource_type":          "eks_cluster",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_public_principal:public_internet", relationCanReach, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
}

func TestProjectAWSAccountTrustPrincipal(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-account-role-trust",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.iam_role_trust",
		Attributes: map[string]string{
			"domain":       "123456789012",
			"path_type":    "assume_role_trust",
			"relationship": "can_assume",
			"subject_id":   "999999999999",
			"subject_type": "account",
			"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
			"target_name":  "AdminRole",
			"target_type":  "role",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	accountURN := "urn:cerebro:writer:aws_account:999999999999"
	if entity := state.entities[accountURN]; entity == nil || entity.EntityType != "aws.account" {
		t.Fatalf("aws account principal entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, accountURN, relationCanAssume, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole")
}

func TestProjectAWSServiceTrustPrincipal(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-service-role-trust",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.iam_role_trust",
		Attributes: map[string]string{
			"domain":       "123456789012",
			"path_type":    "assume_role_trust",
			"relationship": "can_assume",
			"subject_id":   "lambda.amazonaws.com",
			"subject_type": "service_principal",
			"target_id":    "arn:aws:iam::123456789012:role/LambdaRole",
			"target_name":  "LambdaRole",
			"target_type":  "role",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	servicePrincipalURN := "urn:cerebro:writer:aws_service_principal:lambda.amazonaws.com"
	if entity := state.entities[servicePrincipalURN]; entity == nil || entity.EntityType != "aws.service_principal" {
		t.Fatalf("aws service principal entity missing or wrong type: %#v", entity)
	}
	assertProjectedLink(t, state, servicePrincipalURN, relationCanAssume, "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/LambdaRole")
}

func TestProjectAWSInlineEffectivePermission(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-inline-effective-permission",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "iam:*,s3:GetObject",
			"domain":        "123456789012",
			"effect":        "allow",
			"is_admin":      "true",
			"permission":    "iam:*,s3:GetObject",
			"policy_source": "inline",
			"resource_id":   "inline:user:admin@writer.com:InlineAdmin",
			"resource_name": "InlineAdmin",
			"resource_type": "aws_iam_policy",
			"role_id":       "inline:user:admin@writer.com:InlineAdmin",
			"role_name":     "InlineAdmin",
			"scope":         "arn:aws:s3:::writer-bucket",
			"subject_id":    "admin@writer.com",
			"subject_type":  "user",
		},
	}

	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	policyURN := "urn:cerebro:writer:aws_aws_iam_policy:inline:user:admin@writer.com:InlineAdmin"
	roleURN := "urn:cerebro:writer:aws_role:inline:user:admin@writer.com:InlineAdmin"
	permissionLink := state.links["urn:cerebro:writer:aws_user:admin@writer.com|"+relationCanPerform+"|"+policyURN]
	if permissionLink == nil {
		t.Fatalf("inline effective permission link missing")
	}
	if got := permissionLink.Attributes["actions"]; got != "iam:*,s3:GetObject" {
		t.Fatalf("permission link actions = %q, want inline actions", got)
	}
	if got := permissionLink.Attributes["policy_source"]; got != "inline" {
		t.Fatalf("permission link policy_source = %q, want inline", got)
	}
	if got := permissionLink.Attributes["is_admin"]; got != "true" {
		t.Fatalf("permission link is_admin = %q, want true", got)
	}
	if role := state.entities[roleURN]; role == nil || role.EntityType != "aws.role" {
		t.Fatalf("role entity missing or wrong type: %#v", role)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:admin@writer.com", relationAssignedTo, roleURN)
	assertProjectedLink(t, state, roleURN, relationCanPerform, policyURN)
	assertProjectedLink(t, state, roleURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLinkMissing(t, state, roleURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:arn:aws:s3:::writer-bucket")
}

func TestProjectAWSEffectivePermissionWithoutRoleIDSkipsRoleNode(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "aws-effective-permission-no-role-id",
		TenantId: "writer",
		SourceId: "aws",
		Kind:     "aws.effective_permission",
		Attributes: map[string]string{
			"actions":       "s3:GetObject",
			"domain":        "123456789012",
			"effect":        "allow",
			"permission":    "s3:GetObject",
			"policy_source": "managed",
			"resource_id":   "arn:aws:s3:::writer-bucket",
			"resource_name": "writer-bucket",
			"resource_type": "bucket",
			"role_name":     "ReadOnlyAccess",
			"subject_login": "analyst",
			"subject_id":    "analyst@writer.com",
			"subject_type":  "user",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	roleURN := "urn:cerebro:writer:aws_role:ReadOnlyAccess"
	if role := state.entities[roleURN]; role != nil {
		t.Fatalf("role entity should not be created when role_id is missing: %#v", role)
	}
	if role := state.entities["urn:cerebro:writer:aws_role"]; role != nil {
		t.Fatalf("placeholder role entity should not be created when role_id is missing: %#v", role)
	}
	resourceURN := "urn:cerebro:writer:aws_bucket:arn:aws:s3:::writer-bucket"
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationCanPerform, resourceURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_user:analyst@writer.com", relationRepresentsIdentity, "urn:cerebro:writer:identity:login:aws:123456789012:user:analyst")
}

func TestProjectKubernetesInfrastructureEntities(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "k8s-node",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.node",
			Attributes: map[string]string{
				"cluster_id":                "prod-cluster",
				"cluster_name":              "prod",
				"container_runtime_version": "containerd://1.7.0",
				"kubelet_version":           "v1.35.0",
				"node_name":                 "ip-10-0-1-10",
				"ready":                     "true",
			},
		},
		{
			Id:       "k8s-service",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.service",
			Attributes: map[string]string{
				"cluster_id":        "prod-cluster",
				"namespace":         "payments",
				"service_name":      "payments",
				"service_type":      "LoadBalancer",
				"load_balancer_ips": "198.51.100.20",
			},
		},
		{
			Id:       "k8s-ingress",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.ingress",
			Attributes: map[string]string{
				"backend_services":  "payments:443",
				"cluster_id":        "prod-cluster",
				"hosts":             "payments.example.com",
				"ingress_name":      "payments",
				"namespace":         "payments",
				"tls_secret_names":  "payments-tls",
				"load_balancer_ips": "198.51.100.30",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	nodeURN := "urn:cerebro:writer:kubernetes_node:prod-cluster:ip-10-0-1-10"
	serviceURN := "urn:cerebro:writer:kubernetes_service:prod-cluster:payments:payments"
	ingressURN := "urn:cerebro:writer:kubernetes_ingress:prod-cluster:payments:payments"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-cluster"
	if got := state.entities[nodeURN].EntityType; got != "kubernetes.node" {
		t.Fatalf("node entity type = %q", got)
	}
	if got := state.entities[serviceURN].Attributes["service_type"]; got != "LoadBalancer" {
		t.Fatalf("service_type = %q", got)
	}
	if got := state.entities[ingressURN].Attributes["tls_secret_names"]; got != "payments-tls" {
		t.Fatalf("tls_secret_names = %q", got)
	}
	assertProjectedLink(t, state, nodeURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, serviceURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, ingressURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, ingressURN, relationCanReach, serviceURN)
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

	permissionLink := state.links["urn:cerebro:writer:aws_user:admin@writer.com|"+relationCanPerform+"|urn:cerebro:writer:aws_account:123456789012"]
	if permissionLink == nil {
		t.Fatalf("effective permission link missing")
	}
	if got := permissionLink.Attributes["is_admin"]; got != "true" {
		t.Fatalf("permission link is_admin = %q, want true", got)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_account:123456789012", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1", relationRunsAs, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api", relationCanImpersonate, "urn:cerebro:writer:gcp_service_account:payments-sa@writer-prod.iam.gserviceaccount.com")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1", relationHasEvidence, "urn:cerebro:writer:runtime_evidence:evidence-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:runtime_evidence:evidence-1", relationObservedOn, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationHasClassification, "urn:cerebro:writer:data_classification:restricted")
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationTaggedAs, "urn:cerebro:writer:asset_tag:crown_jewel")
}

func TestProjectEvidenceCASIRISReferenceLinksCaseEvidence(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-ref",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":                       "123",
			"case_link_status":              "linked",
			"evidence_cas_blocks_count":     "3",
			"evidence_cas_commit_id":        "commit-1",
			"evidence_cas_content_type":     "application/x-tar",
			"evidence_cas_digest":           "sha256abc",
			"evidence_cas_manifest_version": "2",
			"evidence_cas_merkle_root":      "root",
			"evidence_cas_ref_type":         "evidencecas.manifest.v2",
			"evidence_cas_size_bytes":       "42",
			"evidence_cas_uri":              "evidencecas://cases/123/evidence/file-uuid",
			"evidence_id":                   "456",
			"evidence_type":                 "evidence_cas.artifact",
			"observed_at":                   "2026-06-08T00:00:00Z",
			"resource_entity_type":          "case",
			"resource_id":                   "123",
			"resource_link_status":          "linked",
			"resource_name":                 "IRIS case 123",
			"resource_type":                 "case",
			"resource_urn":                  "urn:cerebro:writer:case:123",
			"source_system":                 "iris",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	evidenceURN := "urn:cerebro:writer:runtime_evidence:456"
	evidence := state.entities[evidenceURN]
	if evidence == nil {
		t.Fatalf("runtime evidence entity %q missing", evidenceURN)
	}
	if got := evidence.Attributes["evidence_cas_uri"]; got != "evidencecas://cases/123/evidence/file-uuid" {
		t.Fatalf("evidence_cas_uri = %q", got)
	}
	if got := evidence.Attributes["source_system"]; got != "iris" {
		t.Fatalf("source_system = %q, want iris", got)
	}
	if got := state.entities["urn:cerebro:writer:case:123"].EntityType; got != "case" {
		t.Fatalf("case entity type = %q, want case", got)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:case:123", relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationObservedOn, "urn:cerebro:writer:case:123")
}

func TestProjectEvidenceCASPreservesRuntimeIdentityAndSourceCorrelation(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-ref",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":                  "case-123",
			"evidence_cas_commit_id":   "commit-1",
			"evidence_cas_digest":      "sha256abc",
			"evidence_cas_merkle_root": "root-1",
			"evidence_cas_ref_type":    "evidencecas.manifest.v2",
			"evidence_cas_uri":         "evidencecas://cases/case-123/evidence/evidence-456",
			"evidence_id":              "evidence-456",
			"occurred_at":              "2026-06-08T00:00:00Z",
			"observed_at":              "2026-06-08T00:01:00Z",
			"request_id":               "request-123",
			"case_link_status":         "linked",
			"resource_entity_type":     "aws.bucket",
			"resource_id":              "bucket-1",
			"resource_link_status":     "linked",
			"resource_name":            "bucket-1",
			"resource_type":            "bucket",
			"resource_urn":             "urn:cerebro:writer:aws_bucket:bucket-1",
			"source_event_id":          "iris-event-123",
			"source_runtime_id":        "iris-runtime",
			"source_system":            "iris",
			"trace_id":                 "trace-123",
			"traceparent":              "00-00000000000000000000000000000123-0000000000000123-01",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-456"
	evidence := state.entities[evidenceURN]
	if evidence == nil {
		t.Fatalf("runtime evidence entity %q missing", evidenceURN)
	}
	for key, want := range map[string]string{
		"tenant_id":                "writer",
		"case_id":                  "case-123",
		"evidence_id":              "evidence-456",
		"evidence_cas_uri":         "evidencecas://cases/case-123/evidence/evidence-456",
		"evidence_cas_digest":      "sha256abc",
		"evidence_cas_merkle_root": "root-1",
		"evidence_cas_commit_id":   "commit-1",
		"evidence_cas_ref_type":    "evidencecas.manifest.v2",
		"source_system":            "iris",
		"source_runtime_id":        "iris-runtime",
		"source_event_id":          "iris-event-123",
		"resource_urn":             "urn:cerebro:writer:aws_bucket:bucket-1",
		"request_id":               "request-123",
		"trace_id":                 "trace-123",
		"traceparent":              "00-00000000000000000000000000000123-0000000000000123-01",
		"occurred_at":              "2026-06-08T00:00:00Z",
		"observed_at":              "2026-06-08T00:01:00Z",
		"resource_link_status":     "linked",
		"case_link_status":         "linked",
	} {
		if got := evidence.Attributes[key]; got != want {
			t.Fatalf("evidence attribute %s = %q, want %q", key, got, want)
		}
	}
	if got := evidence.RuntimeID; got != "iris-runtime" {
		t.Fatalf("RuntimeID = %q, want iris-runtime", got)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_bucket:bucket-1", relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationObservedOn, "urn:cerebro:writer:aws_bucket:bucket-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:case:case-123", relationHasEvidence, evidenceURN)
	assertProjectedLink(t, state, evidenceURN, relationAssociatedWith, "urn:cerebro:writer:case:case-123")
	if result.EntitiesProjected != 3 || result.LinksProjected != 4 {
		t.Fatalf("projection counts = entities %d links %d, want 3 entities and 4 links", result.EntitiesProjected, result.LinksProjected)
	}
}

func TestProjectRuntimeEvidenceRejectsCrossTenantCerebroContextURNs(t *testing.T) {
	for _, tt := range []struct {
		name       string
		attrs      map[string]string
		wantInErr  string
		wantInErr2 string
	}{
		{
			name: "resource_urn",
			attrs: map[string]string{
				"evidence_id":          "evidence-cross-resource",
				"resource_entity_type": "aws.bucket",
				"resource_id":          "bucket-1",
				"resource_link_status": "linked",
				"resource_type":        "bucket",
				"resource_urn":         "urn:cerebro:victim:aws_bucket:bucket-1",
			},
			wantInErr:  "urn:cerebro:victim:aws_bucket:bucket-1",
			wantInErr2: "not projection tenant",
		},
		{
			name: "case_urn",
			attrs: map[string]string{
				"case_id":          "case-1",
				"case_link_status": "linked",
				"case_urn":         "urn:cerebro:victim:case:case-1",
				"evidence_id":      "evidence-cross-case",
			},
			wantInErr:  "urn:cerebro:victim:case:case-1",
			wantInErr2: "not projection tenant",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state := &projectionRecorder{}
			service := New(state, nil)
			_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
				Id:         "runtime-" + tt.name,
				TenantId:   "writer",
				SourceId:   "evidence_cas",
				Kind:       "runtime.evidence",
				Attributes: tt.attrs,
			})
			if err == nil {
				t.Fatal("Project() error = nil, want cross-tenant Cerebro URN error")
			}
			if got := err.Error(); !strings.Contains(got, tt.wantInErr) || !strings.Contains(got, tt.wantInErr2) {
				t.Fatalf("Project() error = %q", got)
			}
			if len(state.entities) != 0 || len(state.links) != 0 {
				t.Fatalf("Project() wrote entities=%d links=%d despite cross-tenant URN", len(state.entities), len(state.links))
			}
		})
	}
}

func TestProjectEvidenceCASReplayIsIdempotentAndConflictsAreRejected(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	event := &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-ref",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"evidence_cas_commit_id": "commit-1",
			"evidence_cas_digest":    "sha256abc",
			"evidence_cas_ref_type":  "evidencecas.manifest.v2",
			"evidence_cas_uri":       "evidencecas://cases/case-123/evidence/evidence-456",
			"evidence_id":            "evidence-456",
			"resource_link_status":   "linked",
			"resource_urn":           "urn:cerebro:writer:case:case-123",
			"source_event_id":        "iris-event-123",
			"source_runtime_id":      "iris-runtime",
		},
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(first) error = %v", err)
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(replay) error = %v", err)
	}
	if len(state.entities) != 2 {
		t.Fatalf("len(entities) after replay = %d, want 2", len(state.entities))
	}
	if len(state.links) != 2 {
		t.Fatalf("len(links) after replay = %d, want 2", len(state.links))
	}

	conflicting := &cerebrov1.EventEnvelope{
		Id:         event.GetId(),
		TenantId:   event.GetTenantId(),
		SourceId:   event.GetSourceId(),
		Kind:       event.GetKind(),
		Attributes: cloneStringMap(event.Attributes),
	}
	conflicting.Attributes["evidence_cas_digest"] = "sha256different"
	stderr := captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), conflicting)
		if err == nil {
			t.Fatalf("Project(conflict) error = nil, want conflict")
		}
	})
	payload := sourceProjectionTelemetryPayload(t, stderr)
	if got := payload["outcome"]; got != "conflict" {
		t.Fatalf("conflict telemetry outcome = %v, want conflict", got)
	}
	if got := payload["conflict_category"]; got != "evidence_cas_digest" {
		t.Fatalf("conflict_category = %v, want evidence_cas_digest", got)
	}
	if strings.Contains(stderr, "sha256different") || strings.Contains(stderr, "evidence-456") || strings.Contains(stderr, "iris-event-123") {
		t.Fatalf("conflict telemetry leaked high-cardinality identifiers: %s", stderr)
	}
	if got := state.entities["urn:cerebro:writer:runtime_evidence:evidence-456"].Attributes["evidence_cas_digest"]; got != "sha256abc" {
		t.Fatalf("digest after conflict = %q, want original sha256abc", got)
	}

	conflictingID := &cerebrov1.EventEnvelope{
		Id:       event.GetId(),
		TenantId: event.GetTenantId(),
		SourceId: event.GetSourceId(),
		Kind:     event.GetKind(),
		Attributes: map[string]string{
			"evidence_cas_commit_id": "commit-1",
			"evidence_cas_digest":    "sha256abc",
			"evidence_cas_ref_type":  "evidencecas.manifest.v2",
			"evidence_cas_uri":       "evidencecas://cases/case-123/evidence/evidence-789",
			"evidence_id":            "evidence-789",
			"resource_urn":           "urn:cerebro:writer:case:case-123",
			"source_event_id":        "iris-event-123",
			"source_runtime_id":      "iris-runtime",
		},
	}
	stderr = captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), conflictingID)
		if err == nil {
			t.Fatalf("Project(conflicting evidence_id) error = nil, want conflict")
		}
	})
	payload = sourceProjectionTelemetryPayload(t, stderr)
	if got := payload["outcome"]; got != "conflict" {
		t.Fatalf("conflicting evidence_id telemetry outcome = %v, want conflict", got)
	}
	if got := payload["conflict_category"]; got != "evidence_id" {
		t.Fatalf("conflicting evidence_id conflict_category = %v, want evidence_id", got)
	}
	if _, ok := state.entities["urn:cerebro:writer:runtime_evidence:evidence-789"]; ok {
		t.Fatalf("conflicting duplicate source_event_id created second runtime evidence")
	}
}

func TestProjectEvidenceCASMissingLinksAreObservableAndBounded(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	stderr := captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "iris-evidence-orphan",
			TenantId: "writer",
			SourceId: "evidence_cas",
			Kind:     "evidence_cas.object",
			Attributes: map[string]string{
				"case_id":                 "case-missing",
				"evidence_cas_digest":     "sha256orphan",
				"evidence_cas_ref_type":   "evidencecas.manifest.v2",
				"evidence_cas_uri":        "evidencecas://cases/case-missing/evidence/evidence-orphan",
				"evidence_id":             "evidence-orphan",
				"source_event_id":         "iris-event-orphan",
				"source_runtime_id":       "iris-runtime",
				"source_system":           "iris",
				"unresolved_case_context": "true",
			},
		})
		if err != nil {
			t.Fatalf("Project() error = %v", err)
		}
	})
	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-orphan"
	evidence := state.entities[evidenceURN]
	if evidence == nil {
		t.Fatalf("runtime evidence entity %q missing", evidenceURN)
	}
	if got := evidence.Attributes["resource_link_status"]; got != "missing" {
		t.Fatalf("resource_link_status = %q, want missing", got)
	}
	if got := evidence.Attributes["case_link_status"]; got != "missing" {
		t.Fatalf("case_link_status = %q, want missing", got)
	}
	if _, ok := state.entities["urn:cerebro:writer:runtime_resource:evidence-orphan"]; ok {
		t.Fatalf("unexpected synthetic fallback resource for orphan evidence")
	}
	if len(state.links) != 0 {
		t.Fatalf("len(links) = %d, want 0 for unresolved resource/case", len(state.links))
	}

	payload := sourceProjectionTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"outcome":              "projected",
		"resource_link_status": "missing",
		"case_link_status":     "missing",
		"orphan_count":         float64(1),
		"missing_case_count":   float64(1),
		"entities_projected":   float64(1),
		"links_projected":      float64(0),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v (payload %#v)", key, got, want, payload)
		}
	}
	linkPayload := sourceProjectionTelemetryEventPayload(t, stderr, "runtime.evidence.link_status")
	for key, want := range map[string]any{
		"source_id":            "evidence_cas",
		"runtime_id":           "iris-runtime",
		"link_status":          "orphan",
		"resource_link_status": "missing",
		"case_link_status":     "missing",
		"orphan_count":         float64(1),
		"missing_case_count":   float64(1),
	} {
		if got := linkPayload[key]; got != want {
			t.Fatalf("link telemetry %s = %#v, want %#v (payload %#v)", key, got, want, linkPayload)
		}
	}
	for _, prohibited := range []string{"evidence-orphan", "iris-event-orphan", "sha256orphan", "evidencecas://", "case-missing"} {
		if strings.Contains(stderr, prohibited) {
			t.Fatalf("telemetry leaked high-cardinality value %q: %s", prohibited, stderr)
		}
	}

	stderr = captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "iris-evidence-unresolved-resource",
			TenantId: "writer",
			SourceId: "evidence_cas",
			Kind:     "evidence_cas.object",
			Attributes: map[string]string{
				"case_id":               "case-unresolved",
				"case_link_status":      "missing",
				"evidence_cas_digest":   "sha256unresolved",
				"evidence_cas_ref_type": "evidencecas.manifest.v2",
				"evidence_cas_uri":      "evidencecas://cases/case-unresolved/evidence/evidence-unresolved",
				"evidence_id":           "evidence-unresolved",
				"resource_link_status":  "missing",
				"resource_urn":          "urn:cerebro:writer:aws_bucket:missing-bucket",
				"source_event_id":       "iris-event-unresolved",
				"source_runtime_id":     "iris-runtime",
				"source_system":         "iris",
			},
		})
		if err != nil {
			t.Fatalf("Project(unresolved resource) error = %v", err)
		}
	})
	unresolvedEvidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-unresolved"
	unresolvedEvidence := state.entities[unresolvedEvidenceURN]
	if unresolvedEvidence == nil {
		t.Fatalf("runtime evidence entity %q missing", unresolvedEvidenceURN)
	}
	if got := unresolvedEvidence.Attributes["resource_link_status"]; got != "missing" {
		t.Fatalf("unresolved resource_link_status = %q, want missing", got)
	}
	if got := unresolvedEvidence.Attributes["case_link_status"]; got != "missing" {
		t.Fatalf("unresolved case_link_status = %q, want missing", got)
	}
	if _, ok := state.entities["urn:cerebro:writer:aws_bucket:missing-bucket"]; ok {
		t.Fatalf("unexpected fabricated resource entity for unresolved resource_urn")
	}
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_bucket:missing-bucket", relationHasEvidence, unresolvedEvidenceURN)
	assertProjectedLinkMissing(t, state, unresolvedEvidenceURN, relationObservedOn, "urn:cerebro:writer:aws_bucket:missing-bucket")
	if _, ok := state.entities["urn:cerebro:writer:case:case-unresolved"]; ok {
		t.Fatalf("unexpected fabricated case entity for unresolved case_id")
	}
	payload = sourceProjectionTelemetryPayload(t, stderr)
	if got := payload["resource_link_status"]; got != "missing" {
		t.Fatalf("unresolved resource telemetry status = %v, want missing", got)
	}
	if got := payload["case_link_status"]; got != "missing" {
		t.Fatalf("unresolved case telemetry status = %v, want missing", got)
	}

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-resource-only",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":                 "case-missing-resource-ok",
			"evidence_cas_digest":     "sha256resource",
			"evidence_cas_ref_type":   "evidencecas.manifest.v2",
			"evidence_cas_uri":        "evidencecas://cases/case-missing-resource-ok/evidence/evidence-resource",
			"evidence_id":             "evidence-resource",
			"resource_entity_type":    "aws.bucket",
			"resource_link_status":    "linked",
			"resource_urn":            "urn:cerebro:writer:aws_bucket:linked-bucket",
			"source_event_id":         "iris-event-resource",
			"source_runtime_id":       "iris-runtime",
			"source_system":           "iris",
			"unresolved_case_context": "true",
		},
	})
	if err != nil {
		t.Fatalf("Project(resource only) error = %v", err)
	}
	resourceEvidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-resource"
	if got := state.entities[resourceEvidenceURN].Attributes["resource_link_status"]; got != "linked" {
		t.Fatalf("resource-only resource_link_status = %q, want linked", got)
	}
	if got := state.entities[resourceEvidenceURN].Attributes["case_link_status"]; got != "missing" {
		t.Fatalf("resource-only case_link_status = %q, want missing", got)
	}
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_bucket:linked-bucket", relationHasEvidence, resourceEvidenceURN)
	assertProjectedLink(t, state, resourceEvidenceURN, relationObservedOn, "urn:cerebro:writer:aws_bucket:linked-bucket")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:case:case-missing-resource-ok", relationHasEvidence, resourceEvidenceURN)
}

func TestProjectEvidenceCASRequiresExplicitLinkabilityBeforeCreatingContextEntities(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	stderr := captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "iris-evidence-implicit-context",
			TenantId: "writer",
			SourceId: "evidence_cas",
			Kind:     "evidence_cas.object",
			Attributes: map[string]string{
				"case_id":               "case-implicit",
				"evidence_cas_digest":   "sha256implicit",
				"evidence_cas_ref_type": "evidencecas.manifest.v2",
				"evidence_cas_uri":      "evidencecas://cases/case-implicit/evidence/evidence-implicit",
				"evidence_id":           "evidence-implicit",
				"resource_urn":          "urn:cerebro:writer:aws_bucket:implicit-bucket",
				"source_event_id":       "iris-event-implicit",
				"source_runtime_id":     "iris-runtime",
				"source_system":         "iris",
			},
		})
		if err != nil {
			t.Fatalf("Project(implicit context) error = %v", err)
		}
	})

	evidenceURN := "urn:cerebro:writer:runtime_evidence:evidence-implicit"
	evidence := state.entities[evidenceURN]
	if evidence == nil {
		t.Fatalf("runtime evidence entity %q missing", evidenceURN)
	}
	if got := evidence.Attributes["resource_link_status"]; got != "missing" {
		t.Fatalf("resource_link_status = %q, want missing when linkability is not explicit", got)
	}
	if got := evidence.Attributes["case_link_status"]; got != "missing" {
		t.Fatalf("case_link_status = %q, want missing when linkability is not explicit", got)
	}
	if _, ok := state.entities["urn:cerebro:writer:aws_bucket:implicit-bucket"]; ok {
		t.Fatalf("unexpected resource entity fabricated from unresolved EvidenceCAS resource_urn")
	}
	if _, ok := state.entities["urn:cerebro:writer:case:case-implicit"]; ok {
		t.Fatalf("unexpected case entity fabricated from unresolved EvidenceCAS case_id")
	}
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_bucket:implicit-bucket", relationHasEvidence, evidenceURN)
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:case:case-implicit", relationHasEvidence, evidenceURN)

	payload := sourceProjectionTelemetryPayload(t, stderr)
	if got := payload["resource_link_status"]; got != "missing" {
		t.Fatalf("resource_link_status telemetry = %v, want missing", got)
	}
	if got := payload["case_link_status"]; got != "missing" {
		t.Fatalf("case_link_status telemetry = %v, want missing", got)
	}
	for _, prohibited := range []string{"implicit-bucket", "case-implicit", "evidence-implicit", "iris-event-implicit", "sha256implicit"} {
		if strings.Contains(stderr, prohibited) {
			t.Fatalf("telemetry leaked high-cardinality value %q: %s", prohibited, stderr)
		}
	}
}

func TestProjectEvidenceCASTenantScopedLinksForCollidingIdentifiers(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "iris-evidence-ref-" + tenantID,
			TenantId: tenantID,
			SourceId: "evidence_cas",
			Kind:     "evidence_cas.object",
			Attributes: map[string]string{
				"case_id":               "case-1",
				"evidence_cas_digest":   "sha256" + tenantID,
				"evidence_cas_ref_type": "evidencecas.manifest.v2",
				"evidence_cas_uri":      "evidencecas://cases/case-1/evidence/evidence-1",
				"evidence_id":           "evidence-1",
				"resource_link_status":  "linked",
				"resource_urn":          "urn:cerebro:" + tenantID + ":case:case-1",
				"source_event_id":       "event-1",
				"source_runtime_id":     "runtime-1",
			},
		})
		if err != nil {
			t.Fatalf("Project(%s) error = %v", tenantID, err)
		}
	}
	assertProjectedLink(t, state, "urn:cerebro:tenant-a:case:case-1", relationHasEvidence, "urn:cerebro:tenant-a:runtime_evidence:evidence-1")
	assertProjectedLink(t, state, "urn:cerebro:tenant-b:case:case-1", relationHasEvidence, "urn:cerebro:tenant-b:runtime_evidence:evidence-1")
	assertProjectedLinkMissing(t, state, "urn:cerebro:tenant-a:case:case-1", relationHasEvidence, "urn:cerebro:tenant-b:runtime_evidence:evidence-1")
	assertProjectedLinkMissing(t, state, "urn:cerebro:tenant-b:case:case-1", relationHasEvidence, "urn:cerebro:tenant-a:runtime_evidence:evidence-1")
}

func TestProjectEvidenceCASStampsNormalizedLinkState(t *testing.T) {
	linkedState := &projectionRecorder{}
	service := New(linkedState, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-linked",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":               "case-linked",
			"case_link_status":      "linked",
			"evidence_cas_digest":   "sha256linked",
			"evidence_cas_ref_type": "evidencecas.manifest.v2",
			"evidence_cas_uri":      "evidencecas://cases/case-linked/evidence/evidence-linked",
			"evidence_id":           "evidence-linked",
			"resource_entity_type":  "case",
			"resource_link_status":  "linked",
			"resource_urn":          "urn:cerebro:writer:case:case-linked",
			"source_event_id":       "iris-event-linked",
			"source_runtime_id":     "iris-runtime",
			"source_system":         "iris",
		},
	}); err != nil {
		t.Fatalf("Project(linked) error = %v", err)
	}
	linked := linkedState.entities["urn:cerebro:writer:runtime_evidence:evidence-linked"]
	if linked == nil {
		t.Fatal("linked runtime evidence entity missing")
	}
	if got := linked.Attributes["evidence_link_state"]; got != "linked" {
		t.Fatalf("linked evidence_link_state = %q, want linked", got)
	}

	unresolvedState := &projectionRecorder{}
	service = New(unresolvedState, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-unresolved",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":                 "case-unresolved",
			"evidence_cas_digest":     "sha256unresolved",
			"evidence_cas_ref_type":   "evidencecas.manifest.v2",
			"evidence_cas_uri":        "evidencecas://cases/case-unresolved/evidence/evidence-unresolved",
			"evidence_id":             "evidence-unresolved",
			"resource_urn":            "urn:cerebro:writer:case:case-unresolved",
			"source_event_id":         "iris-event-unresolved",
			"source_runtime_id":       "iris-runtime",
			"source_system":           "iris",
			"unresolved_case_context": "true",
		},
	}); err != nil {
		t.Fatalf("Project(unresolved) error = %v", err)
	}
	unresolved := unresolvedState.entities["urn:cerebro:writer:runtime_evidence:evidence-unresolved"]
	if unresolved == nil {
		t.Fatal("unresolved runtime evidence entity missing")
	}
	if got := unresolved.Attributes["evidence_link_state"]; got != "unresolved" {
		t.Fatalf("unresolved evidence_link_state = %q, want unresolved", got)
	}

	blankCaseStatusState := &projectionRecorder{}
	service = New(blankCaseStatusState, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-blank-case-status",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"case_id":               "case-blank-status",
			"evidence_cas_digest":   "sha256blankstatus",
			"evidence_cas_ref_type": "evidencecas.manifest.v2",
			"evidence_cas_uri":      "evidencecas://cases/case-blank-status/evidence/evidence-blank-status",
			"evidence_id":           "evidence-blank-status",
			"source_event_id":       "iris-event-blank-status",
			"source_runtime_id":     "iris-runtime",
			"source_system":         "iris",
		},
	}); err != nil {
		t.Fatalf("Project(blank case status) error = %v", err)
	}
	blankCaseStatus := blankCaseStatusState.entities["urn:cerebro:writer:runtime_evidence:evidence-blank-status"]
	if blankCaseStatus == nil {
		t.Fatal("blank case status runtime evidence entity missing")
	}
	if got := blankCaseStatus.Attributes["case_link_status"]; got != "missing" {
		t.Fatalf("blank case status case_link_status = %q, want missing", got)
	}
	if got := blankCaseStatus.Attributes["evidence_link_state"]; got != "unresolved" {
		t.Fatalf("blank case status evidence_link_state = %q, want unresolved", got)
	}

	bareState := &projectionRecorder{}
	service = New(bareState, nil)
	if _, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "iris-evidence-bare",
		TenantId: "writer",
		SourceId: "evidence_cas",
		Kind:     "evidence_cas.object",
		Attributes: map[string]string{
			"evidence_cas_digest":   "sha256bare",
			"evidence_cas_ref_type": "evidencecas.manifest.v2",
			"evidence_cas_uri":      "evidencecas://evidence/evidence-bare",
			"evidence_id":           "evidence-bare",
			"resource_link_status":  "missing",
			"source_event_id":       "iris-event-bare",
			"source_runtime_id":     "iris-runtime",
			"source_system":         "iris",
		},
	}); err != nil {
		t.Fatalf("Project(bare) error = %v", err)
	}
	bare := bareState.entities["urn:cerebro:writer:runtime_evidence:evidence-bare"]
	if bare == nil {
		t.Fatal("bare runtime evidence entity missing")
	}
	if got := bare.Attributes["evidence_link_state"]; got != "linked" {
		t.Fatalf("bare evidence_link_state = %q, want linked", got)
	}
}

func TestProjectKubernetesWorkloadBuildsClusterAndCloudAccountLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-workload-cluster",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload",
		Attributes: map[string]string{
			"cloud_account_external_id": "123456789012",
			"cloud_provider":            "aws",
			"cluster_id":                "prod-cluster",
			"image":                     "registry.example.com/payments-api@sha256:abc123",
			"image_digest":              "sha256:abc123",
			"namespace":                 "payments",
			"node_name":                 "ip-10-0-1-10",
			"service_account_name":      "api",
			"workload_kind":             "Deployment",
			"workload_name":             "payments-api",
			"workload_uid":              "workload-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-cluster"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	workloadURN := "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:workload-1"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api"
	nodeURN := "urn:cerebro:writer:kubernetes_node:prod-cluster:ip-10-0-1-10"
	imageURN := "urn:cerebro:writer:trivy_image:sha256:abc123"
	assertProjectedLink(t, state, namespaceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, serviceAccountURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, nodeURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, workloadURN, relationAssociatedWith, nodeURN)
	assertProjectedLink(t, state, workloadURN, relationDependsOn, imageURN)
	if got := state.entities[clusterURN].EntityType; got != "kubernetes.cluster" {
		t.Fatalf("cluster entity_type = %q, want kubernetes.cluster", got)
	}
}

func TestProjectKubernetesContainerLinksWorkloadNodeAndImage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-container",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.container",
		Attributes: map[string]string{
			"cluster_id":     "prod-cluster",
			"container_name": "api",
			"image":          "registry.example.com/payments-api@sha256:abc123",
			"image_digest":   "sha256:abc123",
			"namespace":      "payments",
			"node_name":      "ip-10-0-1-10",
			"resource_id":    "pod-uid-1",
			"status_ready":   "true",
			"workload_kind":  "Pod",
			"workload_name":  "payments-api",
			"workload_uid":   "pod-uid-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	containerURN := "urn:cerebro:writer:kubernetes_container:prod-cluster:payments:pod-uid-1:api"
	workloadURN := "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:pod-uid-1"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	nodeURN := "urn:cerebro:writer:kubernetes_node:prod-cluster:ip-10-0-1-10"
	imageURN := "urn:cerebro:writer:trivy_image:sha256:abc123"
	if entity := state.entities[containerURN]; entity == nil || entity.EntityType != "kubernetes.container" {
		t.Fatalf("container entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, containerURN, relationBelongsTo, workloadURN)
	assertProjectedLink(t, state, containerURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, workloadURN, relationContains, containerURN)
	assertProjectedLink(t, state, workloadURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, nodeURN, relationBelongsTo, "urn:cerebro:writer:kubernetes_cluster:prod-cluster")
	assertProjectedLink(t, state, containerURN, relationAssociatedWith, nodeURN)
	assertProjectedLink(t, state, containerURN, relationDependsOn, imageURN)
}

func TestProjectKubernetesPodLinksNamespaceServiceAccountNodeAndImage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-pod",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.pod",
		Attributes: map[string]string{
			"cloud_account_external_id": "123456789012",
			"cloud_provider":            "aws",
			"cluster_id":                "prod-cluster",
			"image":                     "registry.example.com/payments-api@sha256:abc123",
			"image_digest":              "sha256:abc123",
			"namespace":                 "payments",
			"node_name":                 "ip-10-0-1-10",
			"resource_id":               "pod-uid-1",
			"resource_name":             "payments-api-abc123",
			"service_account_name":      "api",
			"uid":                       "pod-uid-1",
			"workload_kind":             "Pod",
			"workload_name":             "payments-api-abc123",
			"workload_uid":              "pod-uid-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	podURN := "urn:cerebro:writer:kubernetes_pod:prod-cluster:payments:pod-uid-1"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-cluster"
	nodeURN := "urn:cerebro:writer:kubernetes_node:prod-cluster:ip-10-0-1-10"
	imageURN := "urn:cerebro:writer:trivy_image:sha256:abc123"
	if entity := state.entities[podURN]; entity == nil || entity.EntityType != "kubernetes.pod" {
		t.Fatalf("pod entity missing or wrong: %#v", entity)
	}
	assertProjectedLink(t, state, podURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, podURN, relationRunsAs, serviceAccountURN)
	assertProjectedLink(t, state, serviceAccountURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, namespaceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, nodeURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, podURN, relationAssociatedWith, nodeURN)
	assertProjectedLink(t, state, podURN, relationDependsOn, imageURN)
}

func TestProjectKubernetesWorkloadIdentityBindingAddsContainmentLinks(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-wid-cluster",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload_identity_binding",
		Attributes: map[string]string{
			"cloud_provider":       "gcp",
			"cluster_id":           "prod-cluster",
			"gcp_project_id":       "writer-prod",
			"namespace":            "payments",
			"relationship":         "can_impersonate",
			"service_account_name": "api",
			"target_email":         "payments-sa@writer-prod.iam.gserviceaccount.com",
			"target_id":            "payments-sa@writer-prod.iam.gserviceaccount.com",
			"target_type":          "service_account",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-cluster"
	assertProjectedLink(t, state, serviceAccountURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, namespaceURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, clusterURN, relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
	targetURN := "urn:cerebro:writer:gcp_service_account:payments-sa@writer-prod.iam.gserviceaccount.com"
	targetIdentityURN := "urn:cerebro:writer:identity:email:payments-sa@writer-prod.iam.gserviceaccount.com"
	assertProjectedLink(t, state, serviceAccountURN, relationCanImpersonate, targetURN)
	assertProjectedLink(t, state, targetURN, relationRepresentsIdentity, targetIdentityURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:identifier:email:payments-sa@writer-prod.iam.gserviceaccount.com", relationRepresentsIdentity, targetIdentityURN)
}

func TestProjectKubernetesRBACBindingLinksSubjectsToRole(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-rbac-binding",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.rbac_binding",
		Attributes: map[string]string{
			"binding_kind": "RoleBinding",
			"binding_name": "secret-reader-binding",
			"cluster_id":   "prod-cluster",
			"namespace":    "payments",
			"role_kind":    "Role",
			"role_name":    "secret-reader",
			"subject_refs": "ServiceAccount:payments/api;ServiceAccount:platform/deployer;User:arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	bindingURN := "urn:cerebro:writer:kubernetes_rbac_binding:prod-cluster:RoleBinding:payments:secret-reader-binding"
	roleURN := "urn:cerebro:writer:kubernetes_rbac_role:prod-cluster:Role:payments:secret-reader"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api"
	crossNamespaceServiceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:platform:deployer"
	userURN := "urn:cerebro:writer:kubernetes_user:prod-cluster:arn:aws:sts::123456789012:assumed-role/Admin/alice@example.com"
	namespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:payments"
	crossNamespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:platform"
	assertProjectedLink(t, state, bindingURN, relationAttachedTo, roleURN)
	assertProjectedLink(t, state, bindingURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, serviceAccountURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, crossNamespaceServiceAccountURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, userURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, serviceAccountURN, relationBelongsTo, namespaceURN)
	assertProjectedLink(t, state, crossNamespaceServiceAccountURN, relationBelongsTo, crossNamespaceURN)
	assertProjectedLinkMissing(t, state, crossNamespaceServiceAccountURN, relationBelongsTo, namespaceURN)
}

func TestProjectKubernetesRBACBindingJSONSubjectRefsDoNotInjectSubjects(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-rbac-binding-injection",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.rbac_binding",
		Attributes: map[string]string{
			"binding_kind": "RoleBinding",
			"binding_name": "secret-reader-binding",
			"cluster_id":   "prod-cluster",
			"namespace":    "payments",
			"role_kind":    "Role",
			"role_name":    "secret-reader",
			"subject_refs": `[{"kind":"User","name":"alice@example.com;ServiceAccount:payments/admin"},{"kind":"ServiceAccount","namespace":"payments","name":"api"}]`,
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	roleURN := "urn:cerebro:writer:kubernetes_rbac_role:prod-cluster:Role:payments:secret-reader"
	serviceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api"
	userURN := "urn:cerebro:writer:kubernetes_user:prod-cluster:alice@example.com;ServiceAccount:payments/admin"
	injectedServiceAccountURN := "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:admin"
	assertProjectedLink(t, state, serviceAccountURN, relationAssignedTo, roleURN)
	assertProjectedLink(t, state, userURN, relationAssignedTo, roleURN)
	assertProjectedLinkMissing(t, state, injectedServiceAccountURN, relationAssignedTo, roleURN)
	if entity := state.entities[injectedServiceAccountURN]; entity != nil {
		t.Fatalf("injected service account entity should not be created: %#v", entity)
	}
}

func TestProjectKubernetesRBACClusterRoleBindingStaysClusterScoped(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-cluster-rbac-binding",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.rbac_binding",
		Attributes: map[string]string{
			"binding_kind": "ClusterRoleBinding",
			"binding_name": "cluster-admin-binding",
			"cluster_id":   "prod-cluster",
			"role_kind":    "ClusterRole",
			"role_name":    "cluster-admin",
			"subject_refs": "Group:system:masters",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	bindingURN := "urn:cerebro:writer:kubernetes_rbac_binding:prod-cluster:ClusterRoleBinding:cluster:cluster-admin-binding"
	roleURN := "urn:cerebro:writer:kubernetes_rbac_role:prod-cluster:ClusterRole:cluster:cluster-admin"
	clusterURN := "urn:cerebro:writer:kubernetes_cluster:prod-cluster"
	groupURN := "urn:cerebro:writer:kubernetes_group:prod-cluster:system:masters"
	defaultNamespaceURN := "urn:cerebro:writer:kubernetes_namespace:prod-cluster:default"
	assertProjectedLink(t, state, bindingURN, relationAttachedTo, roleURN)
	assertProjectedLink(t, state, bindingURN, relationBelongsTo, clusterURN)
	assertProjectedLink(t, state, groupURN, relationAssignedTo, roleURN)
	assertProjectedLinkMissing(t, state, defaultNamespaceURN, relationBelongsTo, clusterURN)
	if entity := state.entities[defaultNamespaceURN]; entity != nil {
		t.Fatalf("default namespace entity should not be created for cluster-scoped RBAC: %#v", entity)
	}
}

func TestProjectKubernetesWorkloadFallbackURNIncludesKind(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, kind := range []string{"Deployment", "CronJob"} {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "k8s-workload-" + kind,
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"cluster_id":           "prod-cluster",
				"name":                 "payments-api",
				"namespace":            "payments",
				"service_account_name": "api",
				"workload_kind":        kind,
				"workload_name":        "payments-api",
			},
		})
		if err != nil {
			t.Fatalf("Project() error = %v", err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:Deployment/payments-api", relationRunsAs, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:CronJob/payments-api", relationRunsAs, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:payments-api", relationRunsAs, "urn:cerebro:writer:kubernetes_service_account:prod-cluster:payments:api")
}

func TestProjectKubernetesClusterNameFallbackIsScopedByAccount(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, accountID := range []string{"account-a", "account-b"} {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "k8s-cluster-name-" + accountID,
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"cloud_account_external_id": accountID,
				"cloud_provider":            "azure",
				"cluster_name":              "prod",
				"namespace":                 "payments",
				"service_account_name":      "api",
				"workload_kind":             "Deployment",
				"workload_name":             "payments-api",
			},
		})
		if err != nil {
			t.Fatalf("Project() error = %v", err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_cluster:account-a:prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:account-a")
	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_cluster:account-b:prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:account-b")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:kubernetes_cluster:prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:account-a")
}

func TestProjectKubernetesClusterNameFallbackRequiresAccountScope(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-cluster-name-provider-only",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload",
		Attributes: map[string]string{
			"cloud_provider":       "aws",
			"cluster_name":         "prod",
			"namespace":            "payments",
			"service_account_name": "api",
			"workload_kind":        "Deployment",
			"workload_name":        "payments-api",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if entity := state.entities["urn:cerebro:writer:kubernetes_cluster:aws:prod"]; entity != nil {
		t.Fatalf("provider-only cluster_name fallback should not create scoped cluster: %#v", entity)
	}
	if entity := state.entities["urn:cerebro:writer:kubernetes_cluster:prod"]; entity != nil {
		t.Fatalf("provider-only cluster_name fallback should not create unscoped cluster: %#v", entity)
	}
}

func TestProjectKubernetesCloudAccountIDUsesProjectIDFallback(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-gcp-project-id",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload",
		Attributes: map[string]string{
			"cluster_id":           "gke-prod",
			"namespace":            "payments",
			"project_id":           "writer-prod",
			"service_account_name": "api",
			"workload_kind":        "Deployment",
			"workload_name":        "payments-api",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:kubernetes_cluster:gke-prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
}

func TestProjectKubernetesAzureSkipsGenericAccountID(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "k8s-azure-generic-account",
		TenantId: "writer",
		SourceId: "kubernetes",
		Kind:     "kubernetes.workload",
		Attributes: map[string]string{
			"account_id":           "tenant-or-local-account",
			"cloud_provider":       "azure",
			"cluster_id":           "aks-prod",
			"namespace":            "payments",
			"service_account_name": "api",
			"workload_kind":        "Deployment",
			"workload_name":        "payments-api",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:kubernetes_cluster:aks-prod", relationBelongsTo, "urn:cerebro:writer:cloud_account:tenant-or-local-account")
}

func TestProjectKubernetesSparseEventsSkipPlaceholderURNs(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "k8s-workload-no-cluster",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"namespace":     "payments",
				"workload_kind": "Deployment",
				"workload_name": "payments-api",
			},
		},
		{
			Id:       "k8s-workload-no-id",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"cluster_id":     "prod-cluster",
				"namespace":      "payments",
				"workload_kind":  "Deployment",
				"workload_name":  "",
				"workload_uid":   "",
				"workload_image": "api",
			},
		},
		{
			Id:       "k8s-service-account-no-cluster",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.service_account",
			Attributes: map[string]string{
				"namespace":            "payments",
				"service_account_name": "api",
			},
		},
		{
			Id:       "k8s-container-no-pod-id",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.container",
			Attributes: map[string]string{
				"cluster_id":     "prod-cluster",
				"container_name": "api",
				"namespace":      "payments",
				"workload_name":  "payments-api",
			},
		},
		{
			Id:       "k8s-workload-no-node",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.workload",
			Attributes: map[string]string{
				"cluster_id":     "prod-cluster",
				"name":           "payments-api-abc123",
				"namespace":      "payments",
				"resource_name":  "payments-api-abc123",
				"workload_name":  "payments-api",
				"workload_uid":   "workload-1",
				"workload_image": "api",
			},
		},
		{
			Id:       "k8s-pod-no-pod-id",
			TenantId: "writer",
			SourceId: "kubernetes",
			Kind:     "kubernetes.pod",
			Attributes: map[string]string{
				"cluster_id":    "prod-cluster",
				"name":          "payments-api-abc123",
				"namespace":     "payments",
				"resource_name": "payments-api-abc123",
				"workload_name": "payments-api",
				"workload_uid":  "",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	for _, urn := range []string{
		"urn:cerebro:writer:kubernetes_workload:payments:Deployment/payments-api",
		"urn:cerebro:writer:kubernetes_workload:prod-cluster:payments:/",
		"urn:cerebro:writer:kubernetes_service_account:payments:api",
		"urn:cerebro:writer:kubernetes_namespace:payments",
		"urn:cerebro:writer:kubernetes_container:prod-cluster:payments:payments-api:api",
		"urn:cerebro:writer:kubernetes_node:prod-cluster:payments-api-abc123",
		"urn:cerebro:writer:kubernetes_pod:prod-cluster:payments:payments-api-abc123",
	} {
		if _, ok := state.entities[urn]; ok {
			t.Fatalf("sparse event minted placeholder entity %q", urn)
		}
	}
}

func TestProjectAssetClassificationLinksStrongCloudResourceIDsToAccounts(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "asset-aws-arn",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"data_classification": "restricted",
				"resource_id":         "arn:aws:s3:::writer-bucket",
				"resource_name":       "writer-bucket",
				"resource_type":       "bucket",
				"source_provider":     "aws",
				"aws_account_id":      "123456789012",
			},
		},
		{
			Id:       "asset-azure-arm",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"data_classification": "confidential",
				"resource_id":         "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/data",
				"resource_type":       "storage_account",
				"source_provider":     "azure",
			},
		},
		{
			Id:       "asset-gcp-resource",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"data_classification": "internal",
				"resource_id":         "projects/writer-prod/buckets/data",
				"resource_type":       "bucket",
				"source_provider":     "gcp",
			},
		},
		{
			Id:       "asset-bare-name",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"data_classification": "restricted",
				"resource_id":         "prod-secrets",
				"resource_type":       "secret_store",
				"source_provider":     "aws",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	assertProjectedLink(t, state, "urn:cerebro:writer:aws_bucket:arn:aws:s3:::writer-bucket", relationBelongsTo, "urn:cerebro:writer:cloud_account:123456789012")
	assertProjectedLink(t, state, "urn:cerebro:writer:azure_storage_account:/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/data", relationBelongsTo, "urn:cerebro:writer:cloud_account:sub-1")
	assertProjectedLink(t, state, "urn:cerebro:writer:gcp_bucket:projects/writer-prod/buckets/data", relationBelongsTo, "urn:cerebro:writer:cloud_account:writer-prod")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationBelongsTo, "urn:cerebro:writer:cloud_account:prod-secrets")
}

func TestProjectAssetClassificationLinksEmailOwnerIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)
	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "asset-email-owner",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"owner":               "alice@writer.com",
				"resource_id":         "writer-bucket",
				"resource_type":       "bucket",
				"source_provider":     "aws",
				"data_classification": "restricted",
			},
		},
		{
			Id:       "asset-team-owner",
			TenantId: "writer",
			SourceId: "asset",
			Kind:     "asset.data_sensitivity",
			Attributes: map[string]string{
				"owner":               "Security Team",
				"resource_id":         "prod-secrets",
				"resource_type":       "secret_store",
				"source_provider":     "aws",
				"data_classification": "restricted",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetId(), err)
		}
	}

	emailOwnerURN := "urn:cerebro:writer:owner:alice@writer.com"
	emailIdentityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_bucket:writer-bucket", relationOwnedBy, emailOwnerURN)
	assertProjectedLink(t, state, emailOwnerURN, relationRepresentsIdentity, emailIdentityURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:identifier:email:alice@writer.com", relationRepresentsIdentity, emailIdentityURN)
	assertProjectedLink(t, state, "urn:cerebro:writer:aws_secret_store:prod-secrets", relationOwnedBy, "urn:cerebro:writer:owner:Security Team")
	assertProjectedLinkMissing(t, state, "urn:cerebro:writer:owner:Security Team", relationRepresentsIdentity, "urn:cerebro:writer:identity:login:security team")
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

func TestProjectTelemetryIncludesTenantRuntimeDrilldownContext(t *testing.T) {
	service := New(nil, nil)
	stderr := captureSourceProjectionStderr(t, func() {
		_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
			Id:       "sensitive-event-id",
			TenantId: "writer",
			SourceId: "okta",
			Kind:     "okta.user",
			Attributes: map[string]string{
				"source_runtime_id": "writer-okta-user",
				"resource_urn":      "urn:cerebro:writer:okta_user:00u-sensitive",
			},
		})
		if err != nil {
			t.Fatalf("Project() error = %v", err)
		}
	})

	payload := sourceProjectionTelemetryEventPayload(t, stderr, "source_projection.project")
	for key, want := range map[string]any{
		"tenant_id":                            "writer",
		"source_id":                            "okta",
		"runtime_id":                           "writer-okta-user",
		"event_kind":                           "okta.user",
		"source_projection.tenant_id":          "writer",
		"source_projection.source_id":          "okta",
		"source_projection.runtime_id":         "writer-okta-user",
		"source_projection.event_kind":         "okta.user",
		"status":                               "completed",
		"source_projection.status":             "completed",
		"source_projection.entities_projected": float64(0),
		"source_projection.links_projected":    float64(0),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if payload["trace_id"] == "" || payload["span_id"] == "" {
		t.Fatalf("projection telemetry missing trace/span ids: %#v", payload)
	}
	for _, prohibited := range []string{"sensitive-event-id", "00u-sensitive", "resource_urn"} {
		if strings.Contains(stderr, prohibited) {
			t.Fatalf("projection telemetry leaked high-cardinality value %q: %s", prohibited, stderr)
		}
	}
}

func captureSourceProjectionStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func sourceProjectionTelemetryPayload(t *testing.T, stderr string) map[string]any {
	t.Helper()
	return sourceProjectionTelemetryEventPayload(t, stderr, "source_projection.runtime_evidence")
}

func sourceProjectionTelemetryEventPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "event" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry event %q not found in stderr: %s", name, stderr)
	return nil
}

type projectedLinkExpectation struct {
	fromURN  string
	relation string
	toURN    string
}

func wantProjectedLink(fromURN string, relation string, toURN string) projectedLinkExpectation {
	return projectedLinkExpectation{fromURN: fromURN, relation: relation, toURN: toURN}
}

func assertProjectedLinkSet(t *testing.T, recorder *projectionRecorder, want ...projectedLinkExpectation) {
	t.Helper()
	actualKeys := make([]string, 0, len(recorder.links))
	for key := range recorder.links {
		actualKeys = append(actualKeys, key)
	}
	wantKeys := make([]string, 0, len(want))
	for _, link := range want {
		wantKeys = append(wantKeys, link.fromURN+"|"+link.relation+"|"+link.toURN)
	}
	sort.Strings(actualKeys)
	sort.Strings(wantKeys)
	if stringSlicesEqual(actualKeys, wantKeys) {
		return
	}
	t.Fatalf("projected link set mismatch\nmissing:\n%s\nunexpected:\n%s\nactual:\n%s",
		formatProjectedLinkKeys(diffStringSlices(wantKeys, actualKeys)),
		formatProjectedLinkKeys(diffStringSlices(actualKeys, wantKeys)),
		formatProjectedLinkKeys(actualKeys),
	)
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func diffStringSlices(left []string, right []string) []string {
	rightSet := map[string]struct{}{}
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	var diff []string
	for _, value := range left {
		if _, ok := rightSet[value]; !ok {
			diff = append(diff, value)
		}
	}
	return diff
}

func formatProjectedLinkKeys(keys []string) string {
	if len(keys) == 0 {
		return "(none)"
	}
	return strings.Join(keys, "\n")
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

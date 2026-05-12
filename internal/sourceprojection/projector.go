package sourceprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var emailIdentifierPattern = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

const (
	relationActedOn            = "acted_on"
	relationAffectedBy         = "affected_by"
	relationAffects            = "affects"
	relationAuthored           = "authored"
	relationBelongsTo          = "belongs_to"
	relationCanPerform         = "can_perform"
	relationHasIdentifier      = "has_identifier"
	relationAssignedTo         = "assigned_to"
	relationCanAssume          = "can_assume"
	relationCanAdmin           = "can_admin"
	relationCanImpersonate     = "can_impersonate"
	relationCanReach           = "can_reach"
	relationContains           = "contains"
	relationHasClassification  = "has_classification"
	relationHasEvidence        = "has_evidence"
	relationMemberOf           = "member_of"
	relationObservedOn         = "observed_on"
	relationOwnedBy            = "owned_by"
	relationRepresents         = "represents"
	relationRepresentsIdentity = "represents_identity"
	relationRunsAs             = "runs_as"
	relationSupports           = "supports"
	relationTaggedAs           = "tagged_as"
	relationTargeted           = "targeted"
)

// Service materializes synced source events into current-state and graph stores.
type Service struct {
	state    ports.ProjectionStateStore
	graph    ports.ProjectionGraphStore
	registry *Registry
}

// New constructs a source projector.
func New(state ports.ProjectionStateStore, graph ports.ProjectionGraphStore) *Service {
	return NewWithRegistry(state, graph, BuiltinRegistry())
}

// NewWithRegistry constructs a source projector with an explicit event projector registry.
func NewWithRegistry(state ports.ProjectionStateStore, graph ports.ProjectionGraphStore, registry *Registry) *Service {
	if registry == nil {
		registry = BuiltinRegistry()
	}
	return &Service{state: state, graph: graph, registry: registry}
}

// Project applies one source event to the configured state and graph stores.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("event is required")
	}
	if s == nil || (s.state == nil && s.graph == nil) {
		return ports.ProjectionResult{}, nil
	}
	entities, links, err := s.ProjectRecords(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, entity := range entities {
		if s.state != nil {
			if err := s.state.UpsertProjectedEntity(ctx, entity); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
		if s.graph != nil {
			if err := s.graph.UpsertProjectedEntity(ctx, entity); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
	}
	for _, link := range links {
		if s.state != nil {
			if err := s.state.UpsertProjectedLink(ctx, link); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
		if s.graph != nil {
			if err := s.graph.UpsertProjectedLink(ctx, link); err != nil {
				return ports.ProjectionResult{}, err
			}
		}
	}
	return ports.ProjectionResult{
		EntitiesProjected: uint32(len(entities)),
		LinksProjected:    uint32(len(links)),
	}, nil
}

// ProjectRecords converts one event into normalized projection records without
// writing them. Graph ingest uses this to coalesce repeated records before
// touching Neo4j.
func (s *Service) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if s == nil || s.registry == nil {
		return nil, nil, nil
	}
	entities, links, err := s.registry.Project(event)
	if err != nil {
		return nil, nil, err
	}
	stampProjectionRuntime(event, entities, links)
	return entities, links, nil
}

func stampProjectionRuntime(event *cerebrov1.EventEnvelope, entities []*ports.ProjectedEntity, links []*ports.ProjectedLink) {
	if event == nil {
		return
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		return
	}
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		if strings.TrimSpace(entity.RuntimeID) == "" {
			entity.RuntimeID = runtimeID
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		if strings.TrimSpace(entity.Attributes[ports.EventAttributeSourceRuntimeID]) == "" {
			entity.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
		}
	}
	for _, link := range links {
		if link == nil {
			continue
		}
		if strings.TrimSpace(link.RuntimeID) == "" {
			link.RuntimeID = runtimeID
		}
		if link.Attributes == nil {
			link.Attributes = map[string]string{}
		}
		if strings.TrimSpace(link.Attributes[ports.EventAttributeSourceRuntimeID]) == "" {
			link.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
		}
	}
}

func githubPullRequestProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	payload := payloadMap(event)
	owner := strings.TrimSpace(attributes["owner"])
	repository := strings.TrimSpace(attributes["repository"])
	pullNumber := strings.TrimSpace(attributes["pull_number"])
	author := strings.TrimSpace(attributes["author"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := ""
	if owner != "" {
		orgURN = projectionURN(tenantID, "github_org", owner)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	repoURN := projectionURN(tenantID, "github_repo", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.repo",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	prURN := ""
	if repository != "" && pullNumber != "" {
		prURN = projectionURN(tenantID, "github_pull_request", repository+"#"+pullNumber)
		label := firstNonEmpty(stringValue(payload, "title"), repository+"#"+pullNumber)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        prURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.pull_request",
			Label:      label,
			Attributes: map[string]string{
				"html_url":    strings.TrimSpace(attributes["html_url"]),
				"pull_number": pullNumber,
				"repository":  repository,
				"state":       strings.TrimSpace(attributes["state"]),
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), prURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	authorURN := githubUserURN(tenantID, author)
	if authorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        authorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      author,
			Attributes: map[string]string{"login": author},
		})
		if prURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), authorURN, prURN, relationAuthored, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), authorURN, author, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	org := strings.TrimSpace(attributes["org"])
	repo := strings.TrimSpace(attributes["repo"])
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.TrimSpace(attributes["resource_type"])
	actor := strings.TrimSpace(attributes["actor"])
	actorID := strings.TrimSpace(attributes["actor_id"])
	actorIsBot := strings.TrimSpace(attributes["actor_is_bot"])
	actorIsAgent := strings.TrimSpace(attributes["actor_is_agent"])
	actorType := strings.TrimSpace(attributes["actor_type"])
	actorExternalNameID := strings.TrimSpace(attributes["external_identity_nameid"])
	actorExternalUsername := strings.TrimSpace(attributes["external_identity_username"])
	orgID := strings.TrimSpace(attributes["org_id"])
	programmaticAccessType := strings.TrimSpace(attributes["programmatic_access_type"])
	targetUser := strings.TrimSpace(attributes["user"])
	tokenID := strings.TrimSpace(attributes["token_id"])

	// actorIsOrgSelf is true when GitHub stamps the audit event with the org
	// as its own actor — a pattern that shows up on system-level events such
	// as `integration_installation.version_updated` where no specific user
	// triggered the action. We detect it by comparing the audit log's
	// actor_id against org_id (both numeric and stamped by GitHub itself).
	// When this is true we route the acted_on edge from the github.org node
	// rather than minting a phantom `github.user:<org>` node, mirroring
	// cartography's separation of GitHubOrganization and GitHubUser.
	actorTypeIsOrg := strings.EqualFold(actorType, "Organization")
	actorIsOrgSelf := actorID != "" && orgID != "" && actorID == orgID
	actorIsUnresolvedPublicKey := strings.EqualFold(actorType, "Unresolved") && isGitHubPublicKeyCredential(programmaticAccessType)
	actorIsAutomation := githubAuditActorIsAutomation(actor, actorType, actorIsBot, actorIsAgent)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", org)
	if org != "" {
		orgAttrs := map[string]string{"org": org}
		// Stamp the numeric org_id onto the github.org node so it stays
		// available when consumers need to reason about the org as a
		// first-class actor (e.g. distinguishing org-self events from
		// user actions in downstream rules).
		if orgID != "" {
			orgAttrs["org_id"] = orgID
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      org,
			Attributes: orgAttrs,
		})
	}
	actorOrgURN := orgURN
	if actorTypeIsOrg {
		actorOrgURN = projectionURN(tenantID, "github_org", firstNonEmpty(actor, org))
		if actorOrgURN != "" && actor != "" && !strings.EqualFold(actor, org) {
			actorOrgAttrs := map[string]string{"org": actor}
			addProjectedAttribute(actorOrgAttrs, "org_id", actorID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        actorOrgURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.org",
				Label:      actor,
				Attributes: actorOrgAttrs,
			})
		}
	}

	repoURN := projectionURN(tenantID, "github_repo", firstNonEmpty(repo, resourceID))
	if repo != "" || (resourceID != "" && strings.Contains(resourceID, "/")) {
		label := firstNonEmpty(repo, resourceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.repo",
			Label:      label,
			Attributes: map[string]string{"repository": label},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	resourceURN := githubResourceURN(tenantID, resourceType, resourceID, repoURN)
	if resourceURN != "" {
		label := firstNonEmpty(resourceID, resourceType)
		entityType := "github.resource"
		if repoURN != "" && resourceURN == repoURN {
			entityType = "github.repo"
			label = firstNonEmpty(repo, resourceID)
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      label,
			Attributes: map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
			},
		})
		if orgURN != "" && repoURN == "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if repoURN != "" && resourceURN != repoURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	// `at` carries the audit event's OccurredAt timestamp so graph rules can tell
	// recent GitHub activity from stale historical edges. mergeGraphAttributes is
	// latest-wins, so under the normal in-order ingestion path this field always
	// reflects the most recent action that touched the edge. The
	// deprovisioned-Okta-active-in-GitHub rule uses this to avoid reporting users as
	// "still active" purely from pre-offboarding history.
	actedAttrs := map[string]string{
		"action":   strings.TrimSpace(attributes["action"]),
		"event_id": event.GetId(),
	}
	addProjectedAttribute(actedAttrs, "actor_type", actorType)
	addProjectedAttribute(actedAttrs, "programmatic_access_type", programmaticAccessType)
	addProjectedAttribute(actedAttrs, "source_runtime_id", strings.TrimSpace(attributes["source_runtime_id"]))
	addProjectedAttribute(actedAttrs, "transport_protocol_name", strings.TrimSpace(attributes["transport_protocol_name"]))
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		actedAttrs["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}

	// When the audit event's actor is the org itself (system-level events),
	// route the acted_on edge from the github.org node rather than minting a
	// `github.user:<org>` shadow node. This matches GitHub's data model
	// (orgs are not users) and prevents identity rules from chasing the org
	// as if it were a person that should have an Okta link.
	if (actorIsOrgSelf || actorTypeIsOrg) && actorOrgURN != "" {
		if resourceURN != "" && resourceURN != actorOrgURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorOrgURN, resourceURN, relationActedOn, actedAttrs))
		}
	} else if actorIsUnresolvedPublicKey {
		credentialURN := githubCredentialURN(tenantID, githubPublicKeyCredentialID(tokenID, actor, repo, resourceID, org))
		if credentialURN != "" {
			credentialAttrs := map[string]string{
				"actor":                    actor,
				"credential_type":          "public_key",
				"programmatic_access_type": programmaticAccessType,
			}
			addProjectedAttribute(credentialAttrs, "org", org)
			addProjectedAttribute(credentialAttrs, "org_id", orgID)
			addProjectedAttribute(credentialAttrs, "repository", firstNonEmpty(repo, resourceID))
			addProjectedAttribute(credentialAttrs, "token_id", tokenID)
			addProjectedAttribute(credentialAttrs, "transport_protocol_name", strings.TrimSpace(attributes["transport_protocol_name"]))
			addEntity(entities, &ports.ProjectedEntity{
				URN:        credentialURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.credential",
				Label:      actor,
				Attributes: credentialAttrs,
			})
			if resourceURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, resourceURN, relationActedOn, actedAttrs))
			}
		}
	} else if actorIsAutomation {
		// Automation actors are GitHub Apps/agents, not human identities. Keep the
		// audit event in the append log but do not project them into the identity
		// graph or repeatedly rewrite hot bot->repo acted_on edges.
	} else {
		actorURN := githubUserURN(tenantID, actor)
		if actorURN != "" {
			actorAttrs := map[string]string{
				"external_identity_nameid":   actorExternalNameID,
				"external_identity_username": actorExternalUsername,
				"login":                      actor,
			}
			// Stamp the GitHub-native actor classification signals onto
			// the github.user node so downstream rules can distinguish
			// real users from bots and integration agents structurally,
			// without resorting to login-string heuristics. These fields
			// are stamped by GitHub itself on every audit event; values
			// are kept verbatim ("true" / "false") and merged latest-wins.
			if actorID != "" {
				actorAttrs["actor_id"] = actorID
			}
			if actorType != "" {
				actorAttrs["actor_type"] = actorType
			}
			if actorIsBot != "" {
				actorAttrs["actor_is_bot"] = actorIsBot
			}
			if actorIsAgent != "" {
				actorAttrs["actor_is_agent"] = actorIsAgent
			}
			if orgID != "" {
				actorAttrs["org_id"] = orgID
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        actorURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.user",
				Label:      actor,
				Attributes: actorAttrs,
			})
			if resourceURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, actedAttrs))
			}
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actor, event.GetOccurredAt())
			if !sameIdentifier(actor, actorExternalNameID) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorExternalNameID, event.GetOccurredAt())
			}
			if !sameIdentifier(actor, actorExternalUsername) && !sameIdentifier(actorExternalNameID, actorExternalUsername) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorExternalUsername, event.GetOccurredAt())
			}
		}
	}

	// The previous-version actor URN computed against the github.user
	// URN scheme is used here only to suppress redundant targeted edges
	// when actor==targetUser. The org-self path above doesn't create a
	// github.user actor, so this is purely for the user-actor case.
	previousActorURN := githubUserURN(tenantID, actor)
	targetURN := githubUserURN(tenantID, targetUser)
	if targetURN != "" && targetURN != previousActorURN && githubSyntheticTargetActorType(targetUser) == "" {
		targetAttrs := map[string]string{"login": targetUser}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      targetUser,
			Attributes: targetAttrs,
		})
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, resourceURN, relationTargeted, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), targetURN, targetUser, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func isGitHubPublicKeyCredential(programmaticAccessType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(programmaticAccessType))
	return strings.Contains(normalized, "public key")
}

func githubAuditActorIsAutomation(actor string, actorType string, actorIsBot string, actorIsAgent string) bool {
	if strings.EqualFold(strings.TrimSpace(actorIsBot), "true") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(actorIsAgent), "true") {
		return true
	}
	if githubActorTypeClassifiesAutomation(actorType) {
		return true
	}
	return githubSyntheticTargetActorType(actor) != ""
}

func githubActorTypeClassifiesAutomation(actorType string) bool {
	switch strings.ToLower(strings.TrimSpace(actorType)) {
	case "bot", "organization", "unresolved":
		return true
	}
	return false
}

// githubSyntheticTargetActorType returns the automation classification for a
// structurally synthetic login (i.e. not a real user that could be linked to
// Okta).
//
// Two synthetic shapes are recognised today:
//
//   - GitHub reserves the trailing `[bot]` suffix for App-issued
//     identities (dependabot[bot], github-actions[bot], renovate[bot],
//     coderabbitai[bot], factory-droid[bot], ...). The suffix is part of
//     GitHub's public contract; vendor changes don't alter it.
//
//   - The literal `deploy_key` login is GitHub's synthetic placeholder
//     for SSH-key activity (no real /users/{login} resolution). The
//     actor-side projector path routes these to `github.credential`
//     via `actorIsUnresolvedPublicKey`.
//
// Returns "" when the login is a plain human-shaped GitHub username.
func githubSyntheticTargetActorType(login string) string {
	trimmed := strings.TrimSpace(login)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if strings.HasSuffix(lower, "[bot]") {
		return "Bot"
	}
	switch lower {
	case "deploy_key", "deploy-key":
		return "Unresolved"
	}
	return ""
}

func githubPublicKeyCredentialID(tokenID string, actor string, repo string, resourceID string, org string) string {
	if strings.TrimSpace(tokenID) != "" {
		return strings.TrimSpace(tokenID)
	}
	scope := firstNonEmpty(repo, resourceID, org)
	if strings.TrimSpace(actor) != "" && scope != "" {
		return strings.TrimSpace(actor) + "@" + scope
	}
	return firstNonEmpty(actor, scope)
}

func githubCredentialURN(tenantID string, credentialID string) string {
	return projectionURN(tenantID, "github_credential", credentialID)
}

func githubDependabotAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	repository := strings.TrimSpace(attributes["repository"])
	owner := strings.TrimSpace(attributes["owner"])
	alertNumber := strings.TrimSpace(attributes["alert_number"])
	packageName := strings.TrimSpace(attributes["package"])
	ecosystem := strings.TrimSpace(attributes["ecosystem"])
	advisoryID := firstNonEmpty(attributes["advisory_ghsa_id"], attributes["advisory_cve_id"])
	vulnerabilityID := firstNonEmpty(canonicalVulnerabilityIdentifier(attributes), advisoryID)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	repoURN := projectionURN(tenantID, "github_repo", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.repo",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	alertURN := projectionURN(tenantID, "github_dependabot_alert", repository, alertNumber)
	if repository != "" && alertNumber != "" {
		label := firstNonEmpty(attributes["advisory_ghsa_id"], attributes["advisory_cve_id"], repository+"#"+alertNumber)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        alertURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.dependabot_alert",
			Label:      label,
			Attributes: map[string]string{
				"alert_number":       alertNumber,
				"ecosystem":          ecosystem,
				"html_url":           strings.TrimSpace(attributes["html_url"]),
				"package":            packageName,
				"repository":         repository,
				"severity":           strings.TrimSpace(attributes["severity"]),
				"state":              strings.TrimSpace(attributes["state"]),
				"vulnerability_id":   vulnerabilityID,
				"vulnerability_type": "dependabot",
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	advisoryURN := projectionURN(tenantID, "github_advisory", advisoryID)
	if advisoryID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        advisoryURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.security_advisory",
			Label:      advisoryID,
			Attributes: map[string]string{
				"cve_id":   strings.TrimSpace(attributes["advisory_cve_id"]),
				"ghsa_id":  strings.TrimSpace(attributes["advisory_ghsa_id"]),
				"severity": strings.TrimSpace(attributes["advisory_severity"]),
			},
		})
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, advisoryURN, relationAffectedBy, map[string]string{"event_id": event.GetId()}))
		}
	}

	packageURN := projectionURN(tenantID, "package", ecosystem, packageName)
	if packageName != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        packageURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "package",
			Label:      firstNonEmpty(ecosystem+"/"+packageName, packageName),
			Attributes: map[string]string{
				"ecosystem": ecosystem,
				"name":      packageName,
			},
		})
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, packageURN, relationAffects, map[string]string{"event_id": event.GetId()}))
		}
	}

	vulnerabilityURN := addCanonicalVulnerabilityEntity(entities, tenantID, event.GetSourceId(), attributes)
	canonicalPackageURN := addCanonicalPackageEntity(entities, tenantID, event.GetSourceId(), attributes, ecosystem)
	if vulnerabilityURN != "" {
		evidenceAttributes := vulnerabilityEvidenceAttributes(event, attributes)
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
		if packageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
		if canonicalPackageURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), canonicalPackageURN, vulnerabilityURN, relationAffectedBy, evidenceAttributes))
		}
	}
	if packageURN != "" && canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), packageURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, attributes, ecosystem)))
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	userID := strings.TrimSpace(attributes["user_id"])
	email := strings.TrimSpace(attributes["email"])
	login := strings.TrimSpace(attributes["login"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	userURN := oktaUserURN(tenantID, userID)
	if userURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        userURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.user",
			Label:      firstNonEmpty(email, login, userID),
			Attributes: map[string]string{
				"email":  email,
				"login":  login,
				"status": strings.TrimSpace(attributes["status"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		// observedAt is the time this projection ran, not the event's
		// OccurredAt. okta.user events derive OccurredAt from profile-history
		// fields (LastUpdated/Created/Activated/StatusChanged/LastLogin/
		// PasswordChanged) in sources/okta/source.go's userOccurredAt, so any
		// user whose profile has been static for longer than the graph-rule
		// recency window would have its represents_identity edges restamped
		// with an already-stale `at` on every fresh sync. Identity-aware rules
		// (e.g. the deprovisioned-Okta-active-in-GitHub graph rule) treat
		// stale-`at` rows as evidence the identifier link is no longer
		// asserted and drop them, which silently swallows offboarding gaps for
		// long-static accounts. Stamping with the projection's own clock
		// instead means any current inventory link is always recent, while
		// edges that stop being re-asserted (e.g. a renamed email) still age
		// out naturally because subsequent syncs no longer refresh them.
		observedAt := timestamppb.New(time.Now().UTC())
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, email, observedAt)
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), userURN, login, observedAt)
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	domain := strings.TrimSpace(attributes["domain"])
	actorID := strings.TrimSpace(attributes["actor_id"])
	actorType := strings.TrimSpace(attributes["actor_type"])
	actorAlternateID := strings.TrimSpace(attributes["actor_alternate_id"])
	actorDisplayName := strings.TrimSpace(attributes["actor_display_name"])
	resourceID := strings.TrimSpace(attributes["resource_id"])
	resourceType := strings.TrimSpace(attributes["resource_type"])
	oauthClientID := firstNonEmpty(attributes["oauth_client_id"], attributes["client_id"])
	oauthClientLabel := firstNonEmpty(attributes["oauth_client_label"], attributes["actor_display_name"], oauthClientID)

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "okta_org", domain)
	if domain != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.org",
			Label:      domain,
			Attributes: map[string]string{"domain": domain},
		})
	}

	resourceURN := oktaResourceURN(tenantID, resourceType, resourceID)
	if resourceURN != "" {
		entityType := "okta.resource"
		if strings.EqualFold(resourceType, "user") {
			entityType = "okta.user"
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      firstNonEmpty(resourceID, resourceType),
			Attributes: map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	oauthClientURN := oktaApplicationURN(tenantID, oauthClientID)
	if oauthClientURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        oauthClientURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "okta.application",
			Label:      oauthClientLabel,
			Attributes: map[string]string{
				"app_id":               oauthClientID,
				"client_id":            oauthClientID,
				"oauth_client_type":    strings.TrimSpace(attributes["oauth_client_type"]),
				"oauth_event_category": strings.TrimSpace(attributes["oauth_event_category"]),
				"grant_type":           strings.TrimSpace(attributes["grant_type"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), oauthClientURN, resourceURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, map[string]string{
				"oauth_event_category": attributes["oauth_event_category"],
				"grant_type":           attributes["grant_type"],
			})))
		}
	}

	actorURN := oktaActorURN(tenantID, actorType, actorID)
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: oktaActorEntityType(actorType),
			Label:      firstNonEmpty(actorAlternateID, actorDisplayName, actorID),
			Attributes: map[string]string{
				"actor_id":           actorID,
				"actor_type":         actorType,
				"actor_alternate_id": actorAlternateID,
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if resourceURN != "" && resourceURN != actorURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, oktaAuditRelationAttributes(event, attributes, nil)))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorAlternateID, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func oktaAuditRelationAttributes(event *cerebrov1.EventEnvelope, attributes map[string]string, extra map[string]string) map[string]string {
	relationAttrs := map[string]string{
		"event_id":   event.GetId(),
		"event_type": strings.TrimSpace(attributes["event_type"]),
	}
	addProjectedAttribute(relationAttrs, "outcome_result", strings.TrimSpace(attributes["outcome_result"]))
	addProjectedAttribute(relationAttrs, "outcome_reason", strings.TrimSpace(attributes["outcome_reason"]))
	addProjectedAttribute(relationAttrs, "transaction_id", strings.TrimSpace(attributes["transaction_id"]))
	addProjectedAttribute(relationAttrs, "client_ip", strings.TrimSpace(attributes["client_ip"]))
	addProjectedAttribute(relationAttrs, "source_runtime_id", strings.TrimSpace(attributes["source_runtime_id"]))
	if occurredAt := event.GetOccurredAt(); occurredAt != nil && occurredAt.IsValid() {
		relationAttrs["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}
	for key, value := range extra {
		addProjectedAttribute(relationAttrs, key, strings.TrimSpace(value))
	}
	return relationAttrs
}

func entitiesAndLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink) {
	projectedEntities := make([]*ports.ProjectedEntity, 0, len(entities))
	for _, entity := range entities {
		projectedEntities = append(projectedEntities, entity)
	}
	projectedLinks := make([]*ports.ProjectedLink, 0, len(links))
	for _, link := range links {
		projectedLinks = append(projectedLinks, link)
	}
	return projectedEntities, projectedLinks
}

func tenantID(event *cerebrov1.EventEnvelope) (string, error) {
	tenantID := strings.TrimSpace(event.GetTenantId())
	if tenantID == "" {
		return "", fmt.Errorf("event %q tenant_id is required for projection", event.GetId())
	}
	return tenantID, nil
}

func addEntity(entities map[string]*ports.ProjectedEntity, entity *ports.ProjectedEntity) {
	if entity == nil || strings.TrimSpace(entity.URN) == "" {
		return
	}
	if existing := entities[entity.URN]; existing != nil {
		if strings.TrimSpace(entity.TenantID) != "" {
			existing.TenantID = entity.TenantID
		}
		if strings.TrimSpace(entity.SourceID) != "" {
			existing.SourceID = entity.SourceID
		}
		if strings.TrimSpace(entity.EntityType) != "" {
			existing.EntityType = entity.EntityType
		}
		if strings.TrimSpace(entity.Label) != "" {
			existing.Label = entity.Label
		}
		if len(entity.Attributes) != 0 {
			if existing.Attributes == nil {
				existing.Attributes = map[string]string{}
			}
			for key, value := range entity.Attributes {
				existing.Attributes[key] = value
			}
		}
		return
	}
	entities[entity.URN] = entity
}

func addLink(links map[string]*ports.ProjectedLink, link *ports.ProjectedLink) {
	if link == nil || strings.TrimSpace(link.FromURN) == "" || strings.TrimSpace(link.ToURN) == "" || strings.TrimSpace(link.Relation) == "" {
		return
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	links[key] = link
}

func addProjectedAttribute(attributes map[string]string, key string, value string) {
	if attributes == nil {
		return
	}
	if strings.TrimSpace(value) == "" {
		return
	}
	attributes[key] = strings.TrimSpace(value)
}

func addIdentifierLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, fromURN string, value string, occurredAt *timestamppb.Timestamp) {
	identifierURN, identifierType, label := identifierURN(tenantID, value)
	if identifierURN == "" {
		return
	}
	evidenceAttributes := identifierEvidenceAttributes(value, identifierType, label, eventID, occurredAt)
	canonicalIdentityURN, canonicalIdentityType := canonicalIdentityURN(tenantID, value)
	if canonicalIdentityURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        canonicalIdentityURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: canonicalIdentityType,
			Label:      label,
			Attributes: map[string]string{"value": label},
		})
		addLink(links, projectedLink(tenantID, sourceID, fromURN, canonicalIdentityURN, relationRepresentsIdentity, evidenceAttributes))
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identifierURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: identifierType,
		Label:      label,
		Attributes: map[string]string{"value": label},
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identifierURN, relationHasIdentifier, evidenceAttributes))
	if canonicalIdentityURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, canonicalIdentityURN, identifierURN, relationHasIdentifier, evidenceAttributes))
	}
}

func identifierEvidenceAttributes(rawValue string, identifierType string, normalizedValue string, eventID string, occurredAt *timestamppb.Timestamp) map[string]string {
	matchType := "login"
	confidence := "0.60"
	value := strings.TrimSpace(rawValue)
	if identifierType == "identifier.email" {
		if strings.EqualFold(normalizeIdentifier(value), normalizedValue) {
			matchType = "exact_email"
			confidence = "0.95"
		} else {
			matchType = "extracted_email"
			confidence = "0.85"
		}
	}
	attributes := map[string]string{
		"confidence":       confidence,
		"evidence_type":    "shared_identifier",
		"identifier_type":  strings.TrimPrefix(identifierType, "identifier."),
		"identifier_value": normalizedValue,
		"match_type":       matchType,
	}
	if normalizedEventID := strings.TrimSpace(eventID); normalizedEventID != "" {
		attributes["source_event_id"] = normalizedEventID
	}
	// `at` carries the most recent OccurredAt that re-asserted this identifier
	// link. Source projection is upsert-only and never retracts old edges, so an
	// Okta email/login or GitHub external_identity_nameid that has been renamed
	// would otherwise leave the stale represents_identity edge intact forever
	// and let identity-aware graph rules keep matching through it. The
	// chronological-max merge for `at` (see neo4j store mergeAttributeValue)
	// means rules can scope joins to recently re-observed links and the stale
	// edge naturally ages out of the window once it stops being refreshed.
	if occurredAt != nil && occurredAt.IsValid() {
		attributes["at"] = occurredAt.AsTime().UTC().Format(time.RFC3339)
	}
	return attributes
}

func projectedLink(tenantID string, sourceID string, fromURN string, toURN string, relation string, attributes map[string]string) *ports.ProjectedLink {
	return &ports.ProjectedLink{
		TenantID:   tenantID,
		SourceID:   sourceID,
		FromURN:    fromURN,
		ToURN:      toURN,
		Relation:   relation,
		Attributes: attributes,
	}
}

func githubUserURN(tenantID string, login string) string {
	value := strings.TrimSpace(login)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "github_user", value)
}

func oktaUserURN(tenantID string, userID string) string {
	value := strings.TrimSpace(userID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_user", value)
}

func oktaApplicationURN(tenantID string, appID string) string {
	value := strings.TrimSpace(appID)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "okta_application", value)
}

func oktaActorURN(tenantID string, actorType string, actorID string) string {
	switch {
	case strings.EqualFold(actorType, "user"):
		return oktaUserURN(tenantID, actorID)
	case strings.TrimSpace(actorID) == "":
		return ""
	default:
		return projectionURN(tenantID, "okta_actor", normalizeIdentifier(actorType), strings.TrimSpace(actorID))
	}
}

func oktaActorEntityType(actorType string) string {
	if strings.EqualFold(actorType, "user") {
		return "okta.user"
	}
	if strings.TrimSpace(actorType) == "" {
		return "okta.actor"
	}
	return "okta." + normalizeIdentifier(actorType)
}

func githubResourceURN(tenantID string, resourceType string, resourceID string, repoURN string) string {
	if repoURN != "" && (strings.Contains(strings.ToLower(resourceType), "repository") || strings.Contains(resourceID, "/")) {
		return repoURN
	}
	if strings.TrimSpace(resourceID) == "" && strings.TrimSpace(resourceType) == "" {
		return ""
	}
	return projectionURN(tenantID, "github_resource", normalizeIdentifier(resourceType), strings.TrimSpace(resourceID))
}

func oktaResourceURN(tenantID string, resourceType string, resourceID string) string {
	if strings.TrimSpace(resourceID) == "" {
		return ""
	}
	if strings.EqualFold(resourceType, "user") {
		return oktaUserURN(tenantID, resourceID)
	}
	return projectionURN(tenantID, "okta_resource", normalizeIdentifier(resourceType), strings.TrimSpace(resourceID))
}

func projectionURN(tenantID string, kind string, parts ...string) string {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" || entityKind == "" {
		return ""
	}
	values := make([]string, 0, len(parts)+3)
	values = append(values, "urn", "cerebro", tenant, entityKind)
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return strings.Join(values, ":")
}

func identifierURN(tenantID string, raw string) (string, string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", ""
	}
	if email := extractEmailIdentifier(value); email != "" {
		normalized := normalizeIdentifier(email)
		return projectionURN(tenantID, "identifier", "email", normalized), "identifier.email", normalized
	}
	normalized := normalizeIdentifier(value)
	return projectionURN(tenantID, "identifier", "login", normalized), "identifier.login", normalized
}

func canonicalIdentityURN(tenantID string, raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ""
	}
	if email := extractEmailIdentifier(value); email != "" {
		normalized := normalizeIdentifier(email)
		return projectionURN(tenantID, "identity", "email", normalized), "identity.email"
	}
	normalized := normalizeIdentifier(value)
	return projectionURN(tenantID, "identity", "login", normalized), "identity.login"
}

func extractEmailIdentifier(value string) string {
	return strings.TrimSpace(emailIdentifierPattern.FindString(strings.TrimSpace(value)))
}

func sameIdentifier(left string, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	return normalizeIdentifier(left) == normalizeIdentifier(right)
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func payloadMap(event *cerebrov1.EventEnvelope) map[string]any {
	if len(event.GetPayload()) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return nil
	}
	return payload
}

func stringValue(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

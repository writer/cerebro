package sourceprojection

import (
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

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

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
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

func githubCodeRepositoryProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	repository := strings.TrimSpace(firstNonEmpty(attributes["repository"], attributes["full_name"], attributes["resource_name"]))
	owner := strings.TrimSpace(firstNonEmpty(attributes["owner_login"], attributes["owner"]))
	repoID := strings.TrimSpace(firstNonEmpty(attributes["repo_id"], attributes["resource_id"], repository))
	if repoID == "" {
		return nil, nil, nil
	}

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
			Attributes: map[string]string{"org": owner, "owner_login": owner},
		})
	}

	codeRepoURN := projectionURN(tenantID, "github_code_repository", repoID)
	if codeRepoURN != "" {
		codeRepoAttrs := map[string]string{
			"archived":       strings.TrimSpace(attributes["archived"]),
			"default_branch": strings.TrimSpace(attributes["default_branch"]),
			"fork":           strings.TrimSpace(attributes["fork"]),
			"html_url":       strings.TrimSpace(attributes["html_url"]),
			"name":           strings.TrimSpace(attributes["name"]),
			"owner_login":    owner,
			"private":        strings.TrimSpace(attributes["private"]),
			"repo_id":        strings.TrimSpace(attributes["repo_id"]),
			"repository":     repository,
			"resource_id":    repoID,
			"resource_type":  "code_repository",
			"visibility":     strings.TrimSpace(attributes["visibility"]),
		}
		for _, key := range []string{"secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"} {
			if v := strings.TrimSpace(attributes[key]); v != "" {
				codeRepoAttrs[key] = v
			}
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        codeRepoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      firstNonEmpty(repository, repoID),
			Attributes: codeRepoAttrs,
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), codeRepoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "owner_login": owner}))
		}
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
	actorEmail := strings.TrimSpace(attributes["actor_email"])
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

	repoURN := projectionURN(tenantID, "github_code_repository", firstNonEmpty(repo, resourceID))
	repoScopePresent := repo != "" || (resourceID != "" && strings.Contains(resourceID, "/"))
	if repoScopePresent {
		label := firstNonEmpty(repo, resourceID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      label,
			Attributes: map[string]string{"repository": label},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	resourceURN := githubResourceURN(tenantID, resourceType, resourceID, repoURN)
	programmaticCredential := githubAuditProgrammaticCredentialResource(resourceType)
	programmaticCredentialURN := ""
	if programmaticCredential {
		programmaticCredentialURN = githubCredentialURN(tenantID, githubProgrammaticCredentialID(attributes))
	}
	if resourceURN != "" {
		label := firstNonEmpty(resourceID, resourceType)
		entityType := "github.resource"
		if repoURN != "" && resourceURN == repoURN {
			entityType = "github.code.repository"
			label = firstNonEmpty(repo, resourceID)
		}
		resourceAttrs := githubAuditResourceAttributes(attributes, resourceID, resourceType)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: entityType,
			Label:      label,
			Attributes: resourceAttrs,
		})
		if orgURN != "" && repoURN == "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
		if repoURN != "" && resourceURN != repoURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), resourceURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	if programmaticCredentialURN != "" {
		credentialAttrs := map[string]string{
			"credential_type":          resourceType,
			"programmatic_access_type": programmaticAccessType,
			"resource_id":              resourceID,
			"resource_type":            resourceType,
			"status":                   githubProgrammaticCredentialStatus(attributes),
		}
		addProjectedAttribute(credentialAttrs, "actor", actor)
		addProjectedAttribute(credentialAttrs, "github_app_id", strings.TrimSpace(attributes["github_app_id"]))
		addProjectedAttribute(credentialAttrs, "org", org)
		addProjectedAttribute(credentialAttrs, "org_id", orgID)
		addProjectedAttribute(credentialAttrs, "repository", repo)
		addProjectedAttribute(credentialAttrs, "scope", strings.TrimSpace(attributes["scope"]))
		addProjectedAttribute(credentialAttrs, "token_id", tokenID)
		addEntity(entities, &ports.ProjectedEntity{
			URN:        programmaticCredentialURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.credential",
			Label:      firstNonEmpty(attributes["name"], attributes["github_app_id"], tokenID, resourceID, resourceType),
			Attributes: credentialAttrs,
		})
		if resourceURN != "" && resourceURN != programmaticCredentialURN {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, resourceURN, relationActedOn, map[string]string{
				"action":                   strings.TrimSpace(attributes["action"]),
				"event_id":                 event.GetId(),
				"programmatic_access_type": programmaticAccessType,
			}))
		}
		if repoScopePresent && repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), programmaticCredentialURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	if runnerURN, runnerAttrs := githubSelfHostedRunnerProjection(tenantID, attributes); runnerURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        runnerURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.runner",
			Label:      firstNonEmpty(runnerAttrs["runner_name"], runnerAttrs["runner_id"]),
			Attributes: runnerAttrs,
		})
		if repoScopePresent && repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), runnerURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		} else if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), runnerURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
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
		credentialID := githubAutomationCredentialID(attributes)
		if credentialID != "" {
			credentialURN := githubCredentialURN(tenantID, credentialID)
			credentialAttrs := map[string]string{
				"actor":                    actor,
				"actor_is_agent":           actorIsAgent,
				"actor_is_bot":             actorIsBot,
				"actor_type":               actorType,
				"credential_type":          "automation_actor",
				"programmatic_access_type": programmaticAccessType,
			}
			addProjectedAttribute(credentialAttrs, "github_app_id", strings.TrimSpace(attributes["github_app_id"]))
			addProjectedAttribute(credentialAttrs, "org", org)
			addProjectedAttribute(credentialAttrs, "org_id", orgID)
			addProjectedAttribute(credentialAttrs, "repository", repo)
			addProjectedAttribute(credentialAttrs, "token_id", tokenID)
			addEntity(entities, &ports.ProjectedEntity{
				URN:        credentialURN,
				TenantID:   tenantID,
				SourceID:   event.GetSourceId(),
				EntityType: "github.credential",
				Label:      firstNonEmpty(strings.TrimSpace(attributes["github_app_name"]), strings.TrimSpace(attributes["github_app_id"]), actor, tokenID),
				Attributes: credentialAttrs,
			})
			if resourceURN != "" && resourceURN != credentialURN {
				automationActedAttrs := cloneStringMap(actedAttrs)
				automationActedAttrs["match_type"] = "automation_actor"
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, resourceURN, relationActedOn, automationActedAttrs))
			}
			if repoScopePresent && repoURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
			} else if orgURN != "" {
				addLink(links, projectedLink(tenantID, event.GetSourceId(), credentialURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
			}
		}
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
			if !sameIdentifier(actor, actorEmail) && !sameIdentifier(actorExternalNameID, actorEmail) && !sameIdentifier(actorExternalUsername, actorEmail) {
				addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, actorEmail, event.GetOccurredAt())
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

func githubAuditResourceAttributes(attributes map[string]string, resourceID string, resourceType string) map[string]string {
	resourceAttrs := map[string]string{
		"resource_id":   resourceID,
		"resource_type": resourceType,
	}
	for key, value := range attributes {
		if !githubAuditResourceAttributeKey(key) {
			continue
		}
		addProjectedAttribute(resourceAttrs, key, value)
	}
	return resourceAttrs
}

func githubAuditResourceAttributeKey(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	if strings.HasPrefix(key, "actor") || strings.HasPrefix(key, "external_identity") {
		return false
	}
	switch key {
	case "family", "resource_id", "resource_type", "source_runtime_id", "token_id", "user", "user_id":
		return false
	default:
		return true
	}
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

func githubAuditProgrammaticCredentialResource(resourceType string) bool {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "personal_access_token",
		"org_credential_authorization",
		"integration_installation",
		"integration_installation_request",
		"oauth_application",
		"integration":
		return true
	default:
		return false
	}
}

func githubProgrammaticCredentialID(attributes map[string]string) string {
	resourceType := strings.TrimSpace(attributes["resource_type"])
	prefix := firstNonEmpty(resourceType, "programmatic_credential")
	switch strings.ToLower(resourceType) {
	case "personal_access_token", "org_credential_authorization":
		if tokenID := strings.TrimSpace(attributes["token_id"]); tokenID != "" {
			return prefix + ":" + tokenID
		}
	case "integration_installation", "integration_installation_request", "integration":
		if appID := strings.TrimSpace(attributes["github_app_id"]); appID != "" {
			return prefix + ":" + appID
		}
	}
	scope := firstNonEmpty(attributes["repo"], attributes["org"], attributes["scope"])
	return strings.Join(nonEmptyStrings(prefix, attributes["resource_id"], scope, attributes["actor"]), ":")
}

func githubAutomationCredentialID(attributes map[string]string) string {
	if appID := strings.TrimSpace(attributes["github_app_id"]); appID != "" {
		return "automation_app:" + appID
	}
	if tokenID := strings.TrimSpace(attributes["token_id"]); tokenID != "" {
		return "automation_token:" + tokenID
	}
	actor := strings.TrimSpace(attributes["actor"])
	scope := strings.TrimSpace(firstNonEmpty(attributes["repo"], attributes["resource_id"], attributes["org"], attributes["scope"]))
	if actor == "" && scope == "" {
		return ""
	}
	return strings.Join(nonEmptyStrings("automation_actor", actor, scope), ":")
}

func githubProgrammaticCredentialStatus(attributes map[string]string) string {
	normalized := strings.ToLower(strings.TrimSpace(attributes["action"]))
	operationType := strings.ToLower(strings.TrimSpace(attributes["operation_type"]))
	if containsAny(operationType, "remove", "removed", "revoke", "revoked", "expire", "expired", "delete", "deleted") {
		return "inactive"
	}
	if containsAny(normalized, "revoke", "revoked", "deauthorize", "delete", "remove", "destroy", "suspend") {
		return "inactive"
	}
	if containsAny(normalized, "create", "grant", "authorize", "install", "request", "access_granted", "approve") {
		return "active"
	}
	return "unknown"
}

func githubSelfHostedRunnerProjection(tenantID string, attributes map[string]string) (string, map[string]string) {
	if !githubAuditProjectsSelfHostedRunner(attributes) {
		return "", nil
	}
	runnerID := strings.TrimSpace(attributes["runner_id"])
	if runnerID == "" {
		return "", nil
	}
	scope := strings.TrimSpace(firstNonEmpty(attributes["runner_scope"], attributes["scope"], attributes["repo"], attributes["org"]))
	if scope == "" {
		return "", nil
	}
	scopeType, scopeID := githubRunnerScope(scope)
	if scopeID == "" {
		return "", nil
	}
	attrs := map[string]string{
		"action":            strings.TrimSpace(attributes["action"]),
		"runner_id":         runnerID,
		"runner_name":       strings.TrimSpace(attributes["runner_name"]),
		"runner_scope":      scopeID,
		"runner_scope_type": scopeType,
		"runner_status":     githubSelfHostedRunnerStatus(attributes),
	}
	addProjectedAttribute(attrs, "host_trusted", firstNonEmpty(attributes["runner_host_trusted"], attributes["host_trusted"], attributes["trusted_host"]))
	addProjectedAttribute(attrs, "runner_ephemeral", firstNonEmpty(attributes["runner_ephemeral"], attributes["ephemeral"], attributes["is_ephemeral"]))
	addProjectedAttribute(attrs, "runner_group_name", attributes["runner_group_name"])
	addProjectedAttribute(attrs, "runner_registered", firstNonEmpty(attributes["runner_registered"], attributes["registered"], attributes["is_registered"]))
	addProjectedAttribute(attrs, "runner_state", attributes["runner_state"])
	addProjectedAttribute(attrs, "runner_untrusted", firstNonEmpty(attributes["runner_untrusted"], attributes["host_untrusted"], attributes["untrusted_host"]))
	return projectionURN(tenantID, "github_runner", scopeID, runnerID), attrs
}

func githubAuditProjectsSelfHostedRunner(attributes map[string]string) bool {
	action := strings.TrimSpace(attributes["action"])
	return githubSelfHostedRunnerAuditAction(action)
}

func githubSelfHostedRunnerAuditAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return false
	}
	// GitHub audit rows such as workflows.prepared_workflow_job include per-job
	// GitHub-hosted runner IDs. Those are ephemeral execution details, not
	// customer-managed self-hosted runner assets.
	if strings.HasPrefix(action, "workflows.") {
		return false
	}
	return strings.Contains(action, "self_hosted_runner")
}

func githubRunnerScope(scope string) (string, string) {
	normalized := strings.TrimSpace(scope)
	if normalized == "" {
		return "", ""
	}
	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "repo:"), strings.Contains(normalized, "/"):
		return "repo", normalizeGitHubRunnerScopeID(normalized, "repo")
	case strings.HasPrefix(lower, "enterprise:"):
		return "enterprise", normalizeGitHubRunnerScopeID(normalized, "enterprise")
	case strings.HasPrefix(lower, "org:"):
		return "org", normalizeGitHubRunnerScopeID(normalized, "org")
	default:
		return "org", "org:" + normalized
	}
}

func normalizeGitHubRunnerScopeID(scope string, kind string) string {
	normalized := strings.TrimSpace(scope)
	prefix := kind + ":"
	if strings.HasPrefix(strings.ToLower(normalized), prefix) {
		return normalized
	}
	return prefix + normalized
}

func githubSelfHostedRunnerStatus(attributes map[string]string) string {
	action := strings.ToLower(strings.TrimSpace(attributes["action"]))
	state := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["runner_state"], attributes["state"], attributes["status"])))
	registered := strings.ToLower(strings.TrimSpace(firstNonEmpty(attributes["runner_registered"], attributes["registered"], attributes["is_registered"])))
	if registered == "false" || registered == "0" || registered == "no" {
		return "inactive"
	}
	if containsAny(state, "removed", "deleted", "deregistered", "unregistered") ||
		containsAny(action, "remove_self_hosted_runner", "deregister_self_hosted_runner", "runner_removed") {
		return "inactive"
	}
	return "active"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func nonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
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
	manifestPath := strings.TrimSpace(attributes["manifest_path"])
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

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
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
				"alert_number":             alertNumber,
				"dependency_scope":         strings.TrimSpace(attributes["dependency_scope"]),
				"ecosystem":                ecosystem,
				"first_patched_version":    strings.TrimSpace(attributes["first_patched_version"]),
				"html_url":                 strings.TrimSpace(attributes["html_url"]),
				"manifest_path":            manifestPath,
				"package":                  packageName,
				"repository":               repository,
				"severity":                 strings.TrimSpace(attributes["severity"]),
				"state":                    strings.TrimSpace(attributes["state"]),
				"vulnerability_id":         vulnerabilityID,
				"vulnerability_type":       "dependabot",
				"vulnerable_version_range": strings.TrimSpace(attributes["vulnerable_version_range"]),
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
	addGitHubDependabotDependencyContext(entities, links, tenantID, event, repoURN, alertURN, packageURN, canonicalPackageURN, repository, manifestPath, ecosystem, packageName)
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["dismissed_by"], attributes["dismissed_by_id"], "dismissed_by")

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGitHubDependabotDependencyContext(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, repoURN string, alertURN string, packageURN string, canonicalPackageURN string, repository string, manifestPath string, ecosystem string, packageName string) {
	repository = strings.TrimSpace(repository)
	manifestPath = strings.TrimSpace(manifestPath)
	packageName = strings.TrimSpace(packageName)
	if repository == "" || manifestPath == "" || packageName == "" {
		return
	}
	manifestURN := projectionURN(tenantID, "github_dependency_manifest", repository, manifestPath)
	dependencyURN := projectionURN(tenantID, "github_dependency", repository, manifestPath, ecosystem, packageName)
	if manifestURN == "" || dependencyURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        manifestURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.dependency_manifest",
		Label:      manifestPath,
		Attributes: map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"manifest_path": manifestPath,
			"repository":    repository,
		},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        dependencyURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.dependency",
		Label:      packageName,
		Attributes: map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"manifest_path": manifestPath,
			"package":       packageName,
			"repository":    repository,
		},
	})
	if repoURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), manifestURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, dependencyURN, relationContains, map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"event_id":      event.GetId(),
			"manifest_path": manifestPath,
			"package":       packageName,
		}))
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, manifestURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), manifestURN, dependencyURN, relationContains, map[string]string{"event_id": event.GetId()}))
	if packageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, packageURN, relationRepresents, map[string]string{
			"ecosystem":     strings.TrimSpace(ecosystem),
			"event_id":      event.GetId(),
			"manifest_path": manifestPath,
			"package":       packageName,
		}))
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, packageURN, relationContains, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
	}
	if canonicalPackageURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), dependencyURN, canonicalPackageURN, relationRepresents, packageIdentityAttributes(event, event.GetAttributes(), ecosystem)))
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, canonicalPackageURN, relationContains, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
		if alertURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, canonicalPackageURN, relationAffects, map[string]string{
				"ecosystem":     strings.TrimSpace(ecosystem),
				"event_id":      event.GetId(),
				"manifest_path": manifestPath,
				"package":       packageName,
			}))
		}
	}
	if alertURN != "" {
		addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, dependencyURN, relationAffects, map[string]string{"event_id": event.GetId()}))
	}
}

func githubSecretScanningAlertProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	repository := strings.TrimSpace(attributes["repository"])
	alertNumber := strings.TrimSpace(attributes["alert_number"])

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

	repoURN := projectionURN(tenantID, "github_code_repository", repository)
	if repository != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        repoURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.code.repository",
			Label:      repository,
			Attributes: map[string]string{"repository": repository},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), repoURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	alertLabel := repository + "#" + alertNumber
	if repository == "" {
		alertLabel = owner + "#" + alertNumber
	}
	alertURN := projectionURN(tenantID, "github_secret_scanning_alert", owner, alertNumber)
	if alertNumber != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        alertURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.secret_scanning_alert",
			Label:      alertLabel,
			Attributes: map[string]string{
				"alert_number":             alertNumber,
				"html_url":                 strings.TrimSpace(attributes["html_url"]),
				"push_protection_bypassed": strings.TrimSpace(attributes["push_protection_bypassed"]),
				"repository":               repository,
				"resolution":               strings.TrimSpace(attributes["resolution"]),
				"secret_type":              strings.TrimSpace(attributes["secret_type"]),
				"secret_type_display_name": strings.TrimSpace(attributes["secret_type_display_name"]),
				"state":                    strings.TrimSpace(attributes["state"]),
			},
		})
		if repoURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), alertURN, repoURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["resolved_by"], attributes["resolved_by_id"], "resolved_by")
	addGitHubAlertActorLinks(entities, links, tenantID, event, alertURN, attributes["push_protection_bypassed_by"], attributes["push_protection_bypassed_by_id"], "push_protection_bypassed_by")

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func addGitHubAlertActorLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, event *cerebrov1.EventEnvelope, alertURN string, login string, userID string, actorRole string) {
	login = strings.TrimSpace(login)
	alertURN = strings.TrimSpace(alertURN)
	if login == "" || alertURN == "" {
		return
	}
	userID = strings.TrimSpace(userID)
	actorRole = strings.TrimSpace(actorRole)
	actorURN := projectionURN(tenantID, "github_user", login)
	actorAttrs := map[string]string{"login": login}
	if userID != "" {
		actorAttrs["user_id"] = userID
	}
	if actorRole != "" {
		actorAttrs["actor_role"] = actorRole
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        actorURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "github.user",
		Label:      login,
		Attributes: actorAttrs,
	})
	linkAttrs := map[string]string{"event_id": event.GetId()}
	if actorRole != "" {
		linkAttrs["actor_role"] = actorRole
	}
	linkKey := actorURN + "|" + relationActedOn + "|" + alertURN
	if existing := links[linkKey]; existing != nil {
		mergeCSVLinkAttribute(existing.Attributes, "event_id", event.GetId())
		mergeCSVLinkAttribute(existing.Attributes, "actor_role", actorRole)
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, login, event.GetOccurredAt())
		return
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, alertURN, relationActedOn, linkAttrs))
	addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), actorURN, login, event.GetOccurredAt())
}

func mergeCSVLinkAttribute(attributes map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if attributes == nil || key == "" || value == "" {
		return
	}
	for _, existing := range strings.Split(attributes[key], ",") {
		if strings.TrimSpace(existing) == value {
			return
		}
	}
	if strings.TrimSpace(attributes[key]) == "" {
		attributes[key] = value
		return
	}
	attributes[key] += "," + value
}

func githubOrgMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	login := strings.TrimSpace(attributes["login"])
	role := strings.TrimSpace(attributes["role"])
	userID := strings.TrimSpace(attributes["user_id"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org", Label: owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	memberURN := projectionURN(tenantID, "github_user", login)
	if login != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: memberURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.user", Label: login,
			Attributes: map[string]string{"login": login, "user_id": userID, "role": role},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), memberURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId(), "role": role}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), event.GetId(), memberURN, login, event.GetOccurredAt())
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubOrgInstallationProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attributes := event.GetAttributes()
	owner := strings.TrimSpace(attributes["owner"])
	installID := strings.TrimSpace(attributes["installation_id"])
	appSlug := strings.TrimSpace(attributes["app_slug"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", owner)
	if owner != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: orgURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org", Label: owner,
			Attributes: map[string]string{"org": owner},
		})
	}

	installURN := projectionURN(tenantID, "github_installation", installID)
	if installID != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN: installURN, TenantID: tenantID, SourceID: event.GetSourceId(),
			EntityType: "github.org_installation", Label: firstNonEmpty(appSlug, installID),
			Attributes: map[string]string{
				"created_at":           strings.TrimSpace(attributes["created_at"]),
				"events":               strings.TrimSpace(attributes["events"]),
				"app_slug":             appSlug,
				"installation_id":      installID,
				"permissions":          strings.TrimSpace(attributes["permissions"]),
				"repository_selection": strings.TrimSpace(attributes["repository_selection"]),
				"target_type":          strings.TrimSpace(attributes["target_type"]),
				"updated_at":           strings.TrimSpace(attributes["updated_at"]),
			},
		})
		if orgURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), installURN, orgURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func githubUserURN(tenantID string, login string) string {
	value := strings.TrimSpace(login)
	if value == "" {
		return ""
	}
	return projectionURN(tenantID, "github_user", value)
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

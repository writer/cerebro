package sourceprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	relationActedOn       = "acted_on"
	relationAuthored      = "authored"
	relationBelongsTo     = "belongs_to"
	relationHasIdentifier = "has_identifier"
	relationTargeted      = "targeted"
)

// Service materializes synced source events into current-state and graph stores.
type Service struct {
	state ports.ProjectionStateStore
	graph ports.ProjectionGraphStore
}

// New constructs a source projector.
func New(state ports.ProjectionStateStore, graph ports.ProjectionGraphStore) *Service {
	return &Service{state: state, graph: graph}
}

// Project applies one source event to the configured state and graph stores.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("event is required")
	}
	if s == nil || (s.state == nil && s.graph == nil) {
		return ports.ProjectionResult{}, nil
	}
	entities, links, err := projectionsForEvent(event)
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

func projectionsForEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	switch strings.TrimSpace(event.GetKind()) {
	case "github.pull_request":
		return githubPullRequestProjections(event)
	case "github.audit":
		return githubAuditProjections(event)
	case "okta.user":
		return oktaUserProjections(event)
	case "okta.audit":
		return oktaAuditProjections(event)
	default:
		return nil, nil, nil
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
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), authorURN, author)
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
	targetUser := strings.TrimSpace(attributes["user"])

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}

	orgURN := projectionURN(tenantID, "github_org", org)
	if org != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        orgURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.org",
			Label:      org,
			Attributes: map[string]string{"org": org},
		})
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

	actorURN := githubUserURN(tenantID, actor)
	if actorURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      actor,
			Attributes: map[string]string{"login": actor},
		})
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, map[string]string{
				"action":   strings.TrimSpace(attributes["action"]),
				"event_id": event.GetId(),
			}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), actorURN, actor)
	}

	targetURN := githubUserURN(tenantID, targetUser)
	if targetURN != "" && targetURN != actorURN {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        targetURN,
			TenantID:   tenantID,
			SourceID:   event.GetSourceId(),
			EntityType: "github.user",
			Label:      targetUser,
			Attributes: map[string]string{"login": targetUser},
		})
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), targetURN, resourceURN, relationTargeted, map[string]string{"event_id": event.GetId()}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), targetURN, targetUser)
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
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), userURN, email)
		if !sameIdentifier(email, login) {
			addIdentifierLink(entities, links, tenantID, event.GetSourceId(), userURN, login)
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
		if resourceURN != "" {
			addLink(links, projectedLink(tenantID, event.GetSourceId(), actorURN, resourceURN, relationActedOn, map[string]string{
				"event_id":   event.GetId(),
				"event_type": strings.TrimSpace(attributes["event_type"]),
			}))
		}
		addIdentifierLink(entities, links, tenantID, event.GetSourceId(), actorURN, actorAlternateID)
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
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

func addIdentifierLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, fromURN string, value string) {
	identifierURN, identifierType, label := identifierURN(tenantID, value)
	if identifierURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        identifierURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: identifierType,
		Label:      label,
		Attributes: map[string]string{"value": label},
	})
	addLink(links, projectedLink(tenantID, sourceID, fromURN, identifierURN, relationHasIdentifier, nil))
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
	if looksLikeEmail(value) {
		normalized := normalizeIdentifier(value)
		return projectionURN(tenantID, "identifier", "email", normalized), "identifier.email", normalized
	}
	normalized := normalizeIdentifier(value)
	return projectionURN(tenantID, "identifier", "login", normalized), "identifier.login", normalized
}

func looksLikeEmail(value string) bool {
	return strings.Contains(strings.TrimSpace(value), "@")
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

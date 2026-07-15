package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

func datadogUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	attrs := event.GetAttributes()
	primary.Attributes["active"] = boolString(!projectionBool(attrs["disabled"]))
	if email := strings.TrimSpace(attrs["email"]); email != "" && primary.TenantID != "" {
		entityMap, linkMap := projectionMaps(entities, links)
		addIdentifierLink(entityMap, linkMap, primary.TenantID, event.GetSourceId(), event.GetId(), primary.URN, email, event.GetOccurredAt())
		outEntities, outLinks := entitiesAndLinks(entityMap, linkMap)
		return outEntities, outLinks, nil
	}
	return entities, links, nil
}

func datadogTaggedResourceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	return datadogAddOwnershipAndServiceContext(event, entities, links)
}

func datadogIncidentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	entityMap, linkMap := projectionMaps(entities, links)
	primary := entities[0]
	tenant := primary.TenantID
	attrs := event.GetAttributes()
	if tenant != "" {
		for _, ref := range []struct {
			idKey    string
			emailKey string
			match    string
		}{
			{idKey: "commander_user_id", emailKey: "commander_email", match: "datadog_incident_commander"},
			{idKey: "created_by_user_id", emailKey: "created_by_email", match: "datadog_incident_creator"},
		} {
			userID := strings.TrimSpace(firstNonEmpty(attrs[ref.idKey], attrs[ref.emailKey]))
			if userID == "" {
				continue
			}
			userURN := datadogURN(tenant, "datadog_users", userID)
			userAttrs := map[string]string{"user_id": userID}
			if email := strings.TrimSpace(attrs[ref.emailKey]); email != "" {
				userAttrs["email"] = email
			}
			addEntity(entityMap, &ports.ProjectedEntity{
				URN:        userURN,
				TenantID:   tenant,
				SourceID:   event.GetSourceId(),
				EntityType: "datadog.users",
				Label:      userID,
				Attributes: userAttrs,
			})
			if email := strings.TrimSpace(attrs[ref.emailKey]); email != "" {
				addIdentifierLink(entityMap, linkMap, tenant, event.GetSourceId(), event.GetId(), userURN, email, event.GetOccurredAt())
			}
			addLink(linkMap, projectedLink(tenant, event.GetSourceId(), userURN, primary.URN, relationActedOn, datadogLinkAttrs(event, ref.match)))
		}
	}
	datadogAddOwnershipAndServiceContextTo(event, primary, entityMap, linkMap)
	outEntities, outLinks := entitiesAndLinks(entityMap, linkMap)
	return outEntities, outLinks, nil
}

func datadogAuditEventProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	tenant := primary.TenantID
	if tenant == "" {
		return entities, links, nil
	}
	attrs := event.GetAttributes()
	entityMap, linkMap := projectionMaps(entities, links)
	actorURN := ""
	if actorID := strings.TrimSpace(firstNonEmpty(attrs["actor_id"], attrs["actor_email"], attrs["actor_name"])); actorID != "" {
		actorURN = datadogURN(tenant, "datadog_users", actorID)
		actorAttrs := map[string]string{"user_id": actorID}
		if email := strings.TrimSpace(attrs["actor_email"]); email != "" {
			actorAttrs["email"] = email
		}
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        actorURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "datadog.users",
			Label:      firstNonEmpty(attrs["actor_email"], attrs["actor_name"], actorID),
			Attributes: actorAttrs,
		})
		if email := strings.TrimSpace(attrs["actor_email"]); email != "" {
			addIdentifierLink(entityMap, linkMap, tenant, event.GetSourceId(), event.GetId(), actorURN, email, event.GetOccurredAt())
		}
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), actorURN, primary.URN, relationActedOn, datadogLinkAttrs(event, "datadog_audit_actor")))
	}
	if resourceID := strings.TrimSpace(firstNonEmpty(attrs["resource_id"], attrs["resource_name"])); resourceID != "" {
		resourceType := strings.TrimSpace(firstNonEmpty(attrs["resource_type"], "resource"))
		resourceURN := datadogURN(tenant, "datadog_resource", resourceType+":"+resourceID)
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        resourceURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "datadog.resource",
			Label:      firstNonEmpty(attrs["resource_name"], resourceID),
			Attributes: map[string]string{
				"resource_id":   resourceID,
				"resource_type": resourceType,
				"resource_name": strings.TrimSpace(attrs["resource_name"]),
			},
		})
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), primary.URN, resourceURN, relationObservedOn, datadogLinkAttrs(event, "datadog_audit_resource")))
		if actorURN != "" {
			addLink(linkMap, projectedLink(tenant, event.GetSourceId(), actorURN, resourceURN, relationActedOn, datadogLinkAttrs(event, "datadog_audit_actor_resource")))
		}
	}
	outEntities, outLinks := entitiesAndLinks(entityMap, linkMap)
	return outEntities, outLinks, nil
}

func datadogAddOwnershipAndServiceContext(event *cerebrov1.EventEnvelope, entities []*ports.ProjectedEntity, links []*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	tenant := primary.TenantID
	if tenant == "" {
		return entities, links, nil
	}
	entityMap, linkMap := projectionMaps(entities, links)
	datadogAddOwnershipAndServiceContextTo(event, primary, entityMap, linkMap)
	return entitiesAndLinksWithNilError(entityMap, linkMap)
}

func datadogAddOwnershipAndServiceContextTo(event *cerebrov1.EventEnvelope, primary *ports.ProjectedEntity, entityMap map[string]*ports.ProjectedEntity, linkMap map[string]*ports.ProjectedLink) {
	if event == nil || primary == nil || primary.TenantID == "" {
		return
	}
	tenant := primary.TenantID
	attrs := event.GetAttributes()
	for _, service := range datadogContextValues(attrs, "service") {
		serviceURN := datadogURN(tenant, "datadog_service", service)
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        serviceURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "datadog.service",
			Label:      service,
			Attributes: map[string]string{"service": service},
		})
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), primary.URN, serviceURN, relationBelongsTo, datadogLinkAttrs(event, "datadog_service_tag")))
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), serviceURN, primary.URN, relationContains, datadogLinkAttrs(event, "datadog_service_tag")))
	}
	for _, team := range datadogContextValues(attrs, "team") {
		teamURN := datadogURN(tenant, "datadog_teams", team)
		addEntity(entityMap, &ports.ProjectedEntity{
			URN:        teamURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "datadog.teams",
			Label:      team,
			Attributes: map[string]string{"team_id": team, "handle": team},
		})
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), primary.URN, teamURN, relationBelongsTo, datadogLinkAttrs(event, "datadog_team_tag")))
		addLink(linkMap, projectedLink(tenant, event.GetSourceId(), teamURN, primary.URN, relationContains, datadogLinkAttrs(event, "datadog_team_tag")))
	}
}

func entitiesAndLinksWithNilError(entityMap map[string]*ports.ProjectedEntity, linkMap map[string]*ports.ProjectedLink) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	outEntities, outLinks := entitiesAndLinks(entityMap, linkMap)
	return outEntities, outLinks, nil
}

func projectionMaps(entities []*ports.ProjectedEntity, links []*ports.ProjectedLink) (map[string]*ports.ProjectedEntity, map[string]*ports.ProjectedLink) {
	entityMap := map[string]*ports.ProjectedEntity{}
	linkMap := map[string]*ports.ProjectedLink{}
	for _, entity := range entities {
		addEntity(entityMap, entity)
	}
	for _, link := range links {
		addLink(linkMap, link)
	}
	return entityMap, linkMap
}

func datadogContextValues(attrs map[string]string, key string) []string {
	seen := map[string]struct{}{}
	values := []string{}
	for _, value := range []string{attrs[key], attrs[key+"_id"], attrs[key+"_name"]} {
		datadogAppendContextValue(seen, &values, value)
	}
	for _, tag := range strings.Split(attrs["tags"], ",") {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(strings.ToLower(tag), key+":") {
			datadogAppendContextValue(seen, &values, strings.TrimSpace(tag[len(key)+1:]))
		}
	}
	return values
}

func datadogAppendContextValue(seen map[string]struct{}, values *[]string, value string) {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, "{") || strings.Contains(part, "}") {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		*values = append(*values, part)
	}
}

func datadogURN(tenantID string, kind string, id string) string {
	return "urn:cerebro:" + cerebrourn.EncodeSegment(tenantID) + ":" + cerebrourn.EncodeSegment(kind) + ":" + cerebrourn.EncodeSegment(id)
}

func datadogLinkAttrs(event *cerebrov1.EventEnvelope, matchType string) map[string]string {
	return map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": matchType,
	}
}

package sourceprojection

import (
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func slackTeamURN(tenantID string, teamID string) string {
	return projectionURN(tenantID, "slack_team", strings.TrimSpace(teamID))
}

// slackTeamProjections materializes the Slack workspace/team entity that
// team-scoped users, channels, and user groups anchor to.
func slackTeamProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return genericInventoryProjections(event)
}

// slackTeamScopedProjections materializes a team-scoped Slack entity (channel or
// user group) and links it to its workspace/team context so resources resolve to
// the workspace they belong to.
func slackTeamScopedProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return slackWithTeamContext(event, nil)
}

// slackUserProjections materializes a Slack user entity, links it to its
// workspace/team context, and annotates it with current privilege and MFA
// posture so durable identity findings anchor on the user's current state rather
// than transient audit events.
func slackUserProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return slackWithTeamContext(event, enrichSlackUserPosture)
}

func slackChannelMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return slackMembershipProjections(event, "channel_id", "slack_channel", "slack.channel", "slack_channel_member")
}

func slackUserGroupMemberProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return slackMembershipProjections(event, "usergroup_id", "slack_user_group", "slack.user_group", "slack_user_group_member")
}

func slackAccessLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "slack"})
}

func slackAuditLogProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "slack"})
}

func slackMembershipProjections(event *cerebrov1.EventEnvelope, containerAttr string, containerKind string, containerEntityType string, matchType string) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	userID := strings.TrimSpace(attrs["user_id"])
	containerID := strings.TrimSpace(attrs[containerAttr])
	if userID == "" || containerID == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	userURN := projectionURN(tenantID, "slack_user", userID)
	containerURN := projectionURN(tenantID, containerKind, containerID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        userURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: "slack.user",
		Attributes: map[string]string{"user_id": userID},
	})
	addEntity(entities, &ports.ProjectedEntity{
		URN:        containerURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: containerEntityType,
		Attributes: map[string]string{containerAttr: containerID},
	})
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": matchType,
	}
	addLink(links, projectedLink(tenantID, event.GetSourceId(), userURN, containerURN, relationMemberOf, linkAttrs))
	addLink(links, projectedLink(tenantID, event.GetSourceId(), containerURN, userURN, relationContains, linkAttrs))
	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

func slackWithTeamContext(event *cerebrov1.EventEnvelope, enrich func([]*ports.ProjectedEntity, *cerebrov1.EventEnvelope)) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	projectedEntities, projectedLinks, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if enrich != nil {
		enrich(projectedEntities, event)
	}
	if len(projectedEntities) == 0 {
		return projectedEntities, projectedLinks, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	for _, entity := range projectedEntities {
		addEntity(entities, entity)
	}
	for _, link := range projectedLinks {
		addLink(links, link)
	}
	primary := projectedEntities[0]
	tenant := primary.TenantID
	attrs := event.GetAttributes()
	if tenant != "" {
		switch primary.EntityType {
		case "slack.user":
			addIdentifierLink(entities, links, tenant, event.GetSourceId(), event.GetId(), primary.URN, attrs["email"], event.GetOccurredAt())
		case "slack.channel":
			addSlackChannelCreatorLink(entities, links, tenant, event, primary.URN, attrs)
		}
	}
	teamIDs := slackTeamContextIDs(attrs)
	if tenant == "" || len(teamIDs) == 0 {
		outEntities, outLinks := entitiesAndLinks(entities, links)
		return outEntities, outLinks, nil
	}
	linkAttrs := map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "slack_team",
	}
	for _, teamID := range teamIDs {
		teamURN := slackTeamURN(tenant, teamID)
		if primary.URN == teamURN {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        teamURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "slack.team",
			Attributes: map[string]string{"team_id": teamID},
		})
		addLink(links, projectedLink(tenant, event.GetSourceId(), primary.URN, teamURN, relationBelongsTo, linkAttrs))
		addLink(links, projectedLink(tenant, event.GetSourceId(), teamURN, primary.URN, relationContains, linkAttrs))
	}
	outEntities, outLinks := entitiesAndLinks(entities, links)
	return outEntities, outLinks, nil
}

func addSlackChannelCreatorLink(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenant string, event *cerebrov1.EventEnvelope, channelURN string, attrs map[string]string) {
	creatorID := strings.TrimSpace(attrs["creator"])
	if creatorID == "" {
		return
	}
	creatorURN := projectionURN(tenant, "slack_user", creatorID)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        creatorURN,
		TenantID:   tenant,
		SourceID:   event.GetSourceId(),
		EntityType: "slack.user",
		Attributes: map[string]string{"user_id": creatorID},
	})
	addLink(links, projectedLink(tenant, event.GetSourceId(), creatorURN, channelURN, relationAuthored, map[string]string{
		"event_id":   event.GetId(),
		"at":         eventObservedAt(event),
		"match_type": "slack_channel_creator",
	}))
}

// slackTeamContextIDs resolves the distinct real team IDs a Slack entity is
// scoped to. Shared (Slack Connect) channels expose multi-valued team
// membership, which upstream normalization may collapse into a comma-joined
// string; splitting it here keeps one team link per real team instead of one
// synthetic comma-joined team.
func slackTeamContextIDs(attrs map[string]string) []string {
	seen := map[string]struct{}{}
	ids := make([]string, 0, 2)
	for _, raw := range []string{attrs["team_id"], attrs["shared_team_ids"]} {
		for _, part := range strings.Split(raw, ",") {
			id := strings.TrimSpace(part)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// enrichSlackUserPosture derives current privilege and MFA enrollment posture
// flags on the projected Slack user entity so durable identity findings can
// anchor on the user's current state. Slack user snapshots expose a user's 2FA
// enrollment status, not workspace-level MFA enforcement policy.
func enrichSlackUserPosture(entities []*ports.ProjectedEntity, event *cerebrov1.EventEnvelope) {
	attrs := event.GetAttributes()
	privileged := slackUserPrivileged(attrs)
	hasMFA := slackUserHasMFA(attrs)
	active := !slackUserDeactivated(attrs)
	for _, entity := range entities {
		if entity == nil || entity.EntityType != "slack.user" {
			continue
		}
		if entity.Attributes == nil {
			entity.Attributes = map[string]string{}
		}
		entity.Attributes["privileged"] = boolString(privileged)
		entity.Attributes["has_mfa"] = boolString(hasMFA)
		entity.Attributes["mfa_enrolled"] = boolString(hasMFA)
		entity.Attributes["active"] = boolString(active)
	}
}

func slackUserPrivileged(attributes map[string]string) bool {
	return projectionBool(attributes["is_admin"]) ||
		projectionBool(attributes["is_owner"]) ||
		projectionBool(attributes["is_primary_owner"])
}

func slackUserHasMFA(attributes map[string]string) bool {
	return projectionBool(attributes["has_mfa"]) || projectionBool(attributes["has_2fa"])
}

func slackUserDeactivated(attributes map[string]string) bool {
	return projectionBool(attributes["deleted"])
}

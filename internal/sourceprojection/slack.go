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

func slackWithTeamContext(event *cerebrov1.EventEnvelope, enrich func([]*ports.ProjectedEntity, *cerebrov1.EventEnvelope)) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	entities, links, err := genericInventoryProjections(event)
	if err != nil {
		return nil, nil, err
	}
	if enrich != nil {
		enrich(entities, event)
	}
	if len(entities) == 0 {
		return entities, links, nil
	}
	primary := entities[0]
	tenant := primary.TenantID
	teamIDs := slackTeamContextIDs(event.GetAttributes())
	if tenant == "" || len(teamIDs) == 0 {
		return entities, links, nil
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
		entities = append(entities, &ports.ProjectedEntity{
			URN:        teamURN,
			TenantID:   tenant,
			SourceID:   event.GetSourceId(),
			EntityType: "slack.team",
			Label:      teamID,
			Attributes: map[string]string{"team_id": teamID},
		})
		links = append(links,
			projectedLink(tenant, event.GetSourceId(), primary.URN, teamURN, relationBelongsTo, linkAttrs),
			projectedLink(tenant, event.GetSourceId(), teamURN, primary.URN, relationContains, linkAttrs),
		)
	}
	return entities, links, nil
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

// enrichSlackUserPosture derives current privilege and MFA posture flags on the
// projected Slack user entity so the orphaned-privileged identity finding can
// anchor on the user's current state.
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
		entity.Attributes["mfa_enforced"] = boolString(hasMFA)
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

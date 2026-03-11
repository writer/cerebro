package graph

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

type personInteractionAggregate struct {
	Source              string
	Target              string
	CallCount           int64
	CoActions           int64
	SharedGroups        int64
	SharedApps          int64
	TotalDurationSecond float64
	LastSeen            time.Time
	Sources             map[string]struct{}
}

func (b *Builder) buildPersonInteractionEdges(ctx context.Context) {
	identityToPerson := b.identityToPersonIndex()
	if len(identityToPerson) == 0 {
		return
	}

	personByEmail := b.personByEmailIndex()
	gongUserToPerson := b.gongUserToPersonIndex(ctx, personByEmail)

	aggregates := make(map[string]*personInteractionAggregate)

	merge := func(rawA string, rawB string, source string, updater func(*personInteractionAggregate)) {
		personA := resolvePersonID(rawA, identityToPerson, gongUserToPerson)
		personB := resolvePersonID(rawB, identityToPerson, gongUserToPerson)
		if personA == "" || personB == "" || personA == personB {
			return
		}
		if personA > personB {
			personA, personB = personB, personA
		}
		key := personA + "|" + personB
		agg, ok := aggregates[key]
		if !ok {
			agg = &personInteractionAggregate{
				Source:  personA,
				Target:  personB,
				Sources: make(map[string]struct{}),
			}
			aggregates[key] = agg
		}
		agg.Sources[source] = struct{}{}
		updater(agg)
	}

	gongRows, err := b.queryIfExists(ctx, "gong_call_participants", `
		SELECT a.user_id AS person_a, b.user_id AS person_b,
		       COUNT(*) AS interaction_count,
		       MAX(c.start_time) AS last_interaction,
		       SUM(c.duration_seconds) AS total_duration_seconds
		FROM gong_call_participants a
		JOIN gong_call_participants b ON a.call_id = b.call_id AND a.user_id < b.user_id
		JOIN gong_calls c ON a.call_id = c.id
		WHERE a.user_id IS NOT NULL AND b.user_id IS NOT NULL
		GROUP BY a.user_id, b.user_id
	`)
	if err != nil {
		b.logger.Debug("failed to query gong interaction edges", "error", err)
	} else {
		for _, row := range gongRows.Rows {
			merge(queryRowString(row, "person_a"), queryRowString(row, "person_b"), "gong_calls", func(agg *personInteractionAggregate) {
				agg.CallCount += int64FromValue(queryRow(row, "interaction_count"))
				agg.TotalDurationSecond += float64FromValue(queryRow(row, "total_duration_seconds"))
				agg.LastSeen = maxTime(agg.LastSeen, parseCDCEventTime(queryRow(row, "last_interaction")))
			})
		}
	}

	oktaCoActivityRows, err := b.queryIfExists(ctx, "okta_system_logs", `
		SELECT a.actor_id AS person_a, b.actor_id AS person_b,
		       COUNT(*) AS co_actions,
		       MAX(GREATEST(a.published, b.published)) AS last_interaction
		FROM okta_system_logs a
		JOIN okta_system_logs b ON a.target_id = b.target_id AND a.actor_id < b.actor_id
		WHERE a.actor_id IS NOT NULL AND b.actor_id IS NOT NULL
		  AND a.target_id IS NOT NULL
		  AND ABS(DATEDIFF('hour', a.published, b.published)) < 24
		GROUP BY a.actor_id, b.actor_id
	`)
	if err != nil {
		b.logger.Debug("failed to query okta co-activity edges", "error", err)
	} else {
		for _, row := range oktaCoActivityRows.Rows {
			merge(queryRowString(row, "person_a"), queryRowString(row, "person_b"), "okta_co_activity", func(agg *personInteractionAggregate) {
				agg.CoActions += int64FromValue(queryRow(row, "co_actions"))
				agg.LastSeen = maxTime(agg.LastSeen, parseCDCEventTime(queryRow(row, "last_interaction")))
			})
		}
	}

	oktaSharedGroupsRows, err := b.queryIfExists(ctx, "okta_group_memberships", `
		SELECT a.user_id AS person_a, b.user_id AS person_b,
		       COUNT(DISTINCT a.group_id) AS shared_groups
		FROM okta_group_memberships a
		JOIN okta_group_memberships b ON a.group_id = b.group_id AND a.user_id < b.user_id
		GROUP BY a.user_id, b.user_id
	`)
	if err != nil {
		b.logger.Debug("failed to query okta shared-group edges", "error", err)
	} else {
		for _, row := range oktaSharedGroupsRows.Rows {
			merge(queryRowString(row, "person_a"), queryRowString(row, "person_b"), "okta_shared_groups", func(agg *personInteractionAggregate) {
				agg.SharedGroups += int64FromValue(queryRow(row, "shared_groups"))
			})
		}
	}

	oktaSharedAppsRows, err := b.queryIfExists(ctx, "okta_app_assignments", `
		SELECT a.assignee_id AS person_a, b.assignee_id AS person_b,
		       COUNT(DISTINCT a.app_id) AS shared_apps
		FROM okta_app_assignments a
		JOIN okta_app_assignments b ON a.app_id = b.app_id AND a.assignee_id < b.assignee_id
		WHERE a.assignee_type = 'USER' AND b.assignee_type = 'USER'
		GROUP BY a.assignee_id, b.assignee_id
	`)
	if err != nil {
		b.logger.Debug("failed to query okta shared-app edges", "error", err)
	} else {
		for _, row := range oktaSharedAppsRows.Rows {
			merge(queryRowString(row, "person_a"), queryRowString(row, "person_b"), "okta_shared_apps", func(agg *personInteractionAggregate) {
				agg.SharedApps += int64FromValue(queryRow(row, "shared_apps"))
			})
		}
	}

	edges := make([]*Edge, 0, len(aggregates))
	for _, agg := range aggregates {
		if agg == nil {
			continue
		}
		frequency := agg.CallCount + agg.CoActions + agg.SharedGroups + agg.SharedApps
		if frequency <= 0 {
			continue
		}
		lastSeen := agg.LastSeen
		if lastSeen.IsZero() {
			lastSeen = time.Now().UTC()
		}
		edges = append(edges, &Edge{
			ID:     "person_interaction:" + agg.Source + "<->" + agg.Target,
			Source: agg.Source,
			Target: agg.Target,
			Kind:   EdgeKindInteractedWith,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"call_count":               agg.CallCount,
				"co_actions":               agg.CoActions,
				"shared_groups":            agg.SharedGroups,
				"shared_apps":              agg.SharedApps,
				"frequency":                frequency,
				"last_seen":                lastSeen,
				"total_duration_seconds":   agg.TotalDurationSecond,
				"strength":                 relationshipStrength(lastSeen, float64(frequency)),
				"interaction_source_types": sortedKeys(agg.Sources),
			},
		})
	}

	b.graph.AddEdgesBatch(edges)
}

func (b *Builder) identityToPersonIndex() map[string]string {
	index := make(map[string]string)
	for _, person := range b.graph.GetNodesByKind(NodeKindPerson) {
		index[person.ID] = person.ID
	}
	for _, edgeList := range b.graph.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindResolvesTo {
				continue
			}
			if strings.HasPrefix(edge.Target, "person:") {
				index[edge.Source] = edge.Target
			}
		}
	}
	return index
}

func (b *Builder) personByEmailIndex() map[string]string {
	index := make(map[string]string)
	for _, person := range b.graph.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		if email := normalizePersonEmail(queryRowString(person.Properties, "email")); email != "" {
			index[email] = person.ID
		}
		if rawEmails, ok := queryRowValue(person.Properties, "emails"); ok {
			for _, email := range stringSliceFromValue(rawEmails) {
				email = normalizePersonEmail(email)
				if email == "" {
					continue
				}
				index[email] = person.ID
			}
		}
	}
	return index
}

func (b *Builder) gongUserToPersonIndex(ctx context.Context, personByEmail map[string]string) map[string]string {
	index := make(map[string]string)
	if len(personByEmail) == 0 {
		return index
	}

	rows, err := b.queryIfExists(ctx, "gong_users", `SELECT id, email FROM gong_users`)
	if err != nil {
		b.logger.Debug("failed to query gong users for person mapping", "error", err)
		return index
	}
	for _, row := range rows.Rows {
		gongID := strings.TrimSpace(queryRowString(row, "id"))
		email := normalizePersonEmail(queryRowString(row, "email"))
		if gongID == "" || email == "" {
			continue
		}
		if personID := personByEmail[email]; personID != "" {
			index[gongID] = personID
		}
	}
	return index
}

func resolvePersonID(rawID string, identityToPerson map[string]string, fallback map[string]string) string {
	rawID = strings.TrimSpace(rawID)
	if rawID == "" {
		return ""
	}
	if personID := identityToPerson[rawID]; personID != "" {
		return personID
	}
	if personID := fallback[rawID]; personID != "" {
		return personID
	}
	if strings.HasPrefix(rawID, "person:") {
		return rawID
	}
	return ""
}

func relationshipStrength(lastInteraction time.Time, frequency float64) float64 {
	if frequency <= 0 {
		return 0
	}
	if lastInteraction.IsZero() {
		lastInteraction = time.Now().UTC()
	}
	daysSince := time.Since(lastInteraction).Hours() / 24
	if daysSince < 0 {
		daysSince = 0
	}
	recency := math.Exp(-daysSince / 30)
	return recency * math.Log1p(frequency)
}

func int64FromValue(value any) int64 {
	switch typed := value.(type) {
	case nil:
		return 0
	case int:
		return int64(typed)
	case int64:
		return typed
	case int32:
		return int64(typed)
	case float64:
		return int64(typed)
	case float32:
		return int64(typed)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err == nil {
			return parsed
		}
		parsedFloat, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err == nil {
			return int64(parsedFloat)
		}
	}
	return 0
}

func float64FromValue(value any) float64 {
	switch typed := value.(type) {
	case nil:
		return 0
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func maxTime(a time.Time, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func stringSliceFromValue(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			values = append(values, toString(item))
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

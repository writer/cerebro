package app

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) initTapGraphConsumer(ctx context.Context) {
	if !a.Config.NATSConsumerEnabled {
		return
	}
	subject := "ensemble.tap.>"
	if len(a.Config.NATSConsumerSubjects) > 0 && strings.TrimSpace(a.Config.NATSConsumerSubjects[0]) != "" {
		subject = strings.TrimSpace(a.Config.NATSConsumerSubjects[0])
	}
	if len(a.Config.NATSConsumerSubjects) > 1 {
		a.Logger.Warn("multiple NATS consumer subjects configured; using first subject only",
			"configured_subjects", a.Config.NATSConsumerSubjects,
			"active_subject", subject,
		)
	}

	consumer, err := events.NewJetStreamConsumer(events.ConsumerConfig{
		URLs:                  a.Config.NATSJetStreamURLs,
		Stream:                a.Config.NATSConsumerStream,
		Subject:               subject,
		Durable:               a.Config.NATSConsumerDurable,
		BatchSize:             a.Config.NATSConsumerBatchSize,
		AckWait:               a.Config.NATSConsumerAckWait,
		FetchTimeout:          a.Config.NATSConsumerFetchTimeout,
		ConnectTimeout:        a.Config.NATSJetStreamConnectTimeout,
		AuthMode:              a.Config.NATSJetStreamAuthMode,
		Username:              a.Config.NATSJetStreamUsername,
		Password:              a.Config.NATSJetStreamPassword,
		NKeySeed:              a.Config.NATSJetStreamNKeySeed,
		UserJWT:               a.Config.NATSJetStreamUserJWT,
		TLSEnabled:            a.Config.NATSJetStreamTLSEnabled,
		TLSCAFile:             a.Config.NATSJetStreamTLSCAFile,
		TLSCertFile:           a.Config.NATSJetStreamTLSCertFile,
		TLSKeyFile:            a.Config.NATSJetStreamTLSKeyFile,
		TLSServerName:         a.Config.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: a.Config.NATSJetStreamTLSInsecure,
	}, a.Logger, a.handleTapCloudEvent)
	if err != nil {
		a.Logger.Warn("failed to initialize tap graph consumer", "error", err)
		return
	}
	a.TapConsumer = consumer
	a.Logger.Info("tap graph consumer enabled",
		"stream", a.Config.NATSConsumerStream,
		"subject", subject,
		"durable", a.Config.NATSConsumerDurable,
		"batch_size", a.Config.NATSConsumerBatchSize,
	)

	_ = ctx
}

func (a *App) handleTapCloudEvent(_ context.Context, evt events.CloudEvent) error {
	if !strings.HasPrefix(evt.Type, "ensemble.tap.") {
		return nil
	}
	system, entityType, action := parseTapType(evt.Type)
	if system == "" {
		return nil
	}
	if isTapActivityType(evt.Type) {
		return a.handleTapActivityEvent(system, entityType, evt)
	}

	entityID := strings.TrimSpace(anyToString(evt.Data["entity_id"]))
	if entityID == "" {
		entityID = strings.TrimSpace(anyToString(evt.Data["id"]))
	}
	if entityID == "" {
		return nil
	}

	kind := mapBusinessEntityKind(entityType)
	nodeID := fmt.Sprintf("%s:%s:%s", system, entityType, entityID)
	existingProperties := map[string]any{}
	if a.SecurityGraph != nil {
		if existingNode, ok := a.SecurityGraph.GetNode(nodeID); ok && existingNode != nil && existingNode.Properties != nil {
			existingProperties = existingNode.Properties
		}
	}

	properties := map[string]any{
		"source_system": system,
		"entity_type":   entityType,
		"action":        action,
		"event_type":    evt.Type,
		"event_time":    evt.Time.UTC().Format(time.RFC3339),
	}

	snapshot := mapFromAny(evt.Data["snapshot"])
	changes := mapFromAny(evt.Data["changes"])
	for k, v := range snapshot {
		properties[k] = v
	}
	properties["changes"] = changes
	for k, v := range deriveComputedFields(system, entityType, snapshot, changes, existingProperties, evt.Time) {
		properties[k] = v
	}
	if action == "deleted" {
		properties["inactive"] = true
	}

	node := &graph.Node{
		ID:         nodeID,
		Kind:       kind,
		Name:       coalesceString(anyToString(snapshot["name"]), entityID),
		Provider:   system,
		Properties: properties,
		Risk:       graph.RiskNone,
	}

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
	}
	a.SecurityGraph.AddNode(node)

	// Link foreign-key relationships from snapshot data.
	edges := extractBusinessEdges(system, entityType, nodeID, snapshot)
	for _, e := range edges {
		if _, ok := a.SecurityGraph.GetNode(e.Target); !ok {
			targetParts := strings.SplitN(e.Target, ":", 3)
			targetKind := graph.NodeKindCompany
			targetProvider := system
			targetName := e.Target
			if len(targetParts) == 3 {
				targetProvider = targetParts[0]
				targetKind = mapBusinessEntityKind(targetParts[1])
				targetName = targetParts[2]
			}
			a.SecurityGraph.AddNode(&graph.Node{
				ID:       e.Target,
				Kind:     targetKind,
				Name:     targetName,
				Provider: targetProvider,
				Risk:     graph.RiskNone,
			})
		}
		a.SecurityGraph.AddEdge(e)
	}

	return nil
}

func parseTapType(eventType string) (system string, entityType string, action string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 5 {
		return "", "", ""
	}
	if len(parts) >= 5 && strings.EqualFold(parts[2], "activity") {
		// ensemble.tap.activity.<source>.<type>
		return strings.ToLower(parts[3]), strings.ToLower(parts[4]), strings.ToLower(parts[len(parts)-1])
	}
	// ensemble.tap.<system>.<entity>.<action>
	system = strings.ToLower(parts[2])
	entityType = strings.ToLower(parts[3])
	action = strings.ToLower(parts[len(parts)-1])
	return system, entityType, action
}

func isTapActivityType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.activity.")
}

func (a *App) handleTapActivityEvent(source, activityType string, evt events.CloudEvent) error {
	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
	}

	actorID, actorName := parseTapActivityActor(evt.Data["actor"])
	if actorID == "" {
		actorID = strings.TrimSpace(anyToString(firstPresent(evt.Data, "actor_email", "actor_id", "user_email", "user_id")))
	}
	if actorID == "" {
		return nil
	}
	actorNodeID := actorID
	if !strings.Contains(actorNodeID, ":") {
		actorNodeID = "person:" + strings.ToLower(actorNodeID)
	}

	targetNodeID, targetKind, targetName := parseTapActivityTarget(evt.Data["target"], source)
	if targetNodeID == "" {
		targetID := strings.TrimSpace(anyToString(firstPresent(evt.Data, "entity_id", "target_id", "id")))
		if targetID != "" {
			targetNodeID = fmt.Sprintf("%s:entity:%s", source, targetID)
			targetKind = graph.NodeKindCompany
			targetName = targetID
		}
	}
	if targetNodeID == "" {
		return nil
	}

	occurredAt := evt.Time.UTC()
	if ts, ok := parseTimeValue(firstPresent(evt.Data, "timestamp", "event_time", "occurred_at")); ok {
		occurredAt = ts.UTC()
	}
	action := strings.TrimSpace(anyToString(evt.Data["action"]))
	if action == "" {
		action = activityType
	}

	activityID := strings.TrimSpace(evt.ID)
	if activityID == "" {
		activityID = fmt.Sprintf("%d", occurredAt.UnixNano())
	}
	activityNodeID := fmt.Sprintf("activity:%s:%s:%s", source, activityType, activityID)
	metadata := mapFromAny(evt.Data["metadata"])

	a.SecurityGraph.AddNode(&graph.Node{
		ID:       actorNodeID,
		Kind:     graph.NodeKindUser,
		Name:     coalesceString(actorName, actorID),
		Provider: source,
		Risk:     graph.RiskNone,
		Properties: map[string]any{
			"email": actorID,
		},
	})

	a.SecurityGraph.AddNode(&graph.Node{
		ID:         targetNodeID,
		Kind:       targetKind,
		Name:       coalesceString(targetName, targetNodeID),
		Provider:   source,
		Risk:       graph.RiskNone,
		Properties: map[string]any{"source_system": source},
	})

	a.SecurityGraph.AddNode(&graph.Node{
		ID:       activityNodeID,
		Kind:     graph.NodeKindActivity,
		Name:     coalesceString(action, activityType),
		Provider: source,
		Risk:     graph.RiskNone,
		Properties: map[string]any{
			"source_system": source,
			"event_type":    evt.Type,
			"activity_type": activityType,
			"action":        action,
			"timestamp":     occurredAt.Format(time.RFC3339),
			"metadata":      metadata,
		},
	})

	a.SecurityGraph.AddEdge(&graph.Edge{
		ID:     fmt.Sprintf("%s->%s:%s", actorNodeID, activityNodeID, graph.EdgeKindInteractedWith),
		Source: actorNodeID,
		Target: activityNodeID,
		Kind:   graph.EdgeKindInteractedWith,
		Effect: graph.EdgeEffectAllow,
		Risk:   graph.RiskNone,
		Properties: map[string]any{
			"source_system": source,
		},
	})
	a.SecurityGraph.AddEdge(&graph.Edge{
		ID:     fmt.Sprintf("%s->%s:%s", activityNodeID, targetNodeID, graph.EdgeKindInteractedWith),
		Source: activityNodeID,
		Target: targetNodeID,
		Kind:   graph.EdgeKindInteractedWith,
		Effect: graph.EdgeEffectAllow,
		Risk:   graph.RiskNone,
		Properties: map[string]any{
			"source_system": source,
		},
	})

	return nil
}

func parseTapActivityActor(raw any) (id string, name string) {
	switch actor := raw.(type) {
	case string:
		return strings.TrimSpace(actor), ""
	case map[string]any:
		id = strings.TrimSpace(anyToString(firstPresent(actor, "email", "id", "user_id", "actor_id")))
		name = strings.TrimSpace(anyToString(firstPresent(actor, "name", "display_name", "full_name")))
		return id, name
	default:
		return "", ""
	}
}

func parseTapActivityTarget(raw any, defaultSystem string) (nodeID string, kind graph.NodeKind, name string) {
	switch target := raw.(type) {
	case string:
		targetID := strings.TrimSpace(target)
		if targetID == "" {
			return "", "", ""
		}
		return fmt.Sprintf("%s:entity:%s", defaultSystem, targetID), graph.NodeKindCompany, targetID
	case map[string]any:
		targetID := strings.TrimSpace(anyToString(firstPresent(target, "id", "entity_id", "target_id")))
		if targetID == "" {
			return "", "", ""
		}
		targetType := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "type", "entity_type", "kind"))))
		if targetType == "" {
			targetType = "entity"
		}
		system := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(target, "system", "source"))))
		if system == "" {
			system = defaultSystem
		}
		name := strings.TrimSpace(anyToString(firstPresent(target, "name", "display_name", "title")))
		return fmt.Sprintf("%s:%s:%s", system, targetType, targetID), mapBusinessEntityKind(targetType), name
	default:
		return "", "", ""
	}
}

func mapBusinessEntityKind(entityType string) graph.NodeKind {
	switch strings.ToLower(strings.TrimSpace(entityType)) {
	case "customer":
		return graph.NodeKindCustomer
	case "contact":
		return graph.NodeKindContact
	case "company":
		return graph.NodeKindCompany
	case "deal":
		return graph.NodeKindDeal
	case "opportunity":
		return graph.NodeKindOpportunity
	case "subscription":
		return graph.NodeKindSubscription
	case "invoice":
		return graph.NodeKindInvoice
	case "ticket":
		return graph.NodeKindTicket
	case "lead":
		return graph.NodeKindLead
	default:
		return graph.NodeKind(entityType)
	}
}

func extractBusinessEdges(system string, entityType string, sourceNodeID string, snapshot map[string]any) []*graph.Edge {
	out := make([]*graph.Edge, 0)
	lowEntityType := strings.ToLower(entityType)
	for key, raw := range snapshot {
		if !strings.HasSuffix(strings.ToLower(key), "_id") {
			continue
		}
		targetID := strings.TrimSpace(anyToString(raw))
		if targetID == "" {
			continue
		}
		targetType := strings.ToLower(strings.TrimSuffix(key, "_id"))
		targetNodeID := fmt.Sprintf("%s:%s:%s", system, targetType, targetID)
		kind := inferBusinessEdgeKind(lowEntityType, targetType)
		out = append(out, &graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", sourceNodeID, targetNodeID, kind),
			Source: sourceNodeID,
			Target: targetNodeID,
			Kind:   kind,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"cross_system": false,
				"derived_from": key,
			},
			Risk: graph.RiskNone,
		})
	}
	return out
}

func inferBusinessEdgeKind(entityType, targetType string) graph.EdgeKind {
	switch {
	case targetType == "company" && entityType == "contact":
		return graph.EdgeKindWorksAt
	case targetType == "subscription":
		return graph.EdgeKindSubscribedTo
	case targetType == "invoice":
		return graph.EdgeKindBilledBy
	case targetType == "owner" || targetType == "assignee":
		return graph.EdgeKindAssignedTo
	case targetType == "manager":
		return graph.EdgeKindManagedBy
	case targetType == "referrer" || targetType == "referral":
		return graph.EdgeKindRefers
	case targetType == "renewal":
		return graph.EdgeKindRenews
	default:
		return graph.EdgeKindOwns
	}
}

func deriveComputedFields(system, entityType string, snapshot map[string]any, changes map[string]any, existingProperties map[string]any, eventTime time.Time) map[string]any {
	out := make(map[string]any)
	now := eventTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	switch strings.ToLower(system) {
	case "hubspot":
		if strings.EqualFold(entityType, "deal") {
			if ts, ok := parseTimeValue(firstPresent(snapshot,
				"properties.last_activity_date",
				"properties.hs_lastmodifieddate",
				"last_activity_date",
			)); ok {
				out["days_since_last_activity"] = int(now.Sub(ts).Hours() / 24)
			}
		}
	case "salesforce":
		if strings.EqualFold(entityType, "opportunity") {
			if ts, ok := parseTimeValue(firstPresent(snapshot, "LastModifiedDate", "last_modified_date")); ok {
				out["days_since_last_modified"] = int(now.Sub(ts).Hours() / 24)
			}
			count := toInt(firstPresent(existingProperties, "close_date_push_count"))
			if snapshotCount := toInt(firstPresent(snapshot, "close_date_push_count")); snapshotCount > count {
				count = snapshotCount
			}
			if changeIncludesFieldUpdate(changes, "CloseDate") {
				count++
			}
			if count > 0 {
				out["close_date_push_count"] = count
			}
		}
	case "stripe":
		if strings.EqualFold(entityType, "subscription") {
			if ts, ok := parseTimeValue(firstPresent(snapshot, "trial_end", "trial_end_at")); ok {
				days := int(math.Ceil(ts.Sub(now).Hours() / 24))
				if days < 0 {
					days = 0
				}
				out["days_until_trial_end"] = days
			}
			if _, ok := snapshot["failed_payment_count"]; !ok {
				out["failed_payment_count"] = toInt(firstPresent(snapshot,
					"billing.failed_payment_count",
					"payment.failed_count",
					"failed_payments",
				))
			}
		}
	}

	return out
}

func firstPresent(snapshot map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := nestedValue(snapshot, key); ok {
			return v
		}
	}
	return nil
}

func changeIncludesFieldUpdate(changes map[string]any, field string) bool {
	raw, ok := changes[field]
	if !ok {
		return false
	}
	// If the producer includes old/new details, only count actual value changes.
	if m, ok := raw.(map[string]any); ok {
		if oldValue, okOld := m["old"]; okOld {
			if newValue, okNew := m["new"]; okNew {
				return anyToString(oldValue) != anyToString(newValue)
			}
		}
		if fromValue, okFrom := m["from"]; okFrom {
			if toValue, okTo := m["to"]; okTo {
				return anyToString(fromValue) != anyToString(toValue)
			}
		}
	}
	return true
}

func nestedValue(m map[string]any, path string) (any, bool) {
	current := any(m)
	for _, part := range strings.Split(path, ".") {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := asMap[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func parseTimeValue(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return typed.UTC(), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
			if ts, err := time.Parse(layout, trimmed); err == nil {
				return ts.UTC(), true
			}
		}
		if unix, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return unixToTime(unix), true
		}
		return time.Time{}, false
	case int:
		return unixToTime(int64(typed)), true
	case int64:
		return unixToTime(typed), true
	case float64:
		return unixToTime(int64(typed)), true
	default:
		return time.Time{}, false
	}
}

func unixToTime(unix int64) time.Time {
	// Heuristic for milliseconds precision payloads.
	if unix > 1_000_000_000_000 {
		return time.UnixMilli(unix).UTC()
	}
	return time.Unix(unix, 0).UTC()
}

func mapFromAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		return map[string]any{}
	}
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func coalesceString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func toInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

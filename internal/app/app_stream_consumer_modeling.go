package app

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func deriveTapActivityNodeKind(source, activityType string, data map[string]any) graph.NodeKind {
	source = strings.ToLower(strings.TrimSpace(source))
	activityType = strings.ToLower(strings.TrimSpace(activityType))

	if strings.Contains(activityType, "meeting") || source == "calendar" {
		return graph.NodeKindMeeting
	}
	if strings.Contains(activityType, "pull_request") || strings.HasPrefix(activityType, "pr_") {
		repository := strings.TrimSpace(anyToString(firstPresent(data, "repository", "repo", "metadata.repository")))
		number := strings.TrimSpace(anyToString(firstPresent(data, "number", "pr_number", "metadata.number")))
		if repository != "" && number != "" {
			return graph.NodeKindPullRequest
		}
	}
	if strings.Contains(activityType, "deploy") || strings.Contains(activityType, "release") {
		deployID := strings.TrimSpace(anyToString(firstPresent(data, "deploy_id", "deployment_id", "id", "metadata.deploy_id")))
		serviceID := strings.TrimSpace(anyToString(firstPresent(data, "service", "service_id", "metadata.service_id")))
		if deployID != "" && serviceID != "" {
			return graph.NodeKindDeploymentRun
		}
	}
	if strings.Contains(activityType, "document") || strings.Contains(activityType, "doc_") || strings.Contains(activityType, "wiki") || source == "docs" {
		return graph.NodeKindDocument
	}
	if strings.Contains(activityType, "thread") || source == "slack" {
		threadID := strings.TrimSpace(anyToString(firstPresent(data, "thread_id", "thread_ts", "metadata.thread_id", "metadata.thread_ts")))
		channelID := strings.TrimSpace(anyToString(firstPresent(data, "channel_id", "channel", "metadata.channel_id")))
		if threadID != "" && channelID != "" {
			return graph.NodeKindThread
		}
	}
	if strings.Contains(activityType, "incident") || source == "incident" {
		return graph.NodeKindIncident
	}
	if strings.Contains(activityType, "pr") && strings.TrimSpace(anyToString(firstPresent(data, "repository", "repo", "metadata.repository"))) != "" {
		return graph.NodeKindPullRequest
	}
	if (source == "ci" || source == "github") && strings.TrimSpace(anyToString(firstPresent(data, "service", "service_id", "metadata.service_id"))) != "" {
		if strings.Contains(activityType, "deploy") {
			return graph.NodeKindDeploymentRun
		}
	}
	if isKnownTapActivitySource(source) {
		return graph.NodeKindAction
	}
	return graph.NodeKindActivity
}

func isKnownTapActivitySource(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "github", "slack", "jira", "ci", "calendar", "docs", "incident", "support", "sales", "gong", "crm":
		return true
	default:
		return false
	}
}

func tapActivityNodePrefix(kind graph.NodeKind) string {
	switch kind {
	case graph.NodeKindThread:
		return "thread"
	default:
		return string(kind)
	}
}

func applyTapActivityKindProperties(properties map[string]any, kind graph.NodeKind, activityID, activityType, action, actorNodeID string, occurredAt time.Time, data map[string]any) {
	if properties == nil {
		return
	}
	observed := occurredAt.UTC().Format(time.RFC3339)
	switch kind {
	case graph.NodeKindMeeting:
		properties["meeting_id"] = firstNonEmpty(anyToString(firstPresent(data, "meeting_id", "id", "metadata.meeting_id")), activityID)
		properties["starts_at"] = firstNonEmpty(anyToString(firstPresent(data, "starts_at", "timestamp", "event_time", "occurred_at", "metadata.starts_at")), observed)
		properties["ends_at"] = firstNonEmpty(anyToString(firstPresent(data, "ends_at", "metadata.ends_at")), deriveTapActivityEndTime(data, occurredAt))
		properties["organizer_email"] = strings.TrimPrefix(actorNodeID, "person:")
	case graph.NodeKindPullRequest:
		repository := strings.TrimSpace(anyToString(firstPresent(data, "repository", "repo", "metadata.repository")))
		number := strings.TrimSpace(anyToString(firstPresent(data, "number", "pr_number", "metadata.number")))
		if repository == "" || number == "" {
			properties["action_type"] = activityType
			properties["status"] = inferTapActivityStatus(action, data)
			properties["performed_at"] = observed
			properties["actor_id"] = actorNodeID
			return
		}
		properties["repository"] = repository
		properties["number"] = number
		properties["state"] = inferTapActivityStatus(action, data)
	case graph.NodeKindDeploymentRun:
		deployID := strings.TrimSpace(anyToString(firstPresent(data, "deploy_id", "deployment_id", "id", "metadata.deploy_id")))
		serviceID := strings.TrimSpace(anyToString(firstPresent(data, "service", "service_id", "metadata.service_id")))
		if deployID == "" || serviceID == "" {
			properties["action_type"] = activityType
			properties["status"] = inferTapActivityStatus(action, data)
			properties["performed_at"] = observed
			properties["actor_id"] = actorNodeID
			return
		}
		properties["deploy_id"] = deployID
		properties["service_id"] = serviceID
		properties["environment"] = firstNonEmpty(anyToString(firstPresent(data, "environment", "env", "metadata.environment")), "unknown")
		properties["status"] = inferTapActivityStatus(action, data)
	case graph.NodeKindDocument:
		properties["document_id"] = firstNonEmpty(anyToString(firstPresent(data, "document_id", "doc_id", "id", "metadata.document_id")), activityID)
		properties["title"] = firstNonEmpty(anyToString(firstPresent(data, "title", "name", "subject")), action)
		if url := strings.TrimSpace(anyToString(firstPresent(data, "url", "metadata.url"))); url != "" {
			properties["url"] = url
		}
	case graph.NodeKindThread:
		threadID := strings.TrimSpace(anyToString(firstPresent(data, "thread_id", "thread_ts", "conversation_id", "metadata.thread_id", "metadata.thread_ts")))
		channelID := strings.TrimSpace(anyToString(firstPresent(data, "channel_id", "channel", "metadata.channel_id")))
		if threadID == "" || channelID == "" {
			properties["action_type"] = activityType
			properties["status"] = inferTapActivityStatus(action, data)
			properties["performed_at"] = observed
			properties["actor_id"] = actorNodeID
			return
		}
		properties["thread_id"] = threadID
		properties["channel_id"] = channelID
		if channelName := strings.TrimSpace(anyToString(firstPresent(data, "channel_name", "metadata.channel_name"))); channelName != "" {
			properties["channel_name"] = channelName
		}
	case graph.NodeKindIncident:
		properties["incident_id"] = firstNonEmpty(anyToString(firstPresent(data, "incident_id", "id", "metadata.incident_id")), activityID)
		properties["status"] = inferTapActivityStatus(action, data)
		if severity := strings.TrimSpace(anyToString(firstPresent(data, "severity", "metadata.severity"))); severity != "" {
			properties["severity"] = severity
		}
	case graph.NodeKindAction:
		properties["action_type"] = activityType
		properties["status"] = inferTapActivityStatus(action, data)
		properties["performed_at"] = observed
		properties["actor_id"] = actorNodeID
	default:
		properties["activity_type"] = activityType
		properties["timestamp"] = observed
	}
}

func deriveTapActivityEndTime(data map[string]any, start time.Time) string {
	if start.IsZero() {
		start = time.Now().UTC()
	}
	if seconds := toFloat64(firstPresent(data, "duration_seconds", "duration_sec", "metadata.duration_seconds")); seconds > 0 {
		return start.Add(time.Duration(seconds * float64(time.Second))).UTC().Format(time.RFC3339)
	}
	if minutes := toFloat64(firstPresent(data, "duration_minutes", "metadata.duration_minutes")); minutes > 0 {
		return start.Add(time.Duration(minutes * float64(time.Minute))).UTC().Format(time.RFC3339)
	}
	return start.UTC().Format(time.RFC3339)
}

func inferTapActivityStatus(action string, data map[string]any) string {
	if explicit := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(data, "status", "state", "metadata.status", "metadata.state")))); explicit != "" {
		return explicit
	}
	action = strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(action, "open"), strings.Contains(action, "create"), strings.Contains(action, "start"), strings.Contains(action, "queued"):
		return "open"
	case strings.Contains(action, "close"), strings.Contains(action, "resolve"), strings.Contains(action, "merge"), strings.Contains(action, "complete"), strings.Contains(action, "done"):
		return "completed"
	case strings.Contains(action, "fail"), strings.Contains(action, "error"), strings.Contains(action, "cancel"):
		return "failed"
	default:
		return "updated"
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

func toFloat64(value any) float64 {
	switch typed := value.(type) {
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

package app

import (
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

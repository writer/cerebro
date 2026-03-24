package graph

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// LegacyActivityMigrationOptions controls legacy activity migration behavior.
type LegacyActivityMigrationOptions struct {
	Now time.Time `json:"now,omitempty"`
}

// LegacyActivityMigrationResult summarizes one migration run.
type LegacyActivityMigrationResult struct {
	Scanned         int            `json:"scanned"`
	Migrated        int            `json:"migrated"`
	MarkedForReview int            `json:"marked_for_review"`
	MigratedByKind  map[string]int `json:"migrated_by_kind,omitempty"`
	ReviewNodeIDs   []string       `json:"review_node_ids,omitempty"`
}

// MigrateLegacyActivityNodes rewrites legacy NodeKindActivity nodes into canonical kinds.
//
// Nodes are rewritten in place (same node ID) so existing edges remain connected.
// When classification is uncertain, nodes are migrated to NodeKindAction and marked
// for reviewer follow-up.
func MigrateLegacyActivityNodes(g *Graph, opts LegacyActivityMigrationOptions) LegacyActivityMigrationResult {
	result := LegacyActivityMigrationResult{
		MigratedByKind: make(map[string]int),
	}
	if g == nil {
		return result
	}

	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	nodes := g.GetNodesByKind(NodeKindActivity)
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i] == nil {
			return false
		}
		if nodes[j] == nil {
			return true
		}
		return nodes[i].ID < nodes[j].ID
	})

	for _, node := range nodes {
		if node == nil {
			continue
		}
		result.Scanned++

		migrated, reviewRequired := buildMigratedActivityNode(g, node, now)
		if migrated == nil {
			continue
		}

		g.AddNode(migrated)
		result.Migrated++
		result.MigratedByKind[string(migrated.Kind)]++
		if reviewRequired {
			result.MarkedForReview++
			result.ReviewNodeIDs = append(result.ReviewNodeIDs, migrated.ID)
		}
	}

	if len(result.ReviewNodeIDs) > 0 {
		sort.Strings(result.ReviewNodeIDs)
	}
	if len(result.MigratedByKind) == 0 {
		result.MigratedByKind = nil
	}
	return result
}

func buildMigratedActivityNode(g *Graph, node *Node, now time.Time) (*Node, bool) {
	if node == nil || node.Kind != NodeKindActivity {
		return nil, false
	}

	properties := cloneAnyMap(node.Properties)
	metadata := migrationMapFromAny(properties["metadata"])
	activityType := strings.ToLower(strings.TrimSpace(migrationFirstNonEmpty(
		identityAnyToString(properties["activity_type"]),
		identityAnyToString(properties["action"]),
		identityAnyToString(properties["legacy_activity_type"]),
		extractActivityTypeFromID(node.ID),
	)))
	action := strings.ToLower(strings.TrimSpace(migrationFirstNonEmpty(
		identityAnyToString(properties["action"]),
		activityType,
	)))
	if action == "" {
		action = "activity"
	}

	observedAt := now
	if ts, ok := temporalPropertyTime(properties, "observed_at"); ok {
		observedAt = ts.UTC()
	} else if ts, ok := temporalPropertyTime(properties, "timestamp"); ok {
		observedAt = ts.UTC()
	} else if !node.UpdatedAt.IsZero() {
		observedAt = node.UpdatedAt.UTC()
	}

	validFrom := observedAt
	if ts, ok := temporalPropertyTime(properties, "valid_from"); ok {
		validFrom = ts.UTC()
	}
	confidence := clampUnit(migrationReadFloat(properties, 0.8, "confidence"))
	if confidence <= 0 {
		confidence = 0.8
	}

	sourceSystem := strings.ToLower(strings.TrimSpace(migrationFirstNonEmpty(
		identityAnyToString(properties["source_system"]),
		node.Provider,
	)))
	sourceEventID := strings.TrimSpace(migrationFirstNonEmpty(
		identityAnyToString(properties["source_event_id"]),
		node.ID,
	))
	writeMeta := NormalizeWriteMetadata(observedAt, validFrom, nil, sourceSystem, sourceEventID, confidence, WriteMetadataDefaults{
		Now:               now,
		SourceSystem:      sourceSystem,
		SourceEventID:     sourceEventID,
		SourceEventPrefix: "legacy_activity_migration",
		DefaultConfidence: 0.8,
	})

	kind, reviewRequired := classifyLegacyActivityKind(g, node, activityType, metadata)
	applyMigratedKindProperties(g, properties, metadata, kind, node.ID, activityType, action, observedAt)
	writeMeta.ApplyTo(properties)
	properties["migration_from_kind"] = string(NodeKindActivity)
	properties["migration_migrated_at"] = now.UTC().Format(time.RFC3339)
	if reviewRequired {
		properties["migration_needs_review"] = true
		properties["migration_review_status"] = "uncertain"
		properties["migration_review_reason"] = "insufficient legacy activity semantics for deterministic canonical mapping"
	} else {
		properties["migration_review_status"] = "mapped"
	}

	return &Node{
		ID:                 node.ID,
		Kind:               kind,
		Name:               node.Name,
		Provider:           node.Provider,
		Account:            node.Account,
		Region:             node.Region,
		Properties:         properties,
		Tags:               cloneStringMap(node.Tags),
		Risk:               node.Risk,
		Findings:           append([]string(nil), node.Findings...),
		CreatedAt:          node.CreatedAt,
		UpdatedAt:          now.UTC(),
		Version:            node.Version,
		PreviousProperties: cloneAnyMap(node.PreviousProperties),
		PropertyHistory:    clonePropertyHistoryMap(node.PropertyHistory),
	}, reviewRequired
}

func classifyLegacyActivityKind(g *Graph, node *Node, activityType string, metadata map[string]any) (NodeKind, bool) {
	lowerType := strings.ToLower(strings.TrimSpace(activityType))
	if lowerType == "" {
		return NodeKindAction, true
	}

	if strings.Contains(lowerType, "meeting") || strings.Contains(lowerType, "calendar") {
		return NodeKindMeeting, false
	}
	if strings.Contains(lowerType, "incident") {
		return NodeKindIncident, false
	}
	if strings.Contains(lowerType, "document") || strings.Contains(lowerType, "doc_") || strings.Contains(lowerType, "wiki") {
		return NodeKindDocument, false
	}
	if strings.Contains(lowerType, "thread") || strings.Contains(lowerType, "message") {
		if strings.TrimSpace(migrationFirstNonEmpty(identityAnyToString(metadata["thread_id"]), identityAnyToString(metadata["thread_ts"]))) != "" {
			return NodeKindThread, false
		}
	}
	if strings.Contains(lowerType, "pull_request") || strings.HasPrefix(lowerType, "pr_") {
		if repository := strings.TrimSpace(migrationFirstNonEmpty(identityAnyToString(metadata["repository"]), identityAnyToString(metadata["repo"]))); repository != "" {
			if number := strings.TrimSpace(migrationFirstNonEmpty(identityAnyToString(metadata["number"]), identityAnyToString(metadata["pr_number"]))); number != "" {
				return NodeKindPullRequest, false
			}
		}
	}
	if strings.Contains(lowerType, "deploy") || strings.Contains(lowerType, "release") {
		serviceID := strings.TrimSpace(migrationFirstNonEmpty(identityAnyToString(metadata["service_id"]), identityAnyToString(metadata["service"])))
		if serviceID == "" {
			serviceID = inferServiceIDFromActivityEdges(g, node)
		}
		if serviceID != "" {
			return NodeKindDeploymentRun, false
		}
	}
	return NodeKindAction, true
}

func applyMigratedKindProperties(g *Graph, properties map[string]any, metadata map[string]any, kind NodeKind, nodeID, activityType, action string, observedAt time.Time) {
	observed := observedAt.UTC().Format(time.RFC3339)
	switch kind {
	case NodeKindMeeting:
		properties["meeting_id"] = migrationFirstNonEmpty(identityAnyToString(properties["meeting_id"]), identityAnyToString(metadata["meeting_id"]), nodeID)
		properties["starts_at"] = migrationFirstNonEmpty(identityAnyToString(properties["starts_at"]), identityAnyToString(properties["timestamp"]), observed)
		properties["ends_at"] = migrationFirstNonEmpty(identityAnyToString(properties["ends_at"]), inferLegacyActivityEndTime(properties, metadata, observedAt))
	case NodeKindIncident:
		properties["incident_id"] = migrationFirstNonEmpty(identityAnyToString(properties["incident_id"]), identityAnyToString(metadata["incident_id"]), nodeID)
		properties["status"] = migrationFirstNonEmpty(identityAnyToString(properties["status"]), inferLegacyActivityStatus(action), "updated")
	case NodeKindDocument:
		properties["document_id"] = migrationFirstNonEmpty(identityAnyToString(properties["document_id"]), identityAnyToString(metadata["document_id"]), nodeID)
		properties["title"] = migrationFirstNonEmpty(identityAnyToString(properties["title"]), nodeID)
		if url := strings.TrimSpace(migrationFirstNonEmpty(identityAnyToString(properties["url"]), identityAnyToString(metadata["url"]))); url != "" {
			properties["url"] = url
		}
	case NodeKindThread:
		properties["thread_id"] = migrationFirstNonEmpty(identityAnyToString(properties["thread_id"]), identityAnyToString(metadata["thread_id"]), identityAnyToString(metadata["thread_ts"]), nodeID)
		properties["channel_id"] = migrationFirstNonEmpty(identityAnyToString(properties["channel_id"]), identityAnyToString(metadata["channel_id"]), "unknown")
		if name := strings.TrimSpace(identityAnyToString(metadata["channel_name"])); name != "" {
			properties["channel_name"] = name
		}
	case NodeKindPullRequest:
		properties["repository"] = migrationFirstNonEmpty(identityAnyToString(properties["repository"]), identityAnyToString(metadata["repository"]), identityAnyToString(metadata["repo"]))
		properties["number"] = migrationFirstNonEmpty(identityAnyToString(properties["number"]), identityAnyToString(metadata["number"]), identityAnyToString(metadata["pr_number"]))
		properties["state"] = migrationFirstNonEmpty(identityAnyToString(properties["state"]), inferLegacyActivityStatus(action), "updated")
	case NodeKindDeploymentRun:
		properties["deploy_id"] = migrationFirstNonEmpty(identityAnyToString(properties["deploy_id"]), identityAnyToString(metadata["deploy_id"]), nodeID)
		serviceID := migrationFirstNonEmpty(identityAnyToString(properties["service_id"]), identityAnyToString(metadata["service_id"]), identityAnyToString(metadata["service"]))
		if serviceID == "" {
			serviceID = inferServiceIDFromActivityEdges(g, &Node{ID: nodeID})
		}
		properties["service_id"] = migrationFirstNonEmpty(serviceID, "unknown")
		properties["environment"] = migrationFirstNonEmpty(identityAnyToString(properties["environment"]), identityAnyToString(metadata["environment"]), "unknown")
		properties["status"] = migrationFirstNonEmpty(identityAnyToString(properties["status"]), inferLegacyActivityStatus(action), "updated")
	default:
		properties["action_type"] = migrationFirstNonEmpty(identityAnyToString(properties["action_type"]), activityType, "activity")
		properties["status"] = migrationFirstNonEmpty(identityAnyToString(properties["status"]), inferLegacyActivityStatus(action), "updated")
		properties["performed_at"] = migrationFirstNonEmpty(identityAnyToString(properties["performed_at"]), identityAnyToString(properties["timestamp"]), observed)
	}
}

func inferLegacyActivityEndTime(properties map[string]any, metadata map[string]any, observedAt time.Time) string {
	if seconds := migrationReadFloat(properties, 0, "duration_seconds"); seconds > 0 {
		return observedAt.Add(time.Duration(seconds * float64(time.Second))).UTC().Format(time.RFC3339)
	}
	if minutes := migrationReadFloat(properties, 0, "duration_minutes"); minutes > 0 {
		return observedAt.Add(time.Duration(minutes * float64(time.Minute))).UTC().Format(time.RFC3339)
	}
	if seconds := migrationReadFloat(metadata, 0, "duration_seconds"); seconds > 0 {
		return observedAt.Add(time.Duration(seconds * float64(time.Second))).UTC().Format(time.RFC3339)
	}
	if minutes := migrationReadFloat(metadata, 0, "duration_minutes"); minutes > 0 {
		return observedAt.Add(time.Duration(minutes * float64(time.Minute))).UTC().Format(time.RFC3339)
	}
	return observedAt.UTC().Format(time.RFC3339)
}

func inferLegacyActivityStatus(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(action, "open"), strings.Contains(action, "start"), strings.Contains(action, "create"):
		return "open"
	case strings.Contains(action, "close"), strings.Contains(action, "resolve"), strings.Contains(action, "merge"), strings.Contains(action, "complete"), strings.Contains(action, "done"):
		return "completed"
	case strings.Contains(action, "fail"), strings.Contains(action, "error"), strings.Contains(action, "cancel"):
		return "failed"
	default:
		return "updated"
	}
}

func extractActivityTypeFromID(nodeID string) string {
	parts := strings.Split(strings.TrimSpace(nodeID), ":")
	if len(parts) >= 3 && strings.EqualFold(parts[0], "activity") {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func inferServiceIDFromActivityEdges(g *Graph, node *Node) string {
	if g == nil || node == nil {
		return ""
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil {
			continue
		}
		if edge.Kind != EdgeKindTargets && edge.Kind != EdgeKindInteractedWith {
			continue
		}
		targetNode, ok := g.GetNode(edge.Target)
		if !ok || targetNode == nil {
			continue
		}
		if targetNode.Kind == NodeKindService {
			return strings.TrimSpace(migrationFirstNonEmpty(
				targetNode.PropertyString("service_id"),
				strings.TrimPrefix(targetNode.ID, "service:"),
			))
		}
	}
	return ""
}

func migrationReadFloat(values map[string]any, fallback float64, keys ...string) float64 {
	for _, key := range keys {
		value := values[key]
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
	}
	return fallback
}

func migrationFirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func migrationMapFromAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAnyMap(typed)
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	default:
		return map[string]any{}
	}
}

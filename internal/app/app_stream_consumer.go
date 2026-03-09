package app

import (
	"context"
	"fmt"
	"math"
	"sort"
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
	eventType := strings.TrimSpace(evt.Type)
	if eventType == "" {
		eventType = strings.TrimSpace(evt.Subject)
	}
	if !strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap.") {
		return nil
	}
	if isTapSchemaEventType(eventType) {
		return a.handleTapSchemaEvent(eventType, evt)
	}
	if isTapInteractionType(eventType) {
		return a.handleTapInteractionEvent(eventType, evt)
	}

	system, entityType, action := parseTapType(eventType)
	if system == "" {
		return nil
	}
	if isTapActivityType(eventType) {
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
		"event_type":    eventType,
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

type tapSchemaEntityDefinition struct {
	Kind          string
	Categories    []graph.NodeKindCategory
	Properties    map[string]string
	Relationships []graph.EdgeKind
	Description   string
}

func isTapSchemaEventType(eventType string) bool {
	lower := strings.ToLower(strings.TrimSpace(eventType))
	switch {
	case strings.HasPrefix(lower, "ensemble.tap.schema."),
		strings.HasPrefix(lower, "ensemble.tap.integration.schema."),
		strings.Contains(lower, ".schema.updated"),
		strings.Contains(lower, ".schema.created"),
		strings.Contains(lower, ".schema.connected"):
		return true
	default:
		return false
	}
}

func (a *App) handleTapSchemaEvent(eventType string, evt events.CloudEvent) error {
	integration := parseTapSchemaIntegration(eventType, evt.Data)
	entities := parseTapSchemaEntities(evt.Data)
	if len(entities) == 0 {
		return nil
	}

	registeredNodeKinds := 0
	edgeKinds := make(map[graph.EdgeKind]struct{})
	for _, edgeKind := range parseTapSchemaRelationships(firstPresent(evt.Data, "edge_types", "relationship_types")) {
		edgeKinds[edgeKind] = struct{}{}
	}

	for _, entity := range entities {
		definition := graph.NodeKindDefinition{
			Kind:          graph.NodeKind(entity.Kind),
			Categories:    entity.Categories,
			Properties:    entity.Properties,
			Relationships: entity.Relationships,
			Description:   entity.Description,
		}
		if _, err := graph.RegisterNodeKindDefinition(definition); err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to register tap schema node kind",
					"integration", integration,
					"kind", entity.Kind,
					"error", err,
				)
			}
			continue
		}
		registeredNodeKinds++
		for _, relationship := range entity.Relationships {
			edgeKinds[relationship] = struct{}{}
		}
	}

	registeredEdgeKinds := 0
	for edgeKind := range edgeKinds {
		if _, err := graph.RegisterEdgeKindDefinition(graph.EdgeKindDefinition{Kind: edgeKind}); err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to register tap schema edge kind",
					"integration", integration,
					"kind", edgeKind,
					"error", err,
				)
			}
			continue
		}
		registeredEdgeKinds++
	}

	if a.Logger != nil {
		a.Logger.Info("registered tap integration schema",
			"integration", integration,
			"node_kinds", registeredNodeKinds,
			"edge_kinds", registeredEdgeKinds,
		)
	}
	return nil
}

func parseTapSchemaIntegration(eventType string, data map[string]any) string {
	integration := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(data, "integration", "source_system", "system", "provider", "integration_name"))))
	if integration != "" {
		return integration
	}

	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) >= 5 {
		// ensemble.tap.schema.<integration>.<action>
		if strings.EqualFold(parts[2], "schema") {
			return strings.ToLower(strings.TrimSpace(parts[3]))
		}
		// ensemble.tap.<integration>.schema.<action>
		if strings.EqualFold(parts[3], "schema") {
			return strings.ToLower(strings.TrimSpace(parts[2]))
		}
	}
	return ""
}

func parseTapSchemaEntities(data map[string]any) []tapSchemaEntityDefinition {
	raw := firstPresent(data, "entity_types", "entities", "node_kinds")
	items := make([]any, 0)
	switch typed := raw.(type) {
	case []any:
		items = append(items, typed...)
	case []map[string]any:
		for _, item := range typed {
			items = append(items, item)
		}
	}

	out := make([]tapSchemaEntityDefinition, 0, len(items))
	for _, item := range items {
		entity := mapFromAny(item)
		if len(entity) == 0 {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(entity, "kind", "entity_type", "type", "name"))))
		if kind == "" {
			continue
		}

		definition := tapSchemaEntityDefinition{
			Kind:          kind,
			Categories:    parseTapSchemaCategories(firstPresent(entity, "categories", "category"), kind),
			Properties:    parseTapSchemaProperties(firstPresent(entity, "properties", "fields", "schema")),
			Relationships: parseTapSchemaRelationships(firstPresent(entity, "relationships", "edges", "relation_types")),
			Description:   strings.TrimSpace(anyToString(firstPresent(entity, "description", "summary"))),
		}
		out = append(out, definition)
	}
	return out
}

func parseTapSchemaCategories(raw any, kind string) []graph.NodeKindCategory {
	values := make([]graph.NodeKindCategory, 0)
	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			category := strings.ToLower(strings.TrimSpace(part))
			if category != "" {
				values = append(values, graph.NodeKindCategory(category))
			}
		}
	case []any:
		for _, item := range typed {
			category := strings.ToLower(strings.TrimSpace(anyToString(item)))
			if category != "" {
				values = append(values, graph.NodeKindCategory(category))
			}
		}
	}
	if len(values) == 0 {
		return inferTapSchemaCategories(kind)
	}

	unique := make(map[graph.NodeKindCategory]struct{}, len(values))
	for _, category := range values {
		switch category {
		case graph.NodeCategoryIdentity, graph.NodeCategoryResource, graph.NodeCategoryBusiness, graph.NodeCategoryKubernetes:
			unique[category] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return inferTapSchemaCategories(kind)
	}

	out := make([]graph.NodeKindCategory, 0, len(unique))
	for category := range unique {
		out = append(out, category)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func inferTapSchemaCategories(kind string) []graph.NodeKindCategory {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch {
	case strings.Contains(kind, "user"),
		strings.Contains(kind, "person"),
		strings.Contains(kind, "employee"),
		strings.Contains(kind, "contact"),
		strings.Contains(kind, "member"),
		strings.Contains(kind, "identity"):
		return []graph.NodeKindCategory{graph.NodeCategoryIdentity, graph.NodeCategoryBusiness}
	case strings.Contains(kind, "pod"),
		strings.Contains(kind, "cluster"),
		strings.Contains(kind, "namespace"),
		strings.Contains(kind, "k8s"):
		return []graph.NodeKindCategory{graph.NodeCategoryResource, graph.NodeCategoryKubernetes}
	case strings.Contains(kind, "bucket"),
		strings.Contains(kind, "database"),
		strings.Contains(kind, "instance"),
		strings.Contains(kind, "secret"),
		strings.Contains(kind, "function"),
		strings.Contains(kind, "application"),
		strings.Contains(kind, "service"):
		return []graph.NodeKindCategory{graph.NodeCategoryResource}
	default:
		return []graph.NodeKindCategory{graph.NodeCategoryBusiness}
	}
}

func parseTapSchemaProperties(raw any) map[string]string {
	properties := make(map[string]string)
	for key, value := range mapFromAny(raw) {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}

		valueType := strings.TrimSpace(anyToString(value))
		if nested := mapFromAny(value); len(nested) > 0 {
			valueType = strings.TrimSpace(anyToString(firstPresent(nested, "type", "kind", "data_type")))
		}
		if valueType == "" {
			valueType = "any"
		}
		properties[trimmedKey] = strings.ToLower(valueType)
	}
	return properties
}

func parseTapSchemaRelationships(raw any) []graph.EdgeKind {
	values := make([]graph.EdgeKind, 0)
	switch typed := raw.(type) {
	case []any:
		for _, item := range typed {
			switch relationship := item.(type) {
			case string:
				kind := strings.ToLower(strings.TrimSpace(relationship))
				if kind != "" {
					values = append(values, graph.EdgeKind(kind))
				}
			case map[string]any:
				kind := strings.ToLower(strings.TrimSpace(anyToString(firstPresent(relationship, "kind", "type", "edge_kind", "relationship"))))
				if kind != "" {
					values = append(values, graph.EdgeKind(kind))
				}
			}
		}
	case []string:
		for _, item := range typed {
			kind := strings.ToLower(strings.TrimSpace(item))
			if kind != "" {
				values = append(values, graph.EdgeKind(kind))
			}
		}
	}

	if len(values) == 0 {
		return nil
	}
	unique := make(map[graph.EdgeKind]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	out := make([]graph.EdgeKind, 0, len(unique))
	for value := range unique {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func isTapActivityType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.activity.")
}

func isTapInteractionType(eventType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(eventType)), "ensemble.tap.interaction.")
}

type tapInteractionParticipant struct {
	ID   string
	Name string
}

func (a *App) handleTapInteractionEvent(eventType string, evt events.CloudEvent) error {
	channel, interactionType := parseTapInteractionType(eventType)
	if channel == "" {
		return nil
	}

	interactionType = coalesceString(
		interactionType,
		strings.ToLower(strings.TrimSpace(anyToString(firstPresent(evt.Data, "interaction_type", "type", "action", "snapshot.interaction_type", "snapshot.type", "snapshot.action")))),
		"interaction",
	)

	occurredAt := evt.Time.UTC()
	if ts, ok := parseTimeValue(firstPresent(evt.Data, "timestamp", "event_time", "occurred_at", "provider_timestamp", "snapshot.timestamp", "snapshot.event_time", "snapshot.occurred_at", "snapshot.provider_timestamp")); ok {
		occurredAt = ts.UTC()
	}

	duration := parseTapInteractionDuration(evt.Data)
	weight := parseTapInteractionWeight(evt.Data, duration)
	participants := parseTapInteractionParticipants(evt.Data)
	if len(participants) < 2 {
		return nil
	}

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
	}

	for _, participant := range participants {
		a.upsertTapInteractionPersonNode(participant, channel, occurredAt)
	}

	for i := 0; i < len(participants); i++ {
		for j := i + 1; j < len(participants); j++ {
			graph.UpsertInteractionEdge(a.SecurityGraph, graph.InteractionEdge{
				SourcePersonID: participants[i].ID,
				TargetPersonID: participants[j].ID,
				Channel:        channel,
				Type:           interactionType,
				Timestamp:      occurredAt,
				Duration:       duration,
				Weight:         weight,
			})
		}
	}

	return nil
}

func parseTapInteractionType(eventType string) (channel string, interactionType string) {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) < 4 || !strings.EqualFold(parts[2], "interaction") {
		return "", ""
	}
	channel = strings.ToLower(strings.TrimSpace(parts[3]))
	if len(parts) > 4 {
		interactionType = strings.ToLower(strings.Join(parts[4:], "_"))
	}
	return channel, interactionType
}

func parseTapInteractionParticipants(data map[string]any) []tapInteractionParticipant {
	participants := make([]tapInteractionParticipant, 0)
	seen := make(map[string]struct{})

	addParticipant := func(raw any) {
		participant, ok := parseTapInteractionParticipant(raw)
		if !ok {
			return
		}
		participant.ID = normalizeTapInteractionPersonID(participant.ID)
		if participant.ID == "" {
			return
		}
		if _, ok := seen[participant.ID]; ok {
			return
		}
		if strings.TrimSpace(participant.Name) == "" {
			participant.Name = strings.TrimPrefix(participant.ID, "person:")
		}
		participants = append(participants, participant)
		seen[participant.ID] = struct{}{}
	}

	addMany := func(raw any) {
		switch typed := raw.(type) {
		case []any:
			for _, value := range typed {
				addParticipant(value)
			}
		case []string:
			for _, value := range typed {
				addParticipant(value)
			}
		default:
			addParticipant(raw)
		}
	}

	addParticipant(firstPresent(data,
		"source_person_id", "source_person_email", "source_id", "source_email",
		"actor_id", "actor_email", "user_id", "user_email",
		"snapshot.source_person_id", "snapshot.source_person_email", "snapshot.source_id", "snapshot.source_email",
		"snapshot.actor_id", "snapshot.actor_email", "snapshot.user_id", "snapshot.user_email",
	))
	addParticipant(firstPresent(data,
		"target_person_id", "target_person_email", "target_id", "target_email",
		"counterparty_id", "counterparty_email", "peer_id", "peer_email",
		"reviewed_id", "reviewed_email",
		"snapshot.target_person_id", "snapshot.target_person_email", "snapshot.target_id", "snapshot.target_email",
		"snapshot.counterparty_id", "snapshot.counterparty_email", "snapshot.peer_id", "snapshot.peer_email",
	))
	addParticipant(firstPresent(data, "actor", "source", "target", "user", "snapshot.actor", "snapshot.source", "snapshot.target", "snapshot.user"))

	for _, key := range []string{
		"participants", "participant_ids", "participant_emails", "people", "users", "members", "attendees", "reviewers", "assignees", "collaborators",
		"snapshot.participants", "snapshot.participant_ids", "snapshot.participant_emails",
		"snapshot.people", "snapshot.users", "snapshot.members", "snapshot.attendees", "snapshot.reviewers", "snapshot.assignees", "snapshot.collaborators",
		"interaction.participants", "interaction.users", "snapshot.interaction.participants", "snapshot.interaction.users",
	} {
		addMany(firstPresent(data, key))
	}

	return participants
}

func parseTapInteractionParticipant(raw any) (tapInteractionParticipant, bool) {
	switch typed := raw.(type) {
	case string:
		id := strings.TrimSpace(typed)
		if id == "" {
			return tapInteractionParticipant{}, false
		}
		return tapInteractionParticipant{ID: id}, true
	case map[string]any:
		id := strings.TrimSpace(anyToString(firstPresent(typed,
			"person_id", "person", "id", "user_id", "user", "email",
			"actor_id", "actor_email", "source_person_id", "target_person_id",
		)))
		if id == "" {
			if person, ok := typed["person"].(map[string]any); ok {
				return parseTapInteractionParticipant(person)
			}
			return tapInteractionParticipant{}, false
		}
		name := strings.TrimSpace(anyToString(firstPresent(typed, "name", "display_name", "full_name", "username")))
		return tapInteractionParticipant{ID: id, Name: name}, true
	default:
		return tapInteractionParticipant{}, false
	}
}

func normalizeTapInteractionPersonID(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "person:") {
		return normalized
	}
	normalized = strings.TrimPrefix(normalized, "user:")
	if strings.Contains(normalized, ":") {
		return normalized
	}
	return "person:" + normalized
}

func parseTapInteractionDuration(data map[string]any) time.Duration {
	if seconds := toFloat64(firstPresent(data, "duration_seconds", "duration_sec", "duration_s", "metadata.duration_seconds", "snapshot.duration_seconds", "snapshot.metadata.duration_seconds")); seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	if minutes := toFloat64(firstPresent(data, "duration_minutes", "metadata.duration_minutes", "snapshot.duration_minutes", "snapshot.metadata.duration_minutes")); minutes > 0 {
		return time.Duration(minutes * float64(time.Minute))
	}
	if millis := toFloat64(firstPresent(data, "duration_ms", "metadata.duration_ms", "snapshot.duration_ms", "snapshot.metadata.duration_ms")); millis > 0 {
		return time.Duration(millis * float64(time.Millisecond))
	}

	rawDuration := strings.TrimSpace(anyToString(firstPresent(data, "duration", "metadata.duration", "snapshot.duration", "snapshot.metadata.duration")))
	if rawDuration == "" {
		return 0
	}
	if parsed, err := time.ParseDuration(rawDuration); err == nil && parsed > 0 {
		return parsed
	}
	if seconds, err := strconv.ParseFloat(rawDuration, 64); err == nil && seconds > 0 {
		return time.Duration(seconds * float64(time.Second))
	}
	return 0
}

func parseTapInteractionWeight(data map[string]any, duration time.Duration) float64 {
	if explicit := toFloat64(firstPresent(data, "weight", "interaction_weight", "score", "metadata.weight", "snapshot.weight", "snapshot.metadata.weight")); explicit > 0 {
		return explicit
	}
	if duration <= 0 {
		return 1
	}
	weight := 1 + math.Log1p(duration.Minutes()/30.0)
	if weight < 1 {
		return 1
	}
	return weight
}

func (a *App) upsertTapInteractionPersonNode(participant tapInteractionParticipant, channel string, occurredAt time.Time) {
	if a.SecurityGraph == nil {
		return
	}
	personID := normalizeTapInteractionPersonID(participant.ID)
	if personID == "" {
		return
	}

	properties := make(map[string]any)
	nodeKind := graph.NodeKindPerson
	nodeName := strings.TrimSpace(participant.Name)
	provider := strings.ToLower(strings.TrimSpace(channel))

	if existing, ok := a.SecurityGraph.GetNode(personID); ok && existing != nil {
		for key, value := range mapFromAny(existing.Properties) {
			properties[key] = value
		}
		if existing.Kind != "" {
			nodeKind = existing.Kind
		}
		if nodeKind == graph.NodeKindUser {
			nodeKind = graph.NodeKindPerson
		}
		if strings.TrimSpace(nodeName) == "" {
			nodeName = strings.TrimSpace(existing.Name)
		}
		if provider == "" {
			provider = strings.TrimSpace(existing.Provider)
		}
	}

	if strings.TrimSpace(nodeName) == "" {
		nodeName = strings.TrimPrefix(personID, "person:")
	}
	if !strings.Contains(nodeName, "@") {
		nodeName = strings.TrimSpace(nodeName)
	}

	email := strings.TrimPrefix(personID, "person:")
	if strings.Contains(email, "@") && strings.TrimSpace(anyToString(properties["email"])) == "" {
		properties["email"] = email
	}

	sources := make(map[string]struct{})
	for _, source := range stringSliceFromAny(properties["source_systems"]) {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			continue
		}
		sources[source] = struct{}{}
	}
	if provider != "" {
		sources[provider] = struct{}{}
		properties["source_system"] = provider
	}
	if len(sources) > 0 {
		properties["source_systems"] = sortedStringSet(sources)
	}
	if !occurredAt.IsZero() {
		properties["last_seen"] = occurredAt.UTC().Format(time.RFC3339)
	}

	a.SecurityGraph.AddNode(&graph.Node{
		ID:         personID,
		Kind:       nodeKind,
		Name:       nodeName,
		Provider:   provider,
		Properties: properties,
		Risk:       graph.RiskNone,
	})
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(anyToString(item))
			if text == "" {
				continue
			}
			values = append(values, text)
		}
		return values
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	default:
		return nil
	}
}

func sortedStringSet(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

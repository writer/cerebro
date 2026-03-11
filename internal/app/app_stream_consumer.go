package app

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graphingest"
	"github.com/writer/cerebro/internal/health"
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
		InProgressInterval:    a.Config.NATSConsumerInProgressInterval,
		DeadLetterPath:        a.Config.NATSConsumerDeadLetterPath,
		DropHealthLookback:    a.Config.NATSConsumerDropHealthLookback,
		DropHealthThreshold:   a.Config.NATSConsumerDropHealthThreshold,
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
	if a.Health != nil {
		a.Health.Register("tap_consumer", func(_ context.Context) health.CheckResult {
			start := time.Now().UTC()
			snapshot := consumer.HealthSnapshot(start)
			status := health.StatusHealthy
			message := "consumer healthy"
			graphStaleness := snapshot.GraphStaleness
			if graphStaleness == 0 {
				buildSnapshot := a.GraphBuildSnapshot()
				if !buildSnapshot.LastBuildAt.IsZero() {
					graphStaleness = time.Since(buildSnapshot.LastBuildAt.UTC())
				}
			}
			if snapshot.Threshold > 0 && snapshot.RecentDropped >= snapshot.Threshold {
				status = health.StatusUnhealthy
				message = fmt.Sprintf("consumer dropped %d malformed events in last %s (threshold %d); last_reason=%s",
					snapshot.RecentDropped,
					snapshot.Lookback.String(),
					snapshot.Threshold,
					snapshot.LastDropReason,
				)
			} else if threshold := a.Config.NATSConsumerGraphStalenessThreshold; threshold > 0 && graphStaleness > threshold {
				status = health.StatusUnhealthy
				message = fmt.Sprintf("graph staleness %s exceeds threshold %s", graphStaleness.Round(time.Second), threshold)
			} else if snapshot.ConsumerLag > 0 {
				message = fmt.Sprintf("consumer healthy; lag=%d lag_seconds=%s", snapshot.ConsumerLag, snapshot.ConsumerLagAge.Round(time.Second))
			}
			return health.CheckResult{
				Name:      "tap_consumer",
				Status:    status,
				Message:   message,
				Timestamp: start,
				Latency:   time.Since(start),
			}
		})
	}
	a.Logger.Info("tap graph consumer enabled",
		"stream", a.Config.NATSConsumerStream,
		"subject", subject,
		"durable", a.Config.NATSConsumerDurable,
		"batch_size", a.Config.NATSConsumerBatchSize,
	)

	_ = ctx
}

func (a *App) ensureSecurityGraph() *graph.Graph {
	if a == nil {
		return nil
	}

	a.securityGraphInitMu.Lock()
	defer a.securityGraphInitMu.Unlock()

	if a.SecurityGraph == nil {
		a.SecurityGraph = graph.New()
		a.configureGraphSchemaValidation(a.SecurityGraph)
	}
	return a.SecurityGraph
}

func (a *App) waitForSecurityGraphReady(ctx context.Context) error {
	if a == nil || a.graphReady == nil {
		return nil
	}
	select {
	case <-a.graphReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) handleTapCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	eventType := strings.TrimSpace(evt.Type)
	if eventType == "" {
		eventType = strings.TrimSpace(evt.Subject)
	}
	if !strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap.") {
		return nil
	}
	if err := a.waitForSecurityGraphReady(ctx); err != nil {
		return err
	}
	if isTapSchemaEventType(eventType) {
		return a.handleTapSchemaEvent(eventType, evt)
	}
	if isTapInteractionType(eventType) {
		return a.handleTapInteractionEvent(eventType, evt)
	}
	if mapped, err := a.applyTapDeclarativeMappings(evt); err != nil {
		return err
	} else if mapped {
		return nil
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
	securityGraph := a.ensureSecurityGraph()
	existingProperties := map[string]any{}
	if existingNode, ok := securityGraph.GetNode(nodeID); ok && existingNode != nil && existingNode.Properties != nil {
		existingProperties = existingNode.Properties
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

	securityGraph.AddNode(node)

	// Link foreign-key relationships from snapshot data.
	edges := extractBusinessEdges(system, entityType, nodeID, snapshot)
	for _, e := range edges {
		if _, ok := securityGraph.GetNode(e.Target); !ok {
			targetParts := strings.SplitN(e.Target, ":", 3)
			targetKind := graph.NodeKindCompany
			targetProvider := system
			targetName := e.Target
			if len(targetParts) == 3 {
				targetProvider = targetParts[0]
				targetKind = mapBusinessEntityKind(targetParts[1])
				targetName = targetParts[2]
			}
			securityGraph.AddNode(&graph.Node{
				ID:       e.Target,
				Kind:     targetKind,
				Name:     targetName,
				Provider: targetProvider,
				Risk:     graph.RiskNone,
			})
		}
		securityGraph.AddEdge(e)
	}

	return nil
}

func (a *App) tapEventMapper() (*graphingest.Mapper, error) {
	if a == nil {
		return nil, fmt.Errorf("app is required")
	}
	a.tapMapperOnce.Do(func() {
		path := strings.TrimSpace(os.Getenv("GRAPH_EVENT_MAPPING_PATH"))
		var config graphingest.MappingConfig
		var err error
		if path != "" {
			config, err = graphingest.LoadConfigFile(path)
			if err != nil {
				if a.Logger != nil {
					a.Logger.Warn("failed to load custom graph event mapping config; falling back to defaults",
						"path", path,
						"error", err,
					)
				}
				config, err = graphingest.LoadDefaultConfig()
				if err != nil {
					a.tapMapperErr = fmt.Errorf("load default graph event mapping config after custom config failure: %w", err)
					return
				}
			}
		} else {
			config, err = graphingest.LoadDefaultConfig()
			if err != nil {
				a.tapMapperErr = err
				return
			}
		}

		validationMode := graphingest.MapperValidationEnforce
		deadLetterPath := ""
		if a.Config != nil {
			validationMode = graphingest.MapperValidationMode(strings.ToLower(strings.TrimSpace(a.Config.GraphEventMapperValidationMode)))
			deadLetterPath = strings.TrimSpace(a.Config.GraphEventMapperDeadLetterPath)
		}
		mapperOpts := graphingest.MapperOptions{
			ValidationMode: validationMode,
			DeadLetterPath: deadLetterPath,
		}
		a.TapEventMapper, a.tapMapperErr = graphingest.NewMapperWithOptions(config, a.resolveTapMappingIdentity, mapperOpts)
	})
	if a.tapMapperErr != nil {
		return nil, a.tapMapperErr
	}
	return a.TapEventMapper, nil
}

func (a *App) applyTapDeclarativeMappings(evt events.CloudEvent) (bool, error) {
	mapper, err := a.tapEventMapper()
	if err != nil {
		if a.Logger != nil {
			a.Logger.Warn("tap declarative mapping unavailable; using legacy fallback mapping",
				"event_type", evt.Type,
				"error", err,
			)
		}
		return false, nil
	}
	if mapper == nil {
		return false, nil
	}
	securityGraph := a.ensureSecurityGraph()
	result, err := mapper.Apply(securityGraph, evt)
	if err != nil {
		return false, err
	}
	if result.Matched && a.Logger != nil {
		a.Logger.Info("applied declarative tap graph mappings",
			"event_type", evt.Type,
			"mappings", result.MappingNames,
			"nodes", len(result.NodesUpserted),
			"edges", len(result.EdgesUpserted),
			"events_rejected", result.EventsRejected,
			"nodes_rejected", result.NodesRejected,
			"edges_rejected", result.EdgesRejected,
			"dead_lettered", result.DeadLettered,
		)
	}
	if (result.EventsRejected > 0 || result.NodesRejected > 0 || result.EdgesRejected > 0) && a.Logger != nil {
		a.Logger.Warn("tap declarative mapping rejected invalid writes",
			"event_type", evt.Type,
			"mappings", result.MappingNames,
			"events_rejected", result.EventsRejected,
			"nodes_rejected", result.NodesRejected,
			"edges_rejected", result.EdgesRejected,
			"dead_lettered", result.DeadLettered,
		)
	}
	return result.Matched, nil
}

func (a *App) resolveTapMappingIdentity(raw string, evt events.CloudEvent) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") {
		return raw
	}

	email := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(email, "@") {
		canonicalID := "person:" + email
		if securityGraph := a.ensureSecurityGraph(); securityGraph != nil {
			if _, ok := securityGraph.GetNode(canonicalID); !ok {
				securityGraph.AddNode(&graph.Node{
					ID:       canonicalID,
					Kind:     graph.NodeKindPerson,
					Name:     email,
					Provider: "org",
					Properties: map[string]any{
						"email":           email,
						"source_system":   firstNonEmpty(sourceSystemFromTapType(evt.Type), "tap"),
						"source_event_id": evt.ID,
						"observed_at":     evt.Time.UTC().Format(time.RFC3339),
						"valid_from":      evt.Time.UTC().Format(time.RFC3339),
						"confidence":      0.80,
					},
				})
			}
			_, _ = graph.ResolveIdentityAlias(securityGraph, graph.IdentityAliasAssertion{
				SourceSystem:  firstNonEmpty(sourceSystemFromTapType(evt.Type), "tap"),
				SourceEventID: strings.TrimSpace(evt.ID),
				ExternalID:    email,
				Email:         email,
				CanonicalHint: canonicalID,
				ObservedAt:    evt.Time.UTC(),
				Confidence:    0.95,
			}, graph.IdentityResolutionOptions{})
		}
		return canonicalID
	}
	return raw
}

func sourceSystemFromTapType(eventType string) string {
	parts := strings.Split(strings.TrimSpace(eventType), ".")
	if len(parts) >= 3 {
		return strings.ToLower(strings.TrimSpace(parts[2]))
	}
	return ""
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
	Required      []string
	Relationships []graph.EdgeKind
	Capabilities  []graph.NodeKindCapability
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
			Kind:               graph.NodeKind(entity.Kind),
			Categories:         entity.Categories,
			Properties:         entity.Properties,
			RequiredProperties: entity.Required,
			Relationships:      entity.Relationships,
			Capabilities:       entity.Capabilities,
			Description:        entity.Description,
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
		rawProperties := firstPresent(entity, "properties", "fields", "schema")

		definition := tapSchemaEntityDefinition{
			Kind:          kind,
			Categories:    parseTapSchemaCategories(firstPresent(entity, "categories", "category"), kind),
			Properties:    parseTapSchemaProperties(rawProperties),
			Required:      parseTapSchemaRequiredProperties(firstPresent(entity, "required_properties", "required_fields", "required"), rawProperties),
			Relationships: parseTapSchemaRelationships(firstPresent(entity, "relationships", "edges", "relation_types")),
			Capabilities:  parseTapSchemaCapabilities(firstPresent(entity, "capabilities", "features")),
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

func parseTapSchemaRequiredProperties(raw any, schemaRaw any) []string {
	required := make(map[string]struct{})

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		required[value] = struct{}{}
	}

	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			add(part)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			add(anyToString(item))
		}
	}

	for key, value := range mapFromAny(schemaRaw) {
		nested := mapFromAny(value)
		if len(nested) == 0 {
			continue
		}
		if requiredFlag, ok := firstPresent(nested, "required", "is_required").(bool); ok && requiredFlag {
			add(key)
		}
	}

	return sortedStringSet(required)
}

func parseTapSchemaCapabilities(raw any) []graph.NodeKindCapability {
	capabilities := make(map[graph.NodeKindCapability]struct{})

	add := func(value string) {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case string(graph.NodeCapabilityInternetExposable):
			capabilities[graph.NodeCapabilityInternetExposable] = struct{}{}
		case string(graph.NodeCapabilitySensitiveData):
			capabilities[graph.NodeCapabilitySensitiveData] = struct{}{}
		case string(graph.NodeCapabilityPrivilegedIdentity):
			capabilities[graph.NodeCapabilityPrivilegedIdentity] = struct{}{}
		case string(graph.NodeCapabilityCredentialStore):
			capabilities[graph.NodeCapabilityCredentialStore] = struct{}{}
		}
	}

	switch typed := raw.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			add(part)
		}
	case []string:
		for _, item := range typed {
			add(item)
		}
	case []any:
		for _, item := range typed {
			add(anyToString(item))
		}
	}

	if len(capabilities) == 0 {
		return nil
	}
	out := make([]graph.NodeKindCapability, 0, len(capabilities))
	for capability := range capabilities {
		out = append(out, capability)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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

	securityGraph := a.ensureSecurityGraph()

	for _, participant := range participants {
		a.upsertTapInteractionPersonNode(securityGraph, participant, channel, occurredAt)
	}

	for i := 0; i < len(participants); i++ {
		for j := i + 1; j < len(participants); j++ {
			graph.UpsertInteractionEdge(securityGraph, graph.InteractionEdge{
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

func (a *App) upsertTapInteractionPersonNode(securityGraph *graph.Graph, participant tapInteractionParticipant, channel string, occurredAt time.Time) {
	if securityGraph == nil {
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

	if existing, ok := securityGraph.GetNode(personID); ok && existing != nil {
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

	securityGraph.AddNode(&graph.Node{
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
	securityGraph := a.ensureSecurityGraph()

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
	activityKind := deriveTapActivityNodeKind(source, activityType, evt.Data)
	activityNodeID := fmt.Sprintf("%s:%s:%s:%s", tapActivityNodePrefix(activityKind), source, activityType, activityID)
	metadata := mapFromAny(evt.Data["metadata"])
	if metadata == nil {
		metadata = map[string]any{}
	}
	writeMeta := graph.NormalizeWriteMetadata(
		occurredAt,
		occurredAt,
		nil,
		source,
		evt.ID,
		0.8,
		graph.WriteMetadataDefaults{
			Now:               occurredAt,
			SourceSystem:      source,
			SourceEventID:     evt.ID,
			SourceEventPrefix: "tap_activity",
			DefaultConfidence: 0.8,
		},
	)

	securityGraph.AddNode(&graph.Node{
		ID:       actorNodeID,
		Kind:     graph.NodeKindPerson,
		Name:     coalesceString(actorName, actorID),
		Provider: source,
		Risk:     graph.RiskNone,
		Properties: map[string]any{
			"email": actorID,
		},
	})

	securityGraph.AddNode(&graph.Node{
		ID:         targetNodeID,
		Kind:       targetKind,
		Name:       coalesceString(targetName, targetNodeID),
		Provider:   source,
		Risk:       graph.RiskNone,
		Properties: map[string]any{"source_system": source},
	})

	activityProps := map[string]any{
		"event_type":           evt.Type,
		"legacy_activity_type": activityType,
		"action":               action,
		"metadata":             metadata,
	}
	writeMeta.ApplyTo(activityProps)
	applyTapActivityKindProperties(activityProps, activityKind, activityID, activityType, action, actorNodeID, occurredAt, evt.Data)

	securityGraph.AddNode(&graph.Node{
		ID:         activityNodeID,
		Kind:       activityKind,
		Name:       coalesceString(action, activityType),
		Provider:   source,
		Risk:       graph.RiskNone,
		Properties: activityProps,
	})

	securityGraph.AddEdge(&graph.Edge{
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
	targetEdgeKind := graph.EdgeKindInteractedWith
	if activityKind != graph.NodeKindActivity {
		targetEdgeKind = graph.EdgeKindTargets
	}
	securityGraph.AddEdge(&graph.Edge{
		ID:     fmt.Sprintf("%s->%s:%s", activityNodeID, targetNodeID, targetEdgeKind),
		Source: activityNodeID,
		Target: targetNodeID,
		Kind:   targetEdgeKind,
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

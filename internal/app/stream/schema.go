package stream

import (
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func (r *Runtime) handleTapSchemaEvent(eventType string, evt events.CloudEvent) error {
	integration := ParseTapSchemaIntegration(eventType, evt.Data)
	entities := ParseTapSchemaEntities(evt.Data)
	if len(entities) == 0 {
		return nil
	}

	registeredNodeKinds := 0
	edgeKinds := make(map[graph.EdgeKind]struct{})
	for _, edgeKind := range ParseTapSchemaRelationships(FirstPresent(evt.Data, "edge_types", "relationship_types")) {
		edgeKinds[edgeKind] = struct{}{}
	}

	for _, entity := range entities {
		if !r.registerTapSchemaNodeKind(integration, entity, edgeKinds) {
			continue
		}
		registeredNodeKinds++
	}

	registeredEdgeKinds := r.registerTapSchemaEdgeKinds(integration, edgeKinds)

	if logger := r.logger(); logger != nil {
		logger.Info("registered tap integration schema",
			"integration", integration,
			"node_kinds", registeredNodeKinds,
			"edge_kinds", registeredEdgeKinds,
		)
	}
	return nil
}

func (r *Runtime) registerTapSchemaNodeKind(integration string, entity SchemaEntityDefinition, edgeKinds map[graph.EdgeKind]struct{}) bool {
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
		if logger := r.logger(); logger != nil {
			logger.Warn("failed to register tap schema node kind",
				"integration", integration,
				"kind", entity.Kind,
				"error", err,
			)
		}
		return false
	}
	for _, relationship := range entity.Relationships {
		edgeKinds[relationship] = struct{}{}
	}
	return true
}

func (r *Runtime) registerTapSchemaEdgeKinds(integration string, edgeKinds map[graph.EdgeKind]struct{}) int {
	registered := 0
	for edgeKind := range edgeKinds {
		if _, err := graph.RegisterEdgeKindDefinition(graph.EdgeKindDefinition{Kind: edgeKind}); err != nil {
			if logger := r.logger(); logger != nil {
				logger.Warn("failed to register tap schema edge kind",
					"integration", integration,
					"kind", edgeKind,
					"error", err,
				)
			}
			continue
		}
		registered++
	}
	return registered
}

func (r *Runtime) HandleTapSchemaEvent(eventType string, evt events.CloudEvent) error {
	return r.handleTapSchemaEvent(eventType, evt)
}

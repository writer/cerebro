package app

import (
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

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
		if !a.registerTapSchemaNodeKind(integration, entity, edgeKinds) {
			continue
		}
		registeredNodeKinds++
	}

	registeredEdgeKinds := a.registerTapSchemaEdgeKinds(integration, edgeKinds)

	if a.Logger != nil {
		a.Logger.Info("registered tap integration schema",
			"integration", integration,
			"node_kinds", registeredNodeKinds,
			"edge_kinds", registeredEdgeKinds,
		)
	}
	return nil
}

func (a *App) registerTapSchemaNodeKind(integration string, entity tapSchemaEntityDefinition, edgeKinds map[graph.EdgeKind]struct{}) bool {
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
		return false
	}
	for _, relationship := range entity.Relationships {
		edgeKinds[relationship] = struct{}{}
	}
	return true
}

func (a *App) registerTapSchemaEdgeKinds(integration string, edgeKinds map[graph.EdgeKind]struct{}) int {
	registered := 0
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
		registered++
	}
	return registered
}

package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestEnsureRelationshipNode_EntraResourcesUseAzureProvider(t *testing.T) {
	t.Parallel()

	builder := NewBuilder(newMockDataSource(), slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))
	id := "/subscriptions/sub-123/providers/Microsoft.Directory/users/alice"

	builder.ensureRelationshipNode(id, "entra:user")

	node, ok := builder.Graph().GetNode(id)
	if !ok {
		t.Fatalf("expected placeholder node %q", id)
	}
	if node.Kind != NodeKindUser {
		t.Fatalf("expected user node kind, got %s", node.Kind)
	}
	if node.Provider != "azure" {
		t.Fatalf("expected azure provider, got %q", node.Provider)
	}
	if node.Account != "sub-123" {
		t.Fatalf("expected subscription account enrichment, got %q", node.Account)
	}
	if node.Name != "alice" {
		t.Fatalf("expected Azure display name enrichment, got %q", node.Name)
	}
}

func TestBuilderRelationshipEdges_MapCanAccessToCanRead(t *testing.T) {
	t.Parallel()

	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))

	source.setResult(`
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`, &DataQueryResult{
		Rows: []map[string]any{{
			"source_id":   "user-1",
			"source_type": "okta:user",
			"target_id":   "app-1",
			"target_type": "okta:application",
			"rel_type":    "CAN_ACCESS",
		}},
	})

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	assertEdgeExists(t, builder.Graph(), "user-1", "app-1", EdgeKindCanRead)
	for _, edge := range builder.Graph().GetOutEdges("user-1") {
		if edge.Target == "app-1" && edge.Kind == EdgeKindConnectsTo {
			t.Fatalf("expected CAN_ACCESS to avoid generic connects_to edge, got %#v", edge)
		}
	}
}

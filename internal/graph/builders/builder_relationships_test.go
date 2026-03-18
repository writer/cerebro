package builders

import (
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

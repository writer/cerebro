package kuzu

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestGetEntityNeighborhoodReturnsRootNeighborsAndRelations(t *testing.T) {
	store := newTestStore(t)
	projectEvents(t, store, &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: "writer",
		SourceId: "github",
		Kind:     "github.pull_request",
		Attributes: map[string]string{
			"author":      "alice",
			"owner":       "writer",
			"pull_number": "447",
			"repository":  "writer/cerebro",
			"state":       "open",
		},
	})

	neighborhood, err := store.GetEntityNeighborhood(context.Background(), "urn:cerebro:writer:github_pull_request:writer/cerebro#447", 2)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if neighborhood.Root == nil || neighborhood.Root.URN != "urn:cerebro:writer:github_pull_request:writer/cerebro#447" {
		t.Fatalf("Root = %#v, want pull request root", neighborhood.Root)
	}
	if len(neighborhood.Neighbors) != 2 {
		t.Fatalf("len(Neighbors) = %d, want 2", len(neighborhood.Neighbors))
	}
	if len(neighborhood.Relations) != 2 {
		t.Fatalf("len(Relations) = %d, want 2", len(neighborhood.Relations))
	}
	if !containsNeighborhoodNode(neighborhood.Neighbors, "urn:cerebro:writer:github_repo:writer/cerebro", "github.repo") {
		t.Fatalf("Neighbors missing repo: %#v", neighborhood.Neighbors)
	}
	if !containsNeighborhoodNode(neighborhood.Neighbors, "urn:cerebro:writer:github_user:alice", "github.user") {
		t.Fatalf("Neighbors missing author: %#v", neighborhood.Neighbors)
	}
	if !containsNeighborhoodRelation(neighborhood.Relations, "urn:cerebro:writer:github_user:alice", "authored", "urn:cerebro:writer:github_pull_request:writer/cerebro#447") {
		t.Fatalf("Relations missing authored edge: %#v", neighborhood.Relations)
	}
	if !containsNeighborhoodRelation(neighborhood.Relations, "urn:cerebro:writer:github_pull_request:writer/cerebro#447", "belongs_to", "urn:cerebro:writer:github_repo:writer/cerebro") {
		t.Fatalf("Relations missing belongs_to edge: %#v", neighborhood.Relations)
	}
}

func TestGetEntityNeighborhoodReturnsNotFoundForMissingRoot(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetEntityNeighborhood(context.Background(), "urn:cerebro:writer:github_user:missing", 5)
	if !errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetEntityNeighborhood() error = %v, want %v", err, ports.ErrGraphEntityNotFound)
	}
}

func containsNeighborhoodNode(nodes []*ports.NeighborhoodNode, urn string, entityType string) bool {
	for _, node := range nodes {
		if node != nil && node.URN == urn && node.EntityType == entityType {
			return true
		}
	}
	return false
}

func containsNeighborhoodRelation(relations []*ports.NeighborhoodRelation, fromURN string, relation string, toURN string) bool {
	for _, edge := range relations {
		if edge != nil && edge.FromURN == fromURN && edge.Relation == relation && edge.ToURN == toURN {
			return true
		}
	}
	return false
}

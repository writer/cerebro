package neo4j

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestLiveGetEntityNeighborhoodReturnsRootNeighborsAndRelations(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	projectEvents(t, store, &cerebrov1.EventEnvelope{
		Id:       "github-pr-447",
		TenantId: tenantID,
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

	rootURN := "urn:cerebro:" + tenantID + ":github_pull_request:writer/cerebro#447"
	neighborhood, err := store.GetEntityNeighborhood(context.Background(), rootURN, 2)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if neighborhood.Root == nil || neighborhood.Root.URN != rootURN {
		t.Fatalf("Root = %#v, want pull request root", neighborhood.Root)
	}
	if len(neighborhood.Neighbors) != 2 {
		t.Fatalf("Neighbors len = %d, want 2: %#v", len(neighborhood.Neighbors), neighborhood.Neighbors)
	}
	if !containsNeighborhoodNode(neighborhood.Neighbors, "urn:cerebro:"+tenantID+":github_repo:writer/cerebro", "github.repo") {
		t.Fatalf("Neighbors missing repo: %#v", neighborhood.Neighbors)
	}
	if !containsNeighborhoodRelation(neighborhood.Relations, rootURN, "belongs_to", "urn:cerebro:"+tenantID+":github_repo:writer/cerebro") {
		t.Fatalf("Relations missing belongs_to edge: %#v", neighborhood.Relations)
	}
}

func TestLiveGetEntityNeighborhoodReturnsNotFoundForMissingRoot(t *testing.T) {
	store, tenantID := newLiveTestStore(t)
	_, err := store.GetEntityNeighborhood(context.Background(), "urn:cerebro:"+tenantID+":github_user:missing", 5)
	if !errors.Is(err, ports.ErrGraphEntityNotFound) {
		t.Fatalf("GetEntityNeighborhood() error = %v, want %v", err, ports.ErrGraphEntityNotFound)
	}
}

func containsNeighborhoodNode(nodes []*ports.NeighborhoodNode, urn string, entityType string) bool {
	for _, node := range nodes {
		if node.URN == urn && node.EntityType == entityType {
			return true
		}
	}
	return false
}

func containsNeighborhoodRelation(relations []*ports.NeighborhoodRelation, fromURN string, relation string, toURN string) bool {
	for _, link := range relations {
		if link.FromURN == fromURN && link.Relation == relation && link.ToURN == toURN {
			return true
		}
	}
	return false
}

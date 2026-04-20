package graph

import (
	"context"
	"testing"
)

type countOnlyMetadataStore struct {
	GraphStore
	nodeCount int
	edgeCount int
}

func (s countOnlyMetadataStore) CountNodes(context.Context) (int, error) {
	return s.nodeCount, nil
}

func (s countOnlyMetadataStore) CountEdges(context.Context) (int, error) {
	return s.edgeCount, nil
}

func TestGraphMetadataFromCountsLeavesBuiltAtUnset(t *testing.T) {
	meta, err := graphMetadataFromCounts(context.Background(), countOnlyMetadataStore{
		nodeCount: 3,
		edgeCount: 2,
	})
	if err != nil {
		t.Fatalf("graphMetadataFromCounts() error = %v", err)
	}
	if !meta.BuiltAt.IsZero() {
		t.Fatalf("BuiltAt = %v, want zero", meta.BuiltAt)
	}
	if record := CurrentGraphSnapshotRecordFromMetadata(meta); record != nil {
		t.Fatalf("CurrentGraphSnapshotRecordFromMetadata() = %#v, want nil without BuiltAt", record)
	}
}

package sourcehealth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/writer/cerebro/internal/graphstore"
)

type boundedRunStore struct {
	filters  []graphstore.IngestRunFilter
	failCall int
}

var errListIngestRuns = errors.New("list ingest runs failed")

func (*boundedRunStore) PutIngestRun(context.Context, graphstore.IngestRun) error {
	return nil
}

func (*boundedRunStore) GetIngestRun(context.Context, string) (graphstore.IngestRun, bool, error) {
	return graphstore.IngestRun{}, false, nil
}

func (s *boundedRunStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	s.filters = append(s.filters, filter)
	if s.failCall == len(s.filters) {
		return nil, errListIngestRuns
	}
	if filter.Limit > maxGraphRunStatusLimit {
		return nil, errors.New("ingest run limit exceeded")
	}
	runs := make([]graphstore.IngestRun, 0, len(filter.RuntimeIDs))
	for _, runtimeID := range filter.RuntimeIDs {
		runs = append(runs, graphstore.IngestRun{ID: "run-" + runtimeID, RuntimeID: runtimeID})
	}
	return runs, nil
}

func TestLatestGraphIngestRunsChunksRuntimeIDsAtStoreLimit(t *testing.T) {
	runtimeIDs := make([]string, maxGraphRunStatusLimit+1)
	for index := range runtimeIDs {
		runtimeIDs[index] = fmt.Sprintf("runtime-%03d", index)
	}
	store := &boundedRunStore{}

	runs, err := LatestGraphIngestRuns(context.Background(), store, runtimeIDs)
	if err != nil {
		t.Fatalf("LatestGraphIngestRuns() error = %v", err)
	}
	if len(runs) != len(runtimeIDs) {
		t.Fatalf("LatestGraphIngestRuns() returned %d runs, want %d", len(runs), len(runtimeIDs))
	}
	if len(store.filters) != 2 {
		t.Fatalf("ListIngestRuns() calls = %d, want 2", len(store.filters))
	}
	for index, wantSize := range []int{maxGraphRunStatusLimit, 1} {
		filter := store.filters[index]
		if len(filter.RuntimeIDs) != wantSize || filter.Limit != wantSize || !filter.LatestByRuntime {
			t.Fatalf("ListIngestRuns() filter %d = %#v, want %d runtime IDs with matching limit and LatestByRuntime", index, filter, wantSize)
		}
	}
}

func TestLatestGraphIngestRunsReturnsBatchError(t *testing.T) {
	runtimeIDs := make([]string, maxGraphRunStatusLimit+1)
	for index := range runtimeIDs {
		runtimeIDs[index] = fmt.Sprintf("runtime-%03d", index)
	}
	store := &boundedRunStore{failCall: 2}

	runs, err := LatestGraphIngestRuns(context.Background(), store, runtimeIDs)
	if !errors.Is(err, errListIngestRuns) {
		t.Fatalf("LatestGraphIngestRuns() error = %v, want %v", err, errListIngestRuns)
	}
	if runs != nil {
		t.Fatalf("LatestGraphIngestRuns() runs = %#v, want nil", runs)
	}
	if len(store.filters) != 2 {
		t.Fatalf("ListIngestRuns() calls = %d, want 2", len(store.filters))
	}
}

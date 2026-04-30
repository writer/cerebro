//go:build cgo

package kuzu

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graphstore"
)

func TestIngestRunRoundTripAndList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, ok, err := store.GetIngestRun(ctx, "run-1"); err != nil {
		t.Fatalf("GetIngestRun() error = %v", err)
	} else if ok {
		t.Fatal("GetIngestRun() ok = true, want false")
	}

	first := IngestRun{
		ID:                "run-1",
		RuntimeID:         "writer-github",
		SourceID:          "github",
		TenantID:          "writer",
		CheckpointID:      "runtime:writer-github:hash",
		Status:            graphstore.IngestRunStatusCompleted,
		Trigger:           "manual",
		PagesRead:         2,
		EventsRead:        3,
		EntitiesProjected: 4,
		LinksProjected:    5,
		GraphNodesBefore:  6,
		GraphLinksBefore:  7,
		GraphNodesAfter:   8,
		GraphLinksAfter:   9,
		StartedAt:         "2026-04-29T00:00:00Z",
		FinishedAt:        "2026-04-29T00:00:01Z",
	}
	second := first
	second.ID = "run-2"
	second.RuntimeID = "writer-aws"
	second.SourceID = "aws"
	second.Status = graphstore.IngestRunStatusFailed
	second.Error = "read failed"
	second.StartedAt = "2026-04-29T00:00:02Z"
	if err := store.PutIngestRun(ctx, first); err != nil {
		t.Fatalf("PutIngestRun(first) error = %v", err)
	}
	if err := store.PutIngestRun(ctx, second); err != nil {
		t.Fatalf("PutIngestRun(second) error = %v", err)
	}

	got, ok, err := store.GetIngestRun(ctx, second.ID)
	if err != nil {
		t.Fatalf("GetIngestRun() error = %v", err)
	}
	if !ok {
		t.Fatal("GetIngestRun() ok = false, want true")
	}
	if got != second {
		t.Fatalf("GetIngestRun() = %#v, want %#v", got, second)
	}

	failed, err := store.ListIngestRuns(ctx, IngestRunFilter{Status: graphstore.IngestRunStatusFailed, Limit: 10})
	if err != nil {
		t.Fatalf("ListIngestRuns(failed) error = %v", err)
	}
	if len(failed) != 1 || failed[0].ID != second.ID {
		t.Fatalf("ListIngestRuns(failed) = %#v, want run-2", failed)
	}
	writerGitHub, err := store.ListIngestRuns(ctx, IngestRunFilter{RuntimeID: "writer-github", Limit: 10})
	if err != nil {
		t.Fatalf("ListIngestRuns(runtime) error = %v", err)
	}
	if len(writerGitHub) != 1 || writerGitHub[0].ID != first.ID {
		t.Fatalf("ListIngestRuns(runtime) = %#v, want run-1", writerGitHub)
	}
}

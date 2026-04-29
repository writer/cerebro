package kuzu

import (
	"context"
	"testing"
)

func TestIngestCheckpointRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, ok, err := store.GetIngestCheckpoint(ctx, "github-writer"); err != nil {
		t.Fatalf("GetIngestCheckpoint() error = %v", err)
	} else if ok {
		t.Fatal("GetIngestCheckpoint() ok = true, want false")
	}

	want := IngestCheckpoint{
		ID:               "github-writer",
		SourceID:         "github",
		TenantID:         "writer",
		ConfigHash:       "hash",
		CursorOpaque:     "next-cursor",
		CheckpointOpaque: "checkpoint-cursor",
		Completed:        false,
		PagesRead:        3,
		EventsRead:       15,
		UpdatedAt:        "2026-04-28T00:00:00Z",
	}
	if err := store.PutIngestCheckpoint(ctx, want); err != nil {
		t.Fatalf("PutIngestCheckpoint() error = %v", err)
	}
	got, ok, err := store.GetIngestCheckpoint(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetIngestCheckpoint() error = %v", err)
	}
	if !ok {
		t.Fatal("GetIngestCheckpoint() ok = false, want true")
	}
	if got != want {
		t.Fatalf("GetIngestCheckpoint() = %#v, want %#v", got, want)
	}
}

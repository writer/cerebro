package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func TestReplayJetStreamResumesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	checkpointPath := filepath.Join(dir, "replay.checkpoint.json")
	if err := saveReplayStreamCheckpoint(checkpointPath, "REPLAY_STREAM", "ensemble.tap.replay.>", 9); err != nil {
		t.Fatalf("save replay checkpoint: %v", err)
	}

	prev := replayStreamHistoryFn
	t.Cleanup(func() { replayStreamHistoryFn = prev })
	replayStreamHistoryFn = func(_ context.Context, cfg events.ReplayConfig, handler events.ReplayHandler) (events.ReplayReport, error) {
		if cfg.FromSequence != 10 {
			t.Fatalf("expected replay to resume from sequence 10, got %d", cfg.FromSequence)
		}
		if err := handler(context.Background(), events.ReplayEvent{
			CloudEvent: events.CloudEvent{
				ID:         "evt-replay-10",
				Type:       "ensemble.tap.hubspot.contact.updated",
				Source:     "urn:test",
				Time:       time.Date(2026, 3, 11, 18, 30, 0, 0, time.UTC),
				DataSchema: "urn:test:schema",
				Data: map[string]any{
					"entity_id": "contact-10",
					"snapshot": map[string]any{
						"name": "Alice",
					},
				},
			},
			StreamSequence: 10,
		}); err != nil {
			return events.ReplayReport{}, err
		}
		return events.ReplayReport{
			Stream:             cfg.Stream,
			Subject:            cfg.Subject,
			StartedAt:          time.Now().UTC(),
			CompletedAt:        time.Now().UTC(),
			StartSequence:      cfg.FromSequence,
			UpperBoundSequence: 10,
			LastStreamSequence: 10,
			MessagesFetched:    1,
			EventsParsed:       1,
			EventsHandled:      1,
		}, nil
	}

	report, err := replayJetStream(replayStreamOptions{
		Stream:     "REPLAY_STREAM",
		Subject:    "ensemble.tap.replay.>",
		Checkpoint: checkpointPath,
		Resume:     true,
		DryRun:     true,
	})
	if err != nil {
		t.Fatalf("replayJetStream failed: %v", err)
	}
	if !report.CheckpointLoaded {
		t.Fatalf("expected checkpoint to load, got %#v", report)
	}
	if !report.CheckpointSaved {
		t.Fatalf("expected checkpoint to save, got %#v", report)
	}

	state, err := loadReplayStreamCheckpoint(checkpointPath, "REPLAY_STREAM", "ensemble.tap.replay.>")
	if err != nil {
		t.Fatalf("load replay checkpoint: %v", err)
	}
	if state == nil || state.LastStreamSequence != 10 {
		t.Fatalf("expected last stream sequence 10, got %#v", state)
	}
}

func TestReplayJetStreamMaterializesSnapshot(t *testing.T) {
	dir := t.TempDir()
	prev := replayStreamHistoryFn
	t.Cleanup(func() { replayStreamHistoryFn = prev })
	replayStreamHistoryFn = func(_ context.Context, cfg events.ReplayConfig, handler events.ReplayHandler) (events.ReplayReport, error) {
		if err := handler(context.Background(), events.ReplayEvent{
			CloudEvent: events.CloudEvent{
				ID:         "evt-replay-snapshot",
				Type:       "ensemble.tap.hubspot.contact.updated",
				Source:     "urn:test",
				Time:       time.Date(2026, 3, 11, 19, 0, 0, 0, time.UTC),
				DataSchema: "urn:test:schema",
				Data: map[string]any{
					"entity_id": "contact-1",
					"snapshot": map[string]any{
						"name":       "Alice",
						"company_id": "company-1",
					},
				},
			},
			StreamSequence: 1,
		}); err != nil {
			return events.ReplayReport{}, err
		}
		return events.ReplayReport{
			Stream:             cfg.Stream,
			Subject:            cfg.Subject,
			StartedAt:          time.Now().UTC(),
			CompletedAt:        time.Now().UTC(),
			StartSequence:      1,
			UpperBoundSequence: 1,
			LastStreamSequence: 1,
			MessagesFetched:    1,
			EventsParsed:       1,
			EventsHandled:      1,
		}, nil
	}

	report, err := replayJetStream(replayStreamOptions{
		Stream:      "REPLAY_STREAM",
		Subject:     "ensemble.tap.replay.>",
		DryRun:      false,
		SnapshotDir: dir,
		Checkpoint:  filepath.Join(dir, "replay.checkpoint.json"),
	})
	if err != nil {
		t.Fatalf("replayJetStream failed: %v", err)
	}
	if !report.SnapshotSaved {
		t.Fatalf("expected snapshot to be saved, got %#v", report)
	}
	if report.GraphNodeCount == 0 {
		t.Fatalf("expected replayed graph nodes, got %#v", report)
	}

	store := graph.NewSnapshotStore(dir, 10)
	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("list graph snapshot records: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("expected persisted graph snapshot record, got none")
	}
}

func TestResolveReplaySnapshotDirFallsBackToGraphSnapshotEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GRAPH_SNAPSHOT_PATH", dir)
	if got := resolveReplaySnapshotDir(""); got != dir {
		t.Fatalf("expected replay snapshot dir %q, got %q", dir, got)
	}
}

func TestSaveReplayStreamCheckpointCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "state.json")
	if err := saveReplayStreamCheckpoint(path, "stream-a", "subject-a", 42); err != nil {
		t.Fatalf("save replay stream checkpoint: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected checkpoint file to exist: %v", err)
	}
}

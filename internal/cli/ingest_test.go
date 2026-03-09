package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graphingest"
)

func TestReplayDeadLetterSummarizesReplayOutcomes(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mappings.yaml")
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")

	mappingYAML := `
mappings:
  - name: replay_test
    source: replay.test
    nodes:
      - id: person:{{data.email}}
        kind: person
        name: "{{data.email}}"
        provider: replay
`
	if err := os.WriteFile(mappingPath, []byte(mappingYAML), 0o600); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	now := time.Date(2026, 3, 9, 23, 0, 0, 0, time.UTC)
	records := []graphingest.DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-1",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now,
			EventData:   map[string]any{"email": "alice@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:alice@example.com",
		},
		{
			RecordedAt:  now.Add(1 * time.Second),
			EventID:     "evt-1",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now.Add(1 * time.Second),
			EventData:   map[string]any{"email": "alice@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:alice@example.com",
		},
		{
			RecordedAt:  now.Add(2 * time.Second),
			EventID:     "evt-2",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now.Add(2 * time.Second),
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:bob@example.com",
		},
		{
			RecordedAt:  now.Add(3 * time.Second),
			EventID:     "evt-3",
			EventType:   "replay.unknown",
			EventSource: "urn:test",
			EventTime:   now.Add(3 * time.Second),
			EventData:   map[string]any{"email": "carol@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:carol@example.com",
		},
	}
	if err := writeDeadLetterJSONL(dlqPath, records, nil); err != nil {
		t.Fatalf("write dead-letter file: %v", err)
	}

	report, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
	})
	if err != nil {
		t.Fatalf("replay dead-letter failed: %v", err)
	}

	if report.MappingSource != mappingPath {
		t.Fatalf("expected mapping source %q, got %q", mappingPath, report.MappingSource)
	}
	if report.LinesRead != 4 || report.RecordsParsed != 4 || report.ParseErrors != 0 {
		t.Fatalf("unexpected file scan counters: %#v", report)
	}
	if report.UniqueEvents != 3 {
		t.Fatalf("expected 3 unique events, got %d", report.UniqueEvents)
	}
	if report.EventsDeduplicated != 1 {
		t.Fatalf("expected 1 deduplicated event, got %d", report.EventsDeduplicated)
	}
	if report.EventsProcessed != 3 {
		t.Fatalf("expected 3 processed events, got %d", report.EventsProcessed)
	}
	if report.EventsReplayed != 1 {
		t.Fatalf("expected 1 replayed event, got %d", report.EventsReplayed)
	}
	if report.EventsSkippedNoData != 1 {
		t.Fatalf("expected 1 event skipped for missing data, got %d", report.EventsSkippedNoData)
	}
	if report.EventsUnmatched != 1 {
		t.Fatalf("expected 1 unmatched event, got %d", report.EventsUnmatched)
	}
	if report.EventsStillRejected != 0 {
		t.Fatalf("expected 0 still rejected events, got %d", report.EventsStillRejected)
	}
	if report.NodesUpserted < 1 {
		t.Fatalf("expected at least one node upserted, got %d", report.NodesUpserted)
	}
}

func TestReplayDeadLetterHonorsLimitAndParseErrors(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mappings.yaml")
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")

	mappingYAML := `
mappings:
  - name: replay_test
    source: replay.test
    nodes:
      - id: person:{{data.email}}
        kind: person
        name: "{{data.email}}"
        provider: replay
`
	if err := os.WriteFile(mappingPath, []byte(mappingYAML), 0o600); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	now := time.Date(2026, 3, 9, 23, 30, 0, 0, time.UTC)
	records := []graphingest.DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-1",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now,
			EventData:   map[string]any{"email": "alice@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:alice@example.com",
		},
		{
			RecordedAt:  now.Add(1 * time.Second),
			EventID:     "evt-2",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now.Add(1 * time.Second),
			EventData:   map[string]any{"email": "bob@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:bob@example.com",
		},
	}
	if err := writeDeadLetterJSONL(dlqPath, records, []string{"not-json"}); err != nil {
		t.Fatalf("write dead-letter file: %v", err)
	}

	report, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("replay dead-letter failed: %v", err)
	}

	if report.ParseErrors != 1 {
		t.Fatalf("expected 1 parse error, got %d", report.ParseErrors)
	}
	if report.EventsProcessed != 1 {
		t.Fatalf("expected 1 processed event due to limit, got %d", report.EventsProcessed)
	}
	if report.EventsLimitSkipped != 1 {
		t.Fatalf("expected 1 event skipped by limit, got %d", report.EventsLimitSkipped)
	}
	if report.EventsReplayed != 1 {
		t.Fatalf("expected 1 replayed event, got %d", report.EventsReplayed)
	}
}

func TestReplayDeadLetterCheckpointResume(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mappings.yaml")
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")
	checkpointPath := filepath.Join(dir, "replay-checkpoint.json")

	mappingYAML := `
mappings:
  - name: replay_test
    source: replay.test
    nodes:
      - id: person:{{data.email}}
        kind: person
        name: "{{data.email}}"
        provider: replay
`
	if err := os.WriteFile(mappingPath, []byte(mappingYAML), 0o600); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	now := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	records := []graphingest.DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-1",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now,
			EventData:   map[string]any{"email": "alice@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:alice@example.com",
		},
		{
			RecordedAt:  now.Add(1 * time.Second),
			EventID:     "evt-2",
			EventType:   "replay.test",
			EventSource: "urn:test",
			EventTime:   now.Add(1 * time.Second),
			EventData:   map[string]any{"email": "bob@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:bob@example.com",
		},
	}
	if err := writeDeadLetterJSONL(dlqPath, records, nil); err != nil {
		t.Fatalf("write dead-letter file: %v", err)
	}

	first, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
		Limit:       1,
		Checkpoint:  checkpointPath,
		Resume:      true,
	})
	if err != nil {
		t.Fatalf("first replay failed: %v", err)
	}
	if first.EventsProcessed != 1 {
		t.Fatalf("expected first run to process 1 event, got %d", first.EventsProcessed)
	}
	if !first.CheckpointSaved {
		t.Fatalf("expected checkpoint to be saved on first run, got %#v", first)
	}

	second, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
		Checkpoint:  checkpointPath,
		Resume:      true,
	})
	if err != nil {
		t.Fatalf("second replay failed: %v", err)
	}
	if !second.CheckpointLoaded {
		t.Fatalf("expected checkpoint loaded on second run, got %#v", second)
	}
	if second.EventsCheckpointed != 1 {
		t.Fatalf("expected one checkpoint-skipped event, got %d", second.EventsCheckpointed)
	}
	if second.EventsProcessed != 1 {
		t.Fatalf("expected second run to process remaining one event, got %d", second.EventsProcessed)
	}
	if second.EventsReplayed != 1 {
		t.Fatalf("expected one replayed event on second run, got %d", second.EventsReplayed)
	}
}

func TestReplayDeadLetterCheckpointSkipsOnlySuccessfulReplays(t *testing.T) {
	dir := t.TempDir()
	mappingPath := filepath.Join(dir, "mappings.yaml")
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")
	checkpointPath := filepath.Join(dir, "replay-checkpoint.json")

	mappingYAML := `
mappings:
  - name: replay_test
    source: replay.test
    nodes:
      - id: person:{{data.email}}
        kind: person
        name: "{{data.email}}"
        provider: replay
`
	if err := os.WriteFile(mappingPath, []byte(mappingYAML), 0o600); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	now := time.Date(2026, 3, 10, 0, 10, 0, 0, time.UTC)
	records := []graphingest.DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-unmatched-1",
			EventType:   "replay.unmatched",
			EventSource: "urn:test",
			EventTime:   now,
			EventData:   map[string]any{"email": "alice@example.com"},
			MappingName: "replay_test",
			EntityType:  "node",
			EntityID:    "person:alice@example.com",
		},
	}
	if err := writeDeadLetterJSONL(dlqPath, records, nil); err != nil {
		t.Fatalf("write dead-letter file: %v", err)
	}

	first, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
		Checkpoint:  checkpointPath,
		Resume:      true,
	})
	if err != nil {
		t.Fatalf("first replay failed: %v", err)
	}
	if first.EventsProcessed != 1 || first.EventsUnmatched != 1 {
		t.Fatalf("expected one unmatched processed event, got %#v", first)
	}

	second, err := replayDeadLetter(replayDeadLetterOptions{
		Path:        dlqPath,
		MappingPath: mappingPath,
		Checkpoint:  checkpointPath,
		Resume:      true,
	})
	if err != nil {
		t.Fatalf("second replay failed: %v", err)
	}
	if second.EventsCheckpointed != 0 {
		t.Fatalf("expected no checkpoint-skipped events for unmatched replay, got %d", second.EventsCheckpointed)
	}
	if second.EventsProcessed != 1 || second.EventsUnmatched != 1 {
		t.Fatalf("expected unmatched event to be retried, got %#v", second)
	}
}

func writeDeadLetterJSONL(path string, records []graphingest.DeadLetterRecord, invalid []string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	for idx, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if _, err := file.Write(payload); err != nil {
			return err
		}
		if _, err := file.WriteString("\n"); err != nil {
			return err
		}
		if idx < len(invalid) {
			if _, err := file.WriteString(invalid[idx] + "\n"); err != nil {
				return err
			}
		}
	}

	if len(invalid) > len(records) {
		for _, line := range invalid[len(records):] {
			if _, err := file.WriteString(line + "\n"); err != nil {
				return err
			}
		}
	}
	return nil
}

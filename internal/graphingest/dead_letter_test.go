package graphingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
)

func TestBuildDeadLetterRecordIncludesReplayEventContext(t *testing.T) {
	evtTime := time.Date(2026, 3, 9, 20, 30, 0, 0, time.UTC)
	evt := events.CloudEvent{
		SpecVersion:     "1.0",
		ID:              "evt-1",
		Source:          "urn:ensemble:tap",
		Type:            "ensemble.tap.github.pull_request.opened",
		Subject:         "repo:core",
		Time:            evtTime,
		DataSchema:      "urn:cerebro:events:v1",
		SchemaVersion:   "v1",
		TenantID:        "tenant-a",
		TraceParent:     "00-abc-xyz-01",
		DataContentType: "application/json",
		Data: map[string]any{
			"repo":   "core",
			"number": 42,
		},
	}

	record := buildDeadLetterRecord(evt, "github_pr", "node", "pull_request:core:42", "pull_request", map[string]any{"id": "pull_request:core:42"}, []graph.SchemaValidationIssue{
		{Code: graph.SchemaIssueMissingRequiredProperty, Message: "missing required property"},
	})
	if record.EventID != evt.ID {
		t.Fatalf("expected event id %q, got %q", evt.ID, record.EventID)
	}
	if record.EventType != evt.Type {
		t.Fatalf("expected event type %q, got %q", evt.Type, record.EventType)
	}
	if record.EventTime.IsZero() {
		t.Fatal("expected event time to be set")
	}
	if got := record.EventData["repo"]; got != "core" {
		t.Fatalf("expected event_data.repo=core, got %#v", got)
	}
	if got := record.EventData["number"]; got != 42 {
		t.Fatalf("expected event_data.number=42, got %#v", got)
	}

	replayEvt, ok := record.ReplayEvent()
	if !ok {
		t.Fatal("expected replay event to be available")
	}
	if replayEvt.ID != evt.ID || replayEvt.Type != evt.Type || replayEvt.Source != evt.Source {
		t.Fatalf("unexpected replay event identity: %#v", replayEvt)
	}
	if replayEvt.TenantID != "tenant-a" {
		t.Fatalf("expected tenant tenant-a, got %q", replayEvt.TenantID)
	}
}

func TestInspectDeadLetterFileTailSummary(t *testing.T) {
	now := time.Date(2026, 3, 9, 21, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "mapper.dlq.jsonl")

	rec1 := DeadLetterRecord{
		RecordedAt:  now.Add(-3 * time.Minute),
		EventID:     "evt-1",
		EventType:   "event.one",
		MappingName: "m1",
		EntityType:  "node",
		EntityKind:  "activity",
		Issues: []graph.SchemaValidationIssue{
			{Code: graph.SchemaIssueUnknownNodeKind, Message: "unknown node kind"},
		},
	}
	rec2 := DeadLetterRecord{
		RecordedAt:  now.Add(-2 * time.Minute),
		EventID:     "evt-2",
		EventType:   "event.two",
		MappingName: "m2",
		EntityType:  "node",
		EntityKind:  "pull_request",
		Issues: []graph.SchemaValidationIssue{
			{Code: graph.SchemaIssueMissingRequiredProperty, Message: "missing required property"},
		},
	}
	rec3 := DeadLetterRecord{
		RecordedAt:  now.Add(-1 * time.Minute),
		EventID:     "evt-3",
		EventType:   "event.three",
		MappingName: "m3",
		EntityType:  "edge",
		EntityKind:  "targets",
		Issues: []graph.SchemaValidationIssue{
			{Code: graph.SchemaIssueRelationshipNotAllowed, Message: "relationship not allowed"},
		},
	}

	writeRecord := func(record DeadLetterRecord) {
		t.Helper()
		payload, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open dead-letter file: %v", err)
		}
		if _, err := file.Write(append(payload, '\n')); err != nil {
			_ = file.Close()
			t.Fatalf("write dead-letter record: %v", err)
		}
		_ = file.Close()
	}

	writeRecord(rec1)
	writeRecord(rec2)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open dead-letter file for invalid line: %v", err)
	}
	if _, err := file.WriteString("this-is-not-json\n"); err != nil {
		_ = file.Close()
		t.Fatalf("append invalid line: %v", err)
	}
	_ = file.Close()
	writeRecord(rec3)

	metrics, err := InspectDeadLetterFile(path, 2)
	if err != nil {
		t.Fatalf("inspect dead-letter file failed: %v", err)
	}
	if !metrics.Exists {
		t.Fatal("expected dead-letter file to exist")
	}
	if metrics.TailLimit != 2 {
		t.Fatalf("expected tail limit 2, got %d", metrics.TailLimit)
	}
	if metrics.TailLines != 2 {
		t.Fatalf("expected 2 tail lines, got %d", metrics.TailLines)
	}
	if metrics.RecordsParsed != 1 {
		t.Fatalf("expected one parsed record in tail, got %d", metrics.RecordsParsed)
	}
	if metrics.ParseErrors != 1 {
		t.Fatalf("expected one parse error in tail, got %d", metrics.ParseErrors)
	}
	if got := metrics.EventTypeCounts["event.three"]; got != 1 {
		t.Fatalf("expected event.three count 1, got %d", got)
	}
	if got := metrics.IssueCodeCounts[string(graph.SchemaIssueRelationshipNotAllowed)]; got != 1 {
		t.Fatalf("expected relationship_not_allowed count 1, got %d", got)
	}
}

func TestInspectDeadLetterFileMissingReturnsExistsFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.dlq.jsonl")
	metrics, err := InspectDeadLetterFile(path, 10)
	if err != nil {
		t.Fatalf("inspect missing dead-letter file failed: %v", err)
	}
	if metrics.Exists {
		t.Fatal("expected exists=false for missing dead-letter file")
	}
}

func TestStreamDeadLetterSkipsInvalidLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream.dlq.jsonl")
	now := time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC)

	validLine := func(id string) []byte {
		t.Helper()
		payload, err := json.Marshal(DeadLetterRecord{
			RecordedAt:  now,
			EventID:     id,
			EventType:   "event.replay",
			MappingName: "m",
			EntityType:  "node",
			EntityID:    id,
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaIssueUnknownNodeKind, Message: "unknown node kind"},
			},
		})
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		return payload
	}

	body := append(validLine("evt-1"), '\n')
	body = append(body, []byte("not-json\n")...)
	body = append(body, '\n')
	body = append(body, validLine("evt-2")...)
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write dead-letter file: %v", err)
	}

	var ids []string
	stats, err := StreamDeadLetter(path, func(record DeadLetterRecord) error {
		ids = append(ids, record.EventID)
		return nil
	})
	if err != nil {
		t.Fatalf("stream dead-letter failed: %v", err)
	}
	if stats.LinesRead != 3 {
		t.Fatalf("expected 3 non-empty lines read, got %d", stats.LinesRead)
	}
	if stats.RecordsParsed != 2 {
		t.Fatalf("expected 2 parsed records, got %d", stats.RecordsParsed)
	}
	if stats.ParseErrors != 1 {
		t.Fatalf("expected 1 parse error, got %d", stats.ParseErrors)
	}
	if len(ids) != 2 || ids[0] != "evt-1" || ids[1] != "evt-2" {
		t.Fatalf("unexpected streamed ids: %#v", ids)
	}
}

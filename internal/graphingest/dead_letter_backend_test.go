package graphingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
)

func TestSQLiteDeadLetterBackend_WriteInspectQuery(t *testing.T) {
	dir := t.TempDir()
	dlqPath := filepath.Join(dir, "mapper.dlq.db")
	now := time.Date(2026, 3, 9, 23, 45, 0, 0, time.UTC)

	sink, err := NewDeadLetterSink(dlqPath)
	if err != nil {
		t.Fatalf("new dead-letter sink failed: %v", err)
	}

	records := []DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-1",
			EventType:   "ensemble.tap.test.invalid",
			MappingName: "invalid_kind",
			EntityType:  "node",
			EntityID:    "node:1",
			EntityKind:  "unknown",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaIssueUnknownNodeKind, Message: "unknown kind"},
			},
		},
		{
			RecordedAt:  now.Add(1 * time.Minute),
			EventID:     "evt-2",
			EventType:   "ensemble.tap.test.invalid",
			MappingName: "invalid_kind",
			EntityType:  "edge",
			EntityID:    "edge:1",
			EntityKind:  "targets",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaIssueInvalidProvenance, Message: "invalid confidence"},
			},
		},
	}
	for _, record := range records {
		if err := sink.WriteDeadLetter(record); err != nil {
			t.Fatalf("write dead-letter record failed: %v", err)
		}
	}

	metrics, err := InspectDeadLetter(dlqPath, 10)
	if err != nil {
		t.Fatalf("inspect dead-letter failed: %v", err)
	}
	if !metrics.Exists {
		t.Fatal("expected sqlite DLQ file to exist")
	}
	if metrics.RecordsParsed != 2 {
		t.Fatalf("expected records_parsed=2, got %d", metrics.RecordsParsed)
	}
	if got := metrics.IssueCodeCounts[string(graph.SchemaIssueUnknownNodeKind)]; got != 1 {
		t.Fatalf("expected unknown_node_kind count 1, got %d", got)
	}

	query, err := QueryDeadLetter(dlqPath, DeadLetterQueryOptions{
		Limit:     10,
		IssueCode: string(graph.SchemaIssueInvalidProvenance),
	})
	if err != nil {
		t.Fatalf("query dead-letter failed: %v", err)
	}
	if query.Total != 1 {
		t.Fatalf("expected one queried record, got %d", query.Total)
	}
	if len(query.Records) != 1 || query.Records[0].EventID != "evt-2" {
		t.Fatalf("unexpected query records: %#v", query.Records)
	}

	scan, err := StreamDeadLetterPath(dlqPath, nil)
	if err != nil {
		t.Fatalf("stream dead-letter failed: %v", err)
	}
	if scan.RecordsParsed != 2 {
		t.Fatalf("expected records_parsed=2, got %#v", scan)
	}
}

func TestQueryDeadLetterFileBackend(t *testing.T) {
	dir := t.TempDir()
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")
	now := time.Date(2026, 3, 9, 23, 50, 0, 0, time.UTC)
	if err := writeDeadLetterFileFixture(dlqPath, []DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-a",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaIssueUnknownNodeKind, Message: "unknown kind"},
			},
		},
		{
			RecordedAt:  now.Add(1 * time.Minute),
			EventID:     "evt-b",
			EventType:   "ensemble.tap.beta",
			MappingName: "map-b",
			EntityType:  "edge",
			EntityKind:  "targets",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaIssueRelationshipNotAllowed, Message: "not allowed"},
			},
		},
	}); err != nil {
		t.Fatalf("write file fixture failed: %v", err)
	}

	result, err := QueryDeadLetter(dlqPath, DeadLetterQueryOptions{
		Limit:      10,
		EntityType: "edge",
	})
	if err != nil {
		t.Fatalf("query dead-letter file failed: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Records) != 1 || result.Records[0].EventID != "evt-b" {
		t.Fatalf("unexpected records: %#v", result.Records)
	}
}

func TestQueryDeadLetterSQLiteIssueCodeFilterEscapesLikeWildcards(t *testing.T) {
	dir := t.TempDir()
	dlqPath := filepath.Join(dir, "mapper.dlq.db")
	now := time.Date(2026, 3, 10, 0, 5, 0, 0, time.UTC)

	sink, err := NewDeadLetterSink(dlqPath)
	if err != nil {
		t.Fatalf("new dead-letter sink failed: %v", err)
	}

	literalCode := "issue_%_literal"
	records := []DeadLetterRecord{
		{
			RecordedAt:  now,
			EventID:     "evt-literal",
			EventType:   "ensemble.tap.test.invalid",
			MappingName: "invalid_kind",
			EntityType:  "node",
			EntityID:    "node:1",
			EntityKind:  "unknown",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaValidationIssueCode(literalCode), Message: "literal code"},
			},
		},
		{
			RecordedAt:  now.Add(1 * time.Minute),
			EventID:     "evt-wildcard-match",
			EventType:   "ensemble.tap.test.invalid",
			MappingName: "invalid_kind",
			EntityType:  "node",
			EntityID:    "node:2",
			EntityKind:  "unknown",
			Issues: []graph.SchemaValidationIssue{
				{Code: graph.SchemaValidationIssueCode("issue_AX_literal"), Message: "should not match"},
			},
		},
	}
	for _, record := range records {
		if err := sink.WriteDeadLetter(record); err != nil {
			t.Fatalf("write dead-letter record failed: %v", err)
		}
	}

	query, err := QueryDeadLetter(dlqPath, DeadLetterQueryOptions{
		Limit:     10,
		IssueCode: literalCode,
	})
	if err != nil {
		t.Fatalf("query dead-letter failed: %v", err)
	}
	if query.Total != 1 {
		t.Fatalf("expected total=1 for literal wildcard issue code, got %d", query.Total)
	}
	if len(query.Records) != 1 || query.Records[0].EventID != "evt-literal" {
		t.Fatalf("unexpected query records: %#v", query.Records)
	}
}

func TestQueryDeadLetterFileBackendPaginationOrder(t *testing.T) {
	dir := t.TempDir()
	dlqPath := filepath.Join(dir, "mapper.dlq.jsonl")
	now := time.Date(2026, 3, 10, 0, 15, 0, 0, time.UTC)
	if err := writeDeadLetterFileFixture(dlqPath, []DeadLetterRecord{
		{
			RecordedAt:  now.Add(2 * time.Minute),
			EventID:     "evt-1",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
		},
		{
			RecordedAt:  now.Add(4 * time.Minute),
			EventID:     "evt-2",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
		},
		{
			RecordedAt:  now.Add(1 * time.Minute),
			EventID:     "evt-3",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
		},
		{
			RecordedAt:  now.Add(3 * time.Minute),
			EventID:     "evt-4",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
		},
		{
			RecordedAt:  now,
			EventID:     "evt-5",
			EventType:   "ensemble.tap.alpha",
			MappingName: "map-a",
			EntityType:  "node",
			EntityKind:  "service",
		},
	}); err != nil {
		t.Fatalf("write file fixture failed: %v", err)
	}

	result, err := QueryDeadLetter(dlqPath, DeadLetterQueryOptions{
		Limit:     2,
		Offset:    1,
		EventType: "ensemble.tap.alpha",
	})
	if err != nil {
		t.Fatalf("query dead-letter file failed: %v", err)
	}
	if result.Total != 5 {
		t.Fatalf("expected total=5, got %d", result.Total)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %#v", result.Records)
	}
	if result.Records[0].EventID != "evt-4" || result.Records[1].EventID != "evt-1" {
		t.Fatalf("unexpected page order: %#v", result.Records)
	}
}

func writeDeadLetterFileFixture(path string, records []DeadLetterRecord) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	for _, record := range records {
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
	}
	return nil
}

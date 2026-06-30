package postgres

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAppendLogDeadLetterSchemaShape(t *testing.T) {
	joined := strings.Join(ensureAppendLogDeadLetterStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS append_log_dead_letters",
		"id TEXT PRIMARY KEY",
		"status TEXT NOT NULL",
		"subject TEXT NOT NULL",
		"runtime_id TEXT NOT NULL DEFAULT ''",
		"job_id TEXT NOT NULL DEFAULT ''",
		"event_json JSONB NOT NULL",
		"append_log_dead_letters_status_updated_idx",
		"append_log_dead_letters_subject_status_idx",
		"append_log_dead_letters_runtime_status_idx",
		"append_log_dead_letters_source_status_idx",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("append log dead letter schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestAppendLogDeadLetterListQueryDefaultsToPending(t *testing.T) {
	query, args := appendLogDeadLetterListQuery(ports.AppendLogDeadLetterFilter{})
	for _, fragment := range []string{
		"WHERE status = $1",
		"ORDER BY updated_at ASC, id ASC LIMIT $2",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("appendLogDeadLetterListQuery() = %q, missing %q", query, fragment)
		}
	}
	if len(args) != 2 || args[0] != ports.AppendLogDeadLetterStatusPending || args[1] != int64(appendLogDeadLetterDefaultLimit) {
		t.Fatalf("query args = %#v, want pending and default limit", args)
	}
}

func TestAppendLogDeadLetterListQueryBoundsFilters(t *testing.T) {
	query, args := appendLogDeadLetterListQuery(ports.AppendLogDeadLetterFilter{
		Status:    "all",
		Subject:   " sec.findings.v1.recorded ",
		RuntimeID: " runtime-1 ",
		SourceID:  " github ",
		Limit:     1000,
	})
	if strings.Contains(query, "status =") {
		t.Fatalf("query with status=all should not include status predicate: %q", query)
	}
	for _, fragment := range []string{
		"subject = $1",
		"runtime_id = $2",
		"source_id = $3",
		"LIMIT $4",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("appendLogDeadLetterListQuery() = %q, missing %q", query, fragment)
		}
	}
	if len(args) != 4 || args[0] != "sec.findings.v1.recorded" || args[1] != "runtime-1" || args[2] != "github" || args[3] != int64(appendLogDeadLetterMaxLimit) {
		t.Fatalf("query args = %#v, want trimmed filters and capped limit", args)
	}
}

func TestValidateAppendLogDeadLetterRequiresReplayableEvent(t *testing.T) {
	record := normalizeAppendLogDeadLetter(ports.AppendLogDeadLetter{
		ID:          " apdl_1 ",
		Subject:     " sec.findings.v1.recorded ",
		EventID:     " event-1 ",
		EventKind:   " sec.findings.v1.recorded ",
		PayloadHash: " hash ",
		Event:       &cerebrov1.EventEnvelope{Id: "event-1"},
	})
	if err := validateAppendLogDeadLetter(record); err != nil {
		t.Fatalf("validateAppendLogDeadLetter() error = %v", err)
	}
	record.Event = nil
	if err := validateAppendLogDeadLetter(record); err == nil {
		t.Fatal("validateAppendLogDeadLetter() error = nil, want missing event error")
	}
}

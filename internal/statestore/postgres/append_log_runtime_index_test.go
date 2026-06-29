package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestPutRuntimeIndexEntriesRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if err := store.PutRuntimeIndexEntries(context.Background(), nil, 0); err == nil {
		t.Fatal("PutRuntimeIndexEntries() error = nil, want non-nil")
	}
}

func TestRuntimeIndexWatermarkRejectsUnconfiguredStore(t *testing.T) {
	store := &Store{}
	if _, err := store.RuntimeIndexWatermark(context.Background()); err == nil {
		t.Fatal("RuntimeIndexWatermark() error = nil, want non-nil")
	}
}

func TestLookupRuntimeReplayRejectsMissingRuntimeID(t *testing.T) {
	store := &Store{}
	if _, err := store.LookupRuntimeReplay(context.Background(), ports.RuntimeIndexQuery{RuntimeID: "  "}); err == nil {
		t.Fatal("LookupRuntimeReplay() error = nil, want non-nil for missing runtime id")
	}
}

func TestAppendLogRuntimeIndexSchemaShape(t *testing.T) {
	joined := strings.Join(ensureAppendLogRuntimeIndexStatements, "\n")
	for _, fragment := range []string{
		"CREATE TABLE IF NOT EXISTS append_log_runtime_index",
		"PRIMARY KEY (runtime_id, seq)",
		"append_log_runtime_index_runtime_observed_idx",
		"(runtime_id, occurred_at DESC NULLS LAST, seq DESC)",
		"append_log_runtime_index_runtime_kind_observed_idx",
		"(runtime_id, kind, occurred_at DESC NULLS LAST, seq DESC)",
		"CREATE TABLE IF NOT EXISTS append_log_index_state",
		"indexer TEXT PRIMARY KEY",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("append log runtime index schema missing %q:\n%s", fragment, joined)
		}
	}
}

func TestRuntimeReplayIndexQueryWithoutKinds(t *testing.T) {
	statement, args := runtimeReplayIndexQuery("writer-okta", nil, 42, 100)
	for _, fragment := range []string{
		"WHERE runtime_id = $1 AND seq <= $2",
		"ORDER BY occurred_at DESC NULLS LAST, seq DESC LIMIT $3",
	} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("runtimeReplayIndexQuery() = %q, missing %q", statement, fragment)
		}
	}
	if strings.Contains(statement, "kind IN") {
		t.Fatalf("runtimeReplayIndexQuery() unexpectedly filtered by kind: %q", statement)
	}
	if len(args) != 3 {
		t.Fatalf("runtimeReplayIndexQuery() args = %#v, want runtime, watermark, limit", args)
	}
	if got, ok := args[0].(string); !ok || got != "writer-okta" {
		t.Fatalf("runtimeReplayIndexQuery() args[0] = %#v, want runtime id", args[0])
	}
	if got, ok := args[1].(int64); !ok || got != 42 {
		t.Fatalf("runtimeReplayIndexQuery() args[1] = %#v, want watermark 42", args[1])
	}
	if got, ok := args[2].(int64); !ok || got != 100 {
		t.Fatalf("runtimeReplayIndexQuery() args[2] = %#v, want limit 100", args[2])
	}
}

func TestRuntimeReplayIndexQueryWithKinds(t *testing.T) {
	statement, args := runtimeReplayIndexQuery("writer-okta", []string{"okta.policy_rule", " ", "okta.policy_rule", "duo.user"}, 7, 25)
	if !strings.Contains(statement, "AND kind IN ($3, $4)") {
		t.Fatalf("runtimeReplayIndexQuery() = %q, want deduplicated kind IN ($3, $4)", statement)
	}
	if !strings.Contains(statement, "ORDER BY occurred_at DESC NULLS LAST, seq DESC LIMIT $5") {
		t.Fatalf("runtimeReplayIndexQuery() = %q, want LIMIT placeholder after kinds", statement)
	}
	if len(args) != 5 {
		t.Fatalf("runtimeReplayIndexQuery() args = %#v, want runtime, watermark, 2 kinds, limit", args)
	}
	if got, ok := args[2].(string); !ok || got != "okta.policy_rule" {
		t.Fatalf("runtimeReplayIndexQuery() args[2] = %#v, want first kind", args[2])
	}
	if got, ok := args[4].(int64); !ok || got != 25 {
		t.Fatalf("runtimeReplayIndexQuery() args[4] = %#v, want limit 25", args[4])
	}
}

func TestBoundedInt64Caps(t *testing.T) {
	if got := boundedInt64(123); got != 123 {
		t.Fatalf("boundedInt64(123) = %d, want 123", got)
	}
	if got := boundedInt64(^uint64(0)); got <= 0 {
		t.Fatalf("boundedInt64(maxuint64) = %d, want positive cap", got)
	}
}

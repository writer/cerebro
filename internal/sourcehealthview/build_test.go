package sourcehealthview

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGraphRunFromStore(t *testing.T) {
	run := graphstore.IngestRun{
		ID: "run-1", Status: "completed", CheckpointCursor: "cursor-1",
		CheckpointComplete: true, CheckpointCompleteKnown: true,
		StartedAt: "2026-05-01T00:00:00Z", FinishedAt: "2026-05-01T00:00:30Z",
		PagesRead: 2, EventsRead: 10, EntitiesProjected: 5, LinksProjected: 3,
		IngestRunGraphCounts: graphstore.IngestRunGraphCounts{
			GraphNodesBefore: 100, GraphNodesAfter: 110, GraphLinksBefore: 50, GraphLinksAfter: 47,
		},
	}
	got := GraphRunFromStore(run)
	if got.ID != "run-1" || got.Status != "completed" {
		t.Fatalf("unexpected id/status: %#v", got)
	}
	if got.CheckpointComplete == nil || !*got.CheckpointComplete {
		t.Errorf("CheckpointComplete = %v, want true", got.CheckpointComplete)
	}
	if got.GraphNodeDelta != 10 {
		t.Errorf("GraphNodeDelta = %d, want 10", got.GraphNodeDelta)
	}
	if got.GraphLinkDelta != -3 {
		t.Errorf("GraphLinkDelta = %d, want -3", got.GraphLinkDelta)
	}
	if got.DurationSeconds == nil || *got.DurationSeconds != 30 {
		t.Errorf("DurationSeconds = %v, want 30", got.DurationSeconds)
	}
}

func TestGraphRunFromStoreLegacyCheckpointUnknown(t *testing.T) {
	got := GraphRunFromStore(graphstore.IngestRun{ID: "run-2", CheckpointComplete: true})
	if got.CheckpointComplete != nil {
		t.Errorf("CheckpointComplete = %v, want nil for legacy run", got.CheckpointComplete)
	}
	if got.DurationSeconds != nil {
		t.Errorf("DurationSeconds = %v, want nil for unparsable timestamps", got.DurationSeconds)
	}
}

func TestFindingEvaluationFromRun(t *testing.T) {
	if got := FindingEvaluationFromRun(nil); got != nil {
		t.Fatalf("FindingEvaluationFromRun(nil) = %#v, want nil", got)
	}
	run := &cerebrov1.FindingEvaluationRun{
		Id: "eval-1", RuntimeId: "runtime-1", RuleId: "rule-1", Status: "completed",
		StartedAt:       timestamppb.New(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)),
		FinishedAt:      timestamppb.New(time.Date(2026, 5, 1, 0, 0, 45, 0, time.UTC)),
		EventsEvaluated: 20, EventsProcessed: 18, EventsMatched: 4,
		FindingsUpserted: 2, FindingsEmitted: 1,
		GraphRule: proto.Bool(true), GraphRowsRead: proto.Uint32(7),
	}
	got := FindingEvaluationFromRun(run)
	if got.ID != "eval-1" || got.RuntimeID != "runtime-1" || got.RuleID != "rule-1" {
		t.Fatalf("unexpected identity fields: %#v", got)
	}
	if got.GraphRowsRead != 7 {
		t.Errorf("GraphRowsRead = %d, want 7", got.GraphRowsRead)
	}
	if got.GraphRule == nil || !*got.GraphRule {
		t.Errorf("GraphRule = %v, want true", got.GraphRule)
	}
	if got.DurationSeconds == nil || *got.DurationSeconds != 45 {
		t.Errorf("DurationSeconds = %v, want 45", got.DurationSeconds)
	}
	if got.StartedAt == "" || got.FinishedAt == "" {
		t.Errorf("timestamps not formatted: %#v", got)
	}
}

func TestFindingEvaluationFromRunNoGraphRows(t *testing.T) {
	got := FindingEvaluationFromRun(&cerebrov1.FindingEvaluationRun{Id: "eval-2"})
	if got.GraphRowsRead != 0 {
		t.Errorf("GraphRowsRead = %d, want 0", got.GraphRowsRead)
	}
	if got.DurationSeconds != nil {
		t.Errorf("DurationSeconds = %v, want nil", got.DurationSeconds)
	}
}

func TestSyncFromRuntime(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Config: map[string]string{
		"__cerebro_runtime_records_scanned":    "100",
		"__cerebro_runtime_records_accepted":   "90",
		"__cerebro_runtime_records_rejected":   "10",
		"__cerebro_runtime_entities_projected": "40",
		"__cerebro_runtime_links_projected":    "20",
	}}
	got := syncFromRuntime(runtime)
	want := Sync{RecordsScanned: 100, RecordsAccepted: 90, RecordsRejected: 10, EntitiesProjected: 40, LinksProjected: 20}
	if got != want {
		t.Errorf("syncFromRuntime() = %#v, want %#v", got, want)
	}
}

func TestConfigUint32(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Config: map[string]string{"good": " 42 ", "bad": "notanumber", "neg": "-1"}}
	cases := []struct {
		key  string
		want uint32
	}{
		{"good", 42},
		{"bad", 0},
		{"neg", 0},
		{"missing", 0},
	}
	for _, tc := range cases {
		if got := configUint32(runtime, tc.key); got != tc.want {
			t.Errorf("configUint32(%q) = %d, want %d", tc.key, got, tc.want)
		}
	}
	if got := configUint32(nil, "good"); got != 0 {
		t.Errorf("configUint32(nil) = %d, want 0", got)
	}
}

func TestTimestampValueAndString(t *testing.T) {
	if !timestampValue(nil).IsZero() {
		t.Error("timestampValue(nil) should be zero")
	}
	if !timestampValue(&timestamppb.Timestamp{}).IsZero() {
		t.Error("timestampValue(zero) should be zero")
	}
	ts := timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if timestampValue(ts).IsZero() {
		t.Error("timestampValue(valid) should not be zero")
	}
	if timestampString(nil) != "" {
		t.Error("timestampString(nil) should be empty")
	}
	if got := timestampString(ts); got != "2026-05-01T12:00:00Z" {
		t.Errorf("timestampString() = %q", got)
	}
}

func TestDurationSeconds(t *testing.T) {
	if got := durationSeconds("2026-05-01T00:00:00Z", "2026-05-01T00:01:00Z"); got == nil || *got != 60 {
		t.Errorf("durationSeconds() = %v, want 60", got)
	}
	if durationSeconds("bad", "2026-05-01T00:01:00Z") != nil {
		t.Error("durationSeconds with bad start should be nil")
	}
	if durationSeconds("2026-05-01T00:00:00Z", "bad") != nil {
		t.Error("durationSeconds with bad finish should be nil")
	}
	// Negative durations clamp to zero.
	if got := durationSeconds("2026-05-01T00:01:00Z", "2026-05-01T00:00:00Z"); got == nil || *got != 0 {
		t.Errorf("durationSeconds() = %v, want 0 (clamped)", got)
	}
}

func TestGraphRunLagSeconds(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 2, 0, 0, time.UTC)
	// Prefers FinishedAt.
	if got := graphRunLagSeconds(now, graphstore.IngestRun{StartedAt: "2026-05-01T00:00:00Z", FinishedAt: "2026-05-01T00:01:00Z"}); got == nil || *got != 60 {
		t.Errorf("graphRunLagSeconds() = %v, want 60 from finished", got)
	}
	// Falls back to StartedAt.
	if got := graphRunLagSeconds(now, graphstore.IngestRun{StartedAt: "2026-05-01T00:00:00Z"}); got == nil || *got != 120 {
		t.Errorf("graphRunLagSeconds() = %v, want 120 from started", got)
	}
	// No parseable timestamps.
	if graphRunLagSeconds(now, graphstore.IngestRun{}) != nil {
		t.Error("graphRunLagSeconds with no timestamps should be nil")
	}
}

func TestNonnegativeSeconds(t *testing.T) {
	if got := nonnegativeSeconds(90 * time.Second); got == nil || *got != 90 {
		t.Errorf("nonnegativeSeconds(90s) = %v, want 90", got)
	}
	if got := nonnegativeSeconds(-5 * time.Second); got == nil || *got != 0 {
		t.Errorf("nonnegativeSeconds(-5s) = %v, want 0", got)
	}
}

func TestTimestampDurationSeconds(t *testing.T) {
	start := timestamppb.New(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	finish := timestamppb.New(time.Date(2026, 5, 1, 0, 0, 15, 0, time.UTC))
	if got := timestampDurationSeconds(start, finish); got == nil || *got != 15 {
		t.Errorf("timestampDurationSeconds() = %v, want 15", got)
	}
	if timestampDurationSeconds(nil, finish) != nil {
		t.Error("timestampDurationSeconds with nil start should be nil")
	}
	if timestampDurationSeconds(start, nil) != nil {
		t.Error("timestampDurationSeconds with nil finish should be nil")
	}
}

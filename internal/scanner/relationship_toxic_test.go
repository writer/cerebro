package scanner

import (
	"strings"
	"testing"
	"time"
)

// --- toxicSinceFilter tests ---

func TestToxicSinceFilter_NilCursor(t *testing.T) {
	if got := toxicSinceFilter("s", nil); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestToxicSinceFilter_ZeroTime(t *testing.T) {
	c := &ToxicScanCursor{}
	if got := toxicSinceFilter("b", c); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestToxicSinceFilter_TimeOnly_StrictGT(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts}
	got := toxicSinceFilter("s", c)
	if !strings.Contains(got, "s._cq_sync_time > '") {
		t.Errorf("time-only cursor must use strict >, got %q", got)
	}
	if strings.Contains(got, ">=") {
		t.Errorf("time-only cursor must NOT use >=, got %q", got)
	}
	if !strings.Contains(got, "2026-01-15") {
		t.Errorf("expected date in clause, got %q", got)
	}
}

func TestToxicSinceFilter_WithID_UsesGTE(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts, SinceID: "res-abc"}
	got := toxicSinceFilter("s", c)
	if !strings.Contains(got, "s._cq_sync_time >= '") {
		t.Errorf("cursor with ID must use >= to preserve boundary rows, got %q", got)
	}
}

func TestToxicSinceFilter_EmptyAlias(t *testing.T) {
	ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts}
	got := toxicSinceFilter("", c)
	if !strings.Contains(got, "AND _cq_sync_time > '") {
		t.Errorf("expected unqualified strict > filter, got %q", got)
	}
	if strings.Contains(got, "._cq_sync_time") {
		t.Errorf("empty alias should not produce dot-qualified column, got %q", got)
	}
}

func TestToxicSinceFilter_EmptyAlias_WithID_UsesGTE(t *testing.T) {
	ts := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts, SinceID: "xyz"}
	got := toxicSinceFilter("", c)
	if !strings.Contains(got, "AND _cq_sync_time >= '") {
		t.Errorf("cursor with ID must use >= even without alias, got %q", got)
	}
}

func TestToxicSinceFilter_DifferentAliases(t *testing.T) {
	ts := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts}
	for _, alias := range []string{"s", "b", "r", "r_sa"} {
		got := toxicSinceFilter(alias, c)
		expect := alias + "._cq_sync_time"
		if !strings.Contains(got, expect) {
			t.Errorf("alias=%q: expected %q in clause, got %q", alias, expect, got)
		}
	}
}

func TestToxicSinceFilterColumn_CustomColumn(t *testing.T) {
	ts := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts}

	got := toxicSinceFilterColumn("r_sa", "sync_time", c)
	if !strings.Contains(got, "r_sa.sync_time > '") {
		t.Fatalf("expected custom sync_time column, got %q", got)
	}

	gotNoAlias := toxicSinceFilterColumn("", "sync_time", c)
	if !strings.Contains(gotNoAlias, "AND sync_time > '") {
		t.Fatalf("expected unqualified sync_time column, got %q", gotNoAlias)
	}
}

func TestToxicSinceFilter_BoundaryPreservation(t *testing.T) {
	// With SinceID: CTE must keep rows at exact SinceTime (>=),
	// final keyset WHERE then eliminates already-seen IDs.
	ts := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	withID := &ToxicScanCursor{SinceTime: ts, SinceID: "boundary-resource"}
	withoutID := &ToxicScanCursor{SinceTime: ts}

	gotWith := toxicSinceFilter("b", withID)
	gotWithout := toxicSinceFilter("b", withoutID)

	if !strings.Contains(gotWith, ">= '") {
		t.Errorf("with ID: pushdown must use >=, got %q", gotWith)
	}
	if !strings.Contains(gotWithout, "> '") || strings.Contains(gotWithout, ">= '") {
		t.Errorf("without ID: pushdown must use strict >, got %q", gotWithout)
	}
}

// --- toxicKeysetWhere tests ---

func TestToxicKeysetWhere_NilCursor(t *testing.T) {
	if got := toxicKeysetWhere(nil); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestToxicKeysetWhere_ZeroTime(t *testing.T) {
	c := &ToxicScanCursor{}
	if got := toxicKeysetWhere(c); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestToxicKeysetWhere_TimeOnly(t *testing.T) {
	ts := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts}
	got := toxicKeysetWhere(c)
	if !strings.Contains(got, "WHERE t._row_sync_time >") {
		t.Errorf("expected time-only WHERE, got %q", got)
	}
	if strings.Contains(got, "resource_id") {
		t.Errorf("time-only cursor should not reference resource_id, got %q", got)
	}
}

func TestToxicKeysetWhere_WithID(t *testing.T) {
	ts := time.Date(2026, 4, 15, 6, 30, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts, SinceID: "arn:aws:iam::123:role/test"}
	got := toxicKeysetWhere(c)
	if !strings.Contains(got, "t._row_sync_time >") {
		t.Errorf("keyset should contain time > clause, got %q", got)
	}
	if !strings.Contains(got, "t._row_sync_time =") {
		t.Errorf("keyset should contain time = clause, got %q", got)
	}
	if !strings.Contains(got, "t.resource_id > 'arn:aws:iam::123:role/test'") {
		t.Errorf("keyset should contain id > clause, got %q", got)
	}
	if !strings.Contains(got, " OR ") {
		t.Errorf("keyset should use OR between time-only and tiebreak, got %q", got)
	}
}

func TestToxicKeysetWhere_EscapesSingleQuoteInID(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts, SinceID: "it's-a-test"}
	got := toxicKeysetWhere(c)
	if strings.Contains(got, "it's") {
		t.Errorf("single quote should be escaped, got %q", got)
	}
	if !strings.Contains(got, "it''s-a-test") {
		t.Errorf("expected SQL-escaped quote, got %q", got)
	}
}

func TestToxicKeysetWhere_SameTimestampBoundary(t *testing.T) {
	ts := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	c := &ToxicScanCursor{SinceTime: ts, SinceID: "resource-mmm"}
	got := toxicKeysetWhere(c)

	// Must have the shape: (time > T OR (time = T AND id > ID))
	tsStr := ts.UTC().Format(time.RFC3339Nano)
	expectGT := "t._row_sync_time > '" + tsStr + "'"
	expectEQ := "t._row_sync_time = '" + tsStr + "'"
	expectID := "t.resource_id > 'resource-mmm'"

	if !strings.Contains(got, expectGT) {
		t.Errorf("missing time > clause:\n  want substring: %s\n  got: %s", expectGT, got)
	}
	if !strings.Contains(got, expectEQ) {
		t.Errorf("missing time = clause:\n  want substring: %s\n  got: %s", expectEQ, got)
	}
	if !strings.Contains(got, expectID) {
		t.Errorf("missing id > clause:\n  want substring: %s\n  got: %s", expectID, got)
	}
}

// --- extractToxicCursor tests ---

func TestExtractToxicCursor_Empty(t *testing.T) {
	ts, id := extractToxicCursor(nil)
	if !ts.IsZero() {
		t.Errorf("expected zero time, got %v", ts)
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestExtractToxicCursor_ReturnsMax(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rows := []map[string]interface{}{
		{"_max_sync_time": t1, "_max_cursor_id": "r-aaa", "severity": "HIGH"},
		{"_max_sync_time": t2, "_max_cursor_id": "r-zzz", "severity": "CRITICAL"},
	}
	ts, id := extractToxicCursor(rows)
	if !ts.Equal(t2) {
		t.Errorf("expected %v, got %v", t2, ts)
	}
	if id != "r-zzz" {
		t.Errorf("expected r-zzz, got %q", id)
	}
}

func TestExtractToxicCursor_StringTime(t *testing.T) {
	rows := []map[string]interface{}{
		{"_max_sync_time": "2026-06-15T12:00:00Z", "_max_cursor_id": "res-1"},
	}
	ts, id := extractToxicCursor(rows)
	expected := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if !ts.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, ts)
	}
	if id != "res-1" {
		t.Errorf("expected res-1, got %q", id)
	}
}

func TestExtractToxicCursor_SameTimeDifferentIDs(t *testing.T) {
	ts := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	rows := []map[string]interface{}{
		{"_max_sync_time": ts, "_max_cursor_id": "arn:aws:iam::123:role/alpha"},
		{"_max_sync_time": ts, "_max_cursor_id": "arn:aws:iam::123:role/zeta"},
	}
	_, id := extractToxicCursor(rows)
	if id != "arn:aws:iam::123:role/zeta" {
		t.Errorf("expected lexicographically greatest id, got %q", id)
	}
}

// --- DetectRelationshipToxicCombinations nil-SF tests ---

func TestToxicDetectionResult_NilSF(t *testing.T) {
	result, err := DetectRelationshipToxicCombinations(nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if !result.MaxSyncTime.IsZero() {
		t.Errorf("expected zero MaxSyncTime, got %v", result.MaxSyncTime)
	}
	if result.MaxCursorID != "" {
		t.Errorf("expected empty MaxCursorID, got %q", result.MaxCursorID)
	}
}

func TestToxicDetectionResult_NilSF_NoWatermarkAdvance(t *testing.T) {
	result, _ := DetectRelationshipToxicCombinations(nil, nil, nil)
	if !result.MaxSyncTime.IsZero() {
		t.Fatal("zero-result scan must not produce a data cursor")
	}
}

func TestToxicDetectionResult_NilSF_WithCursor(t *testing.T) {
	cursor := &ToxicScanCursor{
		SinceTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SinceID:   "prev-resource",
	}
	result, err := DetectRelationshipToxicCombinations(nil, nil, cursor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.MaxSyncTime.IsZero() {
		t.Error("nil sf should return zero cursor regardless of input")
	}
}

// --- Cursor data-derived tests ---

func TestToxicCursor_DataDerived(t *testing.T) {
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	rows := []map[string]interface{}{
		{
			"severity":       "CRITICAL",
			"policy_id":      "toxic-1",
			"resource_id":    "svc-a",
			"_max_sync_time": ts,
			"_max_cursor_id": "svc-b",
		},
		{
			"severity":       "HIGH",
			"policy_id":      "toxic-2",
			"resource_id":    "svc-b",
			"_max_sync_time": ts,
			"_max_cursor_id": "svc-b",
		},
	}
	cursorTime, cursorID := extractToxicCursor(rows)
	if !cursorTime.Equal(ts) {
		t.Errorf("cursor time = %v, want %v", cursorTime, ts)
	}
	if cursorID != "svc-b" {
		t.Errorf("cursor id = %q, want %q", cursorID, "svc-b")
	}
}

// --- End-to-end cursor consumption ---

func TestCursorRoundTrip_StoredCursorUsedOnNextRun(t *testing.T) {
	ts := time.Date(2026, 5, 10, 8, 0, 0, 0, time.UTC)
	cursorID := "arn:aws:iam::999:role/omega"

	// Simulate storing a cursor from a previous run's result
	wm := NewWatermarkStore(nil)
	wm.SetWatermark("_toxic_relationships", ts, cursorID, 3)

	// Simulate reading it back on next run (matches call-site logic)
	stored := wm.GetWatermark("_toxic_relationships")
	if stored == nil {
		t.Fatal("expected watermark")
	}
	cursor := &ToxicScanCursor{SinceTime: stored.LastScanTime, SinceID: stored.LastScanID}

	if !cursor.SinceTime.Equal(ts) {
		t.Errorf("cursor time = %v, want %v", cursor.SinceTime, ts)
	}
	if cursor.SinceID != cursorID {
		t.Errorf("cursor id = %q, want %q", cursor.SinceID, cursorID)
	}

	// Verify the CTE pushdown uses >= (cursor has ID, so boundary rows preserved)
	filter := toxicSinceFilter("s", cursor)
	if !strings.Contains(filter, "s._cq_sync_time >= '") {
		t.Errorf("pushdown with ID must use >=, got %q", filter)
	}
	if !strings.Contains(filter, "2026-05-10") {
		t.Errorf("filter should contain stored time, got %q", filter)
	}

	// Verify the keyset WHERE uses both time and ID
	keyset := toxicKeysetWhere(cursor)
	if !strings.Contains(keyset, "2026-05-10") {
		t.Errorf("keyset should contain stored time, got %q", keyset)
	}
	if !strings.Contains(keyset, cursorID) {
		t.Errorf("keyset should contain stored cursor ID %q, got %q", cursorID, keyset)
	}
	if !strings.Contains(keyset, "t.resource_id >") {
		t.Errorf("keyset should reference t.resource_id for tiebreak, got %q", keyset)
	}
}

// --- MapRelationshipToxicRows tests ---

func TestMapRelationshipToxicRows_Empty(t *testing.T) {
	rows := MapRelationshipToxicRows(nil)
	if len(rows) != 0 {
		t.Errorf("expected 0 findings, got %d", len(rows))
	}
}

func TestMapRelationshipToxicRows_SkipsEmptyPolicyAndSeverity(t *testing.T) {
	rows := []map[string]interface{}{
		{"severity": "CRITICAL", "policy_id": "toxic-1", "resource_id": "r1"},
		{"severity": "", "policy_id": "", "resource_id": "r2"},
	}
	findings := MapRelationshipToxicRows(rows)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

package sourcecdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

func TestCursorFeedPageDecodesFromJSON(t *testing.T) {
	var page CursorFeedPage
	body := []byte(`{"items":[{"id":"a"},{"id":"b"}],"nextCursor":"next","hasMore":true}`)
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2", len(page.Items))
	}
	if page.NextCursor != "next" || !page.HasMore {
		t.Fatalf("page = %+v, want nextCursor=next hasMore=true", page)
	}
}

func TestCursorFeedPageNextOpaqueCursorStopsWhenHasMoreFalse(t *testing.T) {
	page := CursorFeedPage{NextCursor: "stale", HasMore: false}
	if got := page.NextOpaqueCursor(); got != "" {
		t.Fatalf("NextOpaqueCursor() = %q, want empty when HasMore is false", got)
	}
}

func TestCursorFeedPageNextOpaqueCursorContinuesOnEmptyPageWithHasMore(t *testing.T) {
	page := CursorFeedPage{NextCursor: "page-2", HasMore: true}
	if got := page.NextOpaqueCursor(); got != "page-2" {
		t.Fatalf("NextOpaqueCursor() = %q, want page-2 even with zero items", got)
	}
}

func TestCursorFeedQueryIncludesFixedParamsLimitAndCursor(t *testing.T) {
	query := CursorFeedQuery(map[string]string{"source": "cloud_identity"}, 50, "cursor-1")
	if got := query.Get("source"); got != "cloud_identity" {
		t.Fatalf("source = %q, want cloud_identity", got)
	}
	if got := query.Get("limit"); got != "50" {
		t.Fatalf("limit = %q, want 50", got)
	}
	if got := query.Get("cursor"); got != "cursor-1" {
		t.Fatalf("cursor = %q, want cursor-1", got)
	}
}

func TestCursorFeedQueryOmitsEmptyCursor(t *testing.T) {
	query := CursorFeedQuery(nil, 10, "")
	if query.Has("cursor") {
		t.Fatal("cursor present, want omitted when empty")
	}
}

func TestClampPageSize(t *testing.T) {
	cases := []struct {
		pageSize int
		max      int
		want     int
	}{
		{pageSize: 0, max: 200, want: 200},
		{pageSize: -5, max: 200, want: 200},
		{pageSize: 500, max: 200, want: 200},
		{pageSize: 50, max: 200, want: 50},
	}
	for _, tc := range cases {
		if got := ClampPageSize(tc.pageSize, tc.max); got != tc.want {
			t.Fatalf("ClampPageSize(%d, %d) = %d, want %d", tc.pageSize, tc.max, got, tc.want)
		}
	}
}

// TestCursorFeedCheckpointPullTerminalPageKeepsResumableCheckpoint pins the
// cursor-feed contract: a terminal (HasMore:false) page still returns a
// resumable checkpoint carrying the provider's raw nextCursor as Token, but
// no in-sync continuation cursor.
func TestCursorFeedCheckpointPullTerminalPageKeepsResumableCheckpoint(t *testing.T) {
	page := CursorFeedPage{NextCursor: "terminal-cursor-token", HasMore: false}
	pull, err := CursorFeedCheckpointPull("acme", "widgets", []string{"a"}, page, nil, func(rec string) (*primitives.Event, error) {
		return &primitives.Event{OccurredAt: nil}, nil
	})
	if err != nil {
		t.Fatalf("CursorFeedCheckpointPull() error = %v", err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("pull.NextCursor = %v, want nil (HasMore=false)", pull.NextCursor)
	}
	if pull.Checkpoint == nil {
		t.Fatal("pull.Checkpoint = nil, want a checkpoint even for a terminal page")
	}
	envelope, ok := DecodeCursorEnvelope(pull.Checkpoint.GetCursorOpaque())
	if !ok || !envelope.ResumableCheckpoint {
		t.Fatalf("pull.Checkpoint.CursorOpaque = %q, want a resumable envelope", pull.Checkpoint.GetCursorOpaque())
	}
	if envelope.Token != "terminal-cursor-token" {
		t.Fatalf("envelope.Token = %q, want terminal-cursor-token", envelope.Token)
	}
}

// TestCursorFeedCheckpointPullEmptyTerminalPageKeepsCursorAndWatermark pins
// the empty-page checkpointing contract: an empty, HasMore=false page must
// still return a resumable checkpoint carrying the provider's (possibly
// unchanged) terminal cursor, and must never regress a watermark already
// established by a prior checkpoint.
func TestCursorFeedCheckpointPullEmptyTerminalPageKeepsCursorAndWatermark(t *testing.T) {
	priorWatermark, err := time.Parse(time.RFC3339, "2026-06-15T12:00:00Z")
	if err != nil {
		t.Fatalf("time.Parse() error = %v", err)
	}
	priorEnvelope := CursorEnvelope{ResumableCheckpoint: true, Token: "prior-cursor"} // #nosec G101 -- pagination cursor token, not credential material.
	SetCursorWatermark(&priorEnvelope, priorWatermark)
	priorOpaque, err := EncodeCursorEnvelope(priorEnvelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	prior := &cerebrov1.SourceCheckpoint{CursorOpaque: priorOpaque}

	page := CursorFeedPage{NextCursor: "next-cursor", HasMore: false}
	pull, err := CursorFeedCheckpointPull("acme", "widgets", []string(nil), page, prior, func(rec string) (*primitives.Event, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("CursorFeedCheckpointPull() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(pull.Events) = %d, want 0", len(pull.Events))
	}
	envelope, ok := DecodeCursorEnvelope(pull.Checkpoint.GetCursorOpaque())
	if !ok || !envelope.ResumableCheckpoint || envelope.Token != "next-cursor" {
		t.Fatalf("envelope = %+v ok=%t, want a resumable envelope carrying next-cursor", envelope, ok)
	}
	if got := pull.Checkpoint.GetWatermark().AsTime().UTC().Format(time.RFC3339); got != "2026-06-15T12:00:00Z" {
		t.Fatalf("checkpoint watermark = %v, want 2026-06-15T12:00:00Z preserved from the prior checkpoint", got)
	}
}

// TestCursorFeedCheckpointPullNextCursorOnlyWhenHasMore pins that
// Pull.NextCursor -- the in-sync continuation cursor -- is populated only
// when the page reports HasMore, independent of the always-present
// resumable checkpoint.
func TestCursorFeedCheckpointPullNextCursorOnlyWhenHasMore(t *testing.T) {
	build := func(rec string) (*primitives.Event, error) { return &primitives.Event{}, nil }

	more := CursorFeedPage{NextCursor: "page-2", HasMore: true}
	pull, err := CursorFeedCheckpointPull("acme", "widgets", []string{"a"}, more, nil, build)
	if err != nil {
		t.Fatalf("CursorFeedCheckpointPull() error = %v", err)
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("pull.NextCursor = %v, want opaque page-2 when HasMore=true", pull.NextCursor)
	}

	terminal := CursorFeedPage{NextCursor: "page-2", HasMore: false}
	pull, err = CursorFeedCheckpointPull("acme", "widgets", []string{"a"}, terminal, nil, build)
	if err != nil {
		t.Fatalf("CursorFeedCheckpointPull() error = %v", err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("pull.NextCursor = %v, want nil when HasMore=false even with a non-empty raw cursor", pull.NextCursor)
	}
}

func TestCursorFeedPriorWatermarkPrefersLaterOfDurableAndEnvelopeWatermark(t *testing.T) {
	envelope := CursorEnvelope{}
	SetCursorWatermark(&envelope, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	checkpoint := &cerebrov1.SourceCheckpoint{
		CursorOpaque: opaque,
		Watermark:    nil,
	}
	if got := CursorFeedPriorWatermark(checkpoint); !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("CursorFeedPriorWatermark() = %v, want 2026-01-01", got)
	}
}

func TestCursorFeedPageToListStopsWhenHasMoreFalse(t *testing.T) {
	list := CursorFeedPageToList(func(_ context.Context, settings string, cursor string, pageSize int) ([]string, CursorFeedPage, error) {
		return []string{"a", "b"}, CursorFeedPage{NextCursor: "stale", HasMore: false}, nil
	})
	records, next, err := list(context.Background(), "settings", "", 10)
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if next != "" {
		t.Fatalf("next = %q, want empty when HasMore=false", next)
	}
}

func TestCursorFeedPageToListContinuesWhenHasMoreTrue(t *testing.T) {
	list := CursorFeedPageToList(func(_ context.Context, settings string, cursor string, pageSize int) ([]string, CursorFeedPage, error) {
		return nil, CursorFeedPage{NextCursor: "page-2", HasMore: true}, nil
	})
	_, next, err := list(context.Background(), "settings", "", 10)
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if next != "page-2" {
		t.Fatalf("next = %q, want page-2", next)
	}
}

func TestCursorFeedPageToListPropagatesError(t *testing.T) {
	wantErr := fmt.Errorf("boom")
	list := CursorFeedPageToList(func(_ context.Context, settings string, cursor string, pageSize int) ([]string, CursorFeedPage, error) {
		return nil, CursorFeedPage{}, wantErr
	})
	_, next, err := list(context.Background(), "settings", "", 10)
	if !errors.Is(err, wantErr) {
		t.Fatalf("list() error = %v, want %v", err, wantErr)
	}
	if next != "" {
		t.Fatalf("next = %q, want empty on error", next)
	}
}

package sourcecdk

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

func TestCursorEnvelopeCanonicalizesResumableCheckpoint(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 34, 56, 789, time.UTC)
	envelope := CursorEnvelope{
		Version:             1,
		Source:              " github ",
		Family:              " pull_request ",
		Mode:                " incremental_watermark ",
		ResumableCheckpoint: true,
		Token:               " 2 ",
		BoundaryIDs:         []string{" pr-2 ", "pr-1", "pr-2", ""},
		Extra:               map[string]string{" repo ": " cerebro ", "empty": " "},
	}
	SetCursorWatermark(&envelope, watermark)

	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	if !ResumableCursorOpaque(opaque) {
		t.Fatalf("ResumableCursorOpaque(%q) = false, want true", opaque)
	}
	decoded, ok := DecodeCursorEnvelope(opaque)
	if !ok {
		t.Fatalf("DecodeCursorEnvelope(%q) ok = false, want true", opaque)
	}
	if decoded.Source != "github" || decoded.Family != "pull_request" || decoded.Mode != "incremental_watermark" {
		t.Fatalf("decoded source/family/mode = %q/%q/%q", decoded.Source, decoded.Family, decoded.Mode)
	}
	if decoded.Token != "2" {
		t.Fatalf("decoded token = %q, want 2", decoded.Token)
	}
	if got := decoded.BoundaryIDs; len(got) != 2 || got[0] != "pr-1" || got[1] != "pr-2" {
		t.Fatalf("decoded boundary IDs = %#v, want sorted unique IDs", got)
	}
	if got := decoded.Extra["repo"]; got != "cerebro" {
		t.Fatalf("decoded extra repo = %q, want cerebro", got)
	}
	if got := CursorWatermark(decoded); !got.Equal(watermark) {
		t.Fatalf("CursorWatermark() = %s, want %s", got, watermark)
	}
}

func TestCursorEnvelopeRejectsProviderNativeCursor(t *testing.T) {
	if _, ok := DecodeCursorEnvelope("2"); ok {
		t.Fatal("DecodeCursorEnvelope(native token) ok = true, want false")
	}
	if ResumableCursorOpaque(`{"token":"2"}`) {
		t.Fatal("ResumableCursorOpaque(non-resumable envelope) = true, want false")
	}
	if got := CursorWatermark(CursorEnvelope{Watermark: "not-a-time"}); !got.IsZero() {
		t.Fatalf("CursorWatermark(invalid) = %s, want zero", got)
	}
}

func TestCursorPageReadsEnvelopeToken(t *testing.T) {
	opaque, err := EncodeCursorEnvelope(CursorEnvelope{ResumableCheckpoint: true, Token: "3"})
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	page, err := CursorPage(&cerebrov1.SourceCursor{Opaque: opaque})
	if err != nil {
		t.Fatalf("CursorPage(envelope) error = %v", err)
	}
	if page != 3 {
		t.Fatalf("CursorPage(envelope) = %d, want 3", page)
	}
	page, err = CursorPage(&cerebrov1.SourceCursor{Opaque: `{"resumable_checkpoint":true}`})
	if err != nil {
		t.Fatalf("CursorPage(envelope without token) error = %v", err)
	}
	if page != 1 {
		t.Fatalf("CursorPage(envelope without token) = %d, want 1", page)
	}
	if _, err := CursorPage(&cerebrov1.SourceCursor{Opaque: "0"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("CursorPage(0) error = %v, want ErrInvalidConfig", err)
	}
}

func TestCursorAfterOrPageReadsTypedTokens(t *testing.T) {
	after, page, err := CursorAfterOrPage(&cerebrov1.SourceCursor{Opaque: "after:cursor-2"})
	if err != nil {
		t.Fatalf("CursorAfterOrPage(after) error = %v", err)
	}
	if after != "cursor-2" || page != "" {
		t.Fatalf("CursorAfterOrPage(after) = %q/%q, want cursor-2/empty", after, page)
	}
	after, page, err = CursorAfterOrPage(&cerebrov1.SourceCursor{Opaque: "page:2"})
	if err != nil {
		t.Fatalf("CursorAfterOrPage(page) error = %v", err)
	}
	if after != "" || page != "2" {
		t.Fatalf("CursorAfterOrPage(page) = %q/%q, want empty/2", after, page)
	}
	after, page, err = CursorAfterOrPage(&cerebrov1.SourceCursor{Opaque: "2"})
	if err != nil {
		t.Fatalf("CursorAfterOrPage(legacy) error = %v", err)
	}
	if after != "" || page != "" {
		t.Fatalf("CursorAfterOrPage(legacy) = %q/%q, want empty/empty", after, page)
	}
	if _, _, err := CursorAfterOrPage(&cerebrov1.SourceCursor{Opaque: "page:0"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("CursorAfterOrPage(page:0) error = %v, want ErrInvalidConfig", err)
	}
}

func TestNextAfterOrPageCursorPrefersAfter(t *testing.T) {
	if got := NextAfterOrPageCursor("cursor-2", "3", 4); got != "after:cursor-2" {
		t.Fatalf("NextAfterOrPageCursor(after) = %q, want after cursor", got)
	}
	if got := NextAfterOrPageCursor("", "3", 4); got != "page:3" {
		t.Fatalf("NextAfterOrPageCursor(token) = %q, want page token", got)
	}
	if got := NextAfterOrPageCursor("", "", 4); got != "page:4" {
		t.Fatalf("NextAfterOrPageCursor(page) = %q, want page fallback", got)
	}
}

func TestIncrementalWatermarkFiltersBoundaryEvents(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	events := []*primitives.Event{
		watermarkTestEvent("newer", watermark.Add(time.Minute)),
		watermarkTestEvent("seen-boundary", watermark),
		watermarkTestEvent("new-boundary", watermark),
		watermarkTestEvent("older", watermark.Add(-time.Minute)),
	}
	filtered, reached := IncrementalWatermarkEvents(events, IncrementalWatermarkState{
		Watermark:   watermark,
		BoundaryIDs: map[string]struct{}{"seen-boundary": {}},
	})
	if !reached {
		t.Fatal("IncrementalWatermarkEvents reached = false, want true")
	}
	if len(filtered) != 2 || filtered[0].GetId() != "newer" || filtered[1].GetId() != "new-boundary" {
		t.Fatalf("filtered events = %#v, want newer and new-boundary", filtered)
	}
	checkpoint := IncrementalWatermarkCheckpoint("github", "pull_request", filtered, IncrementalWatermarkState{})
	if got := checkpoint.GetWatermark().AsTime(); !got.Equal(watermark.Add(time.Minute)) {
		t.Fatalf("checkpoint watermark = %s, want newest event", got)
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		t.Fatal("checkpoint cursor is not an envelope")
	}
	if got := envelope.BoundaryIDs; len(got) != 1 || got[0] != "newer" {
		t.Fatalf("checkpoint boundary IDs = %#v, want newest event boundary", got)
	}
}

func watermarkTestEvent(id string, occurredAt time.Time) *primitives.Event {
	return &primitives.Event{
		Id:         id,
		OccurredAt: timestamppb.New(occurredAt),
	}
}

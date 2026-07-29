package sourcecdk

import (
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestDescendingIDPageRoundTripPreservesDurableBounds(t *testing.T) {
	watermark := time.Date(2026, 7, 1, 4, 0, 0, 0, time.UTC)
	page := DescendingIDPage{BaselineID: 50}
	page.CaptureHigh(205, watermark)
	cursor, more, err := page.ContinuationCursor(100, 100, 106, "archetype", "scan", "scan_id_desc")
	if err != nil {
		t.Fatalf("ContinuationCursor() error = %v", err)
	}
	if !more {
		t.Fatal("ContinuationCursor() more = false")
	}

	restored, err := DescendingIDPageFrom(cursor, &cerebrov1.SourceCheckpoint{CursorOpaque: "50"}, "archetype", "scan_id_desc")
	if err != nil {
		t.Fatalf("DescendingIDPageFrom() error = %v", err)
	}
	if restored.BaselineID != 50 || restored.BeforeID != 106 || restored.HighID != 205 {
		t.Fatalf("restored = %#v", restored)
	}
	if !restored.HighWatermark.Equal(watermark) {
		t.Fatalf("HighWatermark = %v, want %v", restored.HighWatermark, watermark)
	}
	if got := restored.ProgressCheckpoint().GetCursorOpaque(); got != "205" {
		t.Fatalf("ProgressCheckpoint() = %q, want 205", got)
	}
}

func TestDescendingIDPageStopsAtContiguousBaseline(t *testing.T) {
	page := DescendingIDPage{
		BaselineID:    0,
		HighID:        100,
		HighWatermark: time.Date(2026, 7, 1, 4, 0, 0, 0, time.UTC),
	}
	cursor, more, err := page.ContinuationCursor(100, 100, 1, "archetype", "scan", "scan_id_desc")
	if err != nil {
		t.Fatalf("ContinuationCursor() error = %v", err)
	}
	if more || cursor != nil {
		t.Fatalf("ContinuationCursor() = %#v, %v, want terminal", cursor, more)
	}
}

func TestDescendingIDPageRejectsInvalidContinuationBounds(t *testing.T) {
	opaque, err := EncodeCursorEnvelope(CursorEnvelope{
		Source:    "archetype",
		Mode:      "scan_id_desc",
		Token:     "50",
		Watermark: "2026-07-01T04:00:00Z",
		Extra:     map[string]string{"baseline_id": "50", "high_id": "205"},
	})
	if err != nil {
		t.Fatalf("EncodeCursorEnvelope() error = %v", err)
	}
	_, err = DescendingIDPageFrom(&cerebrov1.SourceCursor{Opaque: opaque}, nil, "archetype", "scan_id_desc")
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("DescendingIDPageFrom() error = %v, want ErrInvalidConfig", err)
	}
}

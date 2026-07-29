package sourcecdk

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DescendingIDPage tracks a bounded walk from the newest provider record back
// to the last durable ID without advancing that checkpoint between pages.
type DescendingIDPage struct {
	BaselineID    int64
	BeforeID      int64
	HighID        int64
	HighWatermark time.Time
}

// DescendingIDPageFrom restores a descending-ID page walk. Legacy numeric
// cursors and checkpoints remain valid as durable baseline IDs.
func DescendingIDPageFrom(cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, source, mode string) (DescendingIDPage, error) {
	state := DescendingIDPage{BaselineID: descendingCheckpointID(checkpoint.GetCursorOpaque())}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return state, nil
	}
	envelope, ok := DecodeCursorEnvelope(opaque)
	if !ok || envelope.Source != strings.TrimSpace(source) || envelope.Mode != strings.TrimSpace(mode) {
		state.BaselineID = descendingCheckpointID(opaque)
		return state, nil
	}
	var err error
	if state.BaselineID, err = nonNegativeCursorInt(envelope.Extra["baseline_id"], "baseline_id"); err != nil {
		return DescendingIDPage{}, err
	}
	if state.BeforeID, err = positiveCursorInt64(envelope.Token, "before_id"); err != nil {
		return DescendingIDPage{}, err
	}
	if state.HighID, err = positiveCursorInt64(envelope.Extra["high_id"], "high_id"); err != nil {
		return DescendingIDPage{}, err
	}
	state.HighWatermark = CursorWatermark(envelope)
	if state.HighWatermark.IsZero() {
		return DescendingIDPage{}, fmt.Errorf("%w: descending id cursor high watermark is required", ErrInvalidConfig)
	}
	if state.BeforeID > state.HighID || state.BaselineID >= state.BeforeID {
		return DescendingIDPage{}, fmt.Errorf("%w: descending id cursor bounds are invalid", ErrInvalidConfig)
	}
	return state, nil
}

// CaptureHigh records the immutable upper bound from the first provider page.
func (p *DescendingIDPage) CaptureHigh(id int64, watermark time.Time) {
	if p == nil || p.HighID != 0 || id <= p.BaselineID || watermark.IsZero() {
		return
	}
	p.HighID = id
	p.HighWatermark = watermark.UTC()
}

// ContinuationCursor returns a cursor for the next older provider page when
// the current full page can still contain IDs above the durable baseline.
func (p DescendingIDPage) ContinuationCursor(returned, limit int, oldestID int64, source, family, mode string) (*cerebrov1.SourceCursor, bool, error) {
	if returned != limit || oldestID <= p.BaselineID+1 {
		return nil, false, nil
	}
	envelope := CursorEnvelope{
		Version: 1,
		Source:  source,
		Family:  family,
		Mode:    mode,
		Token:   strconv.FormatInt(oldestID, 10),
		Extra: map[string]string{
			"baseline_id": strconv.FormatInt(p.BaselineID, 10),
			"high_id":     strconv.FormatInt(p.HighID, 10),
		},
	}
	SetCursorWatermark(&envelope, p.HighWatermark)
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return nil, false, err
	}
	return &cerebrov1.SourceCursor{Opaque: opaque}, true, nil
}

// ProgressCheckpoint returns the captured high ID only after the walk reaches
// its terminal page. Callers keep the existing checkpoint on continuation pages.
func (p DescendingIDPage) ProgressCheckpoint() *cerebrov1.SourceCheckpoint {
	if p.HighID <= p.BaselineID || p.HighWatermark.IsZero() {
		return nil
	}
	return &cerebrov1.SourceCheckpoint{
		CursorOpaque: strconv.FormatInt(p.HighID, 10),
		Watermark:    timestamppb.New(p.HighWatermark),
	}
}

func descendingCheckpointID(opaque string) int64 {
	trimmed := strings.TrimSpace(opaque)
	if envelope, ok := DecodeCursorEnvelope(trimmed); ok {
		trimmed = envelope.Token
	}
	id, _ := strconv.ParseInt(trimmed, 10, 64)
	return id
}

func positiveCursorInt64(raw, field string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%w: descending id cursor %s must be a positive integer", ErrInvalidConfig, field)
	}
	return value, nil
}

func nonNegativeCursorInt(raw, field string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%w: descending id cursor %s must be a non-negative integer", ErrInvalidConfig, field)
	}
	return value, nil
}

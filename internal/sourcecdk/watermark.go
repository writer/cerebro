package sourcecdk

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
)

const incrementalWatermarkMode = "incremental_watermark"

// IncrementalWatermarkState tracks a high-water mark and the event IDs already
// seen at that boundary so equal-timestamp events can be deduplicated safely.
type IncrementalWatermarkState struct {
	Watermark   time.Time
	BoundaryIDs map[string]struct{}
}

// IncrementalWatermarkCheckpointState restores incremental state from a source
// checkpoint when its cursor envelope belongs to source/family.
func IncrementalWatermarkCheckpointState(source string, family string, checkpoint *cerebrov1.SourceCheckpoint) IncrementalWatermarkState {
	state := IncrementalWatermarkState{BoundaryIDs: map[string]struct{}{}}
	if checkpoint == nil {
		return state
	}
	if watermark := checkpoint.GetWatermark(); watermark != nil && !watermark.AsTime().IsZero() {
		state.Watermark = watermark.AsTime().UTC()
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok || !incrementalCursorMatches(envelope, source, family) {
		return state
	}
	if watermark := CursorWatermark(envelope); !watermark.IsZero() {
		state.Watermark = watermark.UTC()
	}
	for _, id := range envelope.BoundaryIDs {
		state.BoundaryIDs[strings.TrimSpace(id)] = struct{}{}
	}
	return state
}

// IncrementalWatermarkEvents keeps only events newer than state. It returns
// true when the page reached the known boundary and the source can stop.
func IncrementalWatermarkEvents(events []*primitives.Event, state IncrementalWatermarkState) ([]*primitives.Event, bool) {
	if state.Watermark.IsZero() {
		return events, false
	}
	filtered := make([]*primitives.Event, 0, len(events))
	reachedWatermark := false
	for _, event := range events {
		if event == nil {
			continue
		}
		occurredAt := event.GetOccurredAt().AsTime().UTC()
		switch {
		case occurredAt.After(state.Watermark):
			filtered = append(filtered, event)
		case occurredAt.Equal(state.Watermark):
			if _, seen := state.BoundaryIDs[event.GetId()]; seen {
				reachedWatermark = true
				continue
			}
			filtered = append(filtered, event)
		default:
			reachedWatermark = true
		}
	}
	return filtered, reachedWatermark
}

// IncrementalWatermarkCheckpoint advances a checkpoint from emitted events.
func IncrementalWatermarkCheckpoint(source string, family string, events []*primitives.Event, prior IncrementalWatermarkState) *cerebrov1.SourceCheckpoint {
	watermark := prior.Watermark
	boundaryIDs := make(map[string]struct{}, len(prior.BoundaryIDs))
	for id := range prior.BoundaryIDs {
		boundaryIDs[id] = struct{}{}
	}
	for _, event := range events {
		if event == nil {
			continue
		}
		occurredAt := event.GetOccurredAt().AsTime().UTC()
		switch {
		case watermark.IsZero() || occurredAt.After(watermark):
			watermark = occurredAt
			boundaryIDs = map[string]struct{}{event.GetId(): {}}
		case occurredAt.Equal(watermark):
			boundaryIDs[event.GetId()] = struct{}{}
		}
	}
	if watermark.IsZero() {
		return nil
	}
	boundaryValues := make([]string, 0, len(boundaryIDs))
	for id := range boundaryIDs {
		boundaryValues = append(boundaryValues, id)
	}
	envelope := CursorEnvelope{
		Source:              source,
		Family:              family,
		Mode:                incrementalWatermarkMode,
		ResumableCheckpoint: true,
		BoundaryIDs:         boundaryValues,
	}
	SetCursorWatermark(&envelope, watermark)
	opaque, _ := EncodeCursorEnvelope(envelope)
	return &cerebrov1.SourceCheckpoint{
		Watermark:    timestamppb.New(watermark.UTC()),
		CursorOpaque: opaque,
	}
}

// IncrementalWatermarkCheckpointWithToken stores a provider continuation token
// inside a checkpoint envelope without dropping watermark metadata.
func IncrementalWatermarkCheckpointWithToken(checkpoint *cerebrov1.SourceCheckpoint, token string) *cerebrov1.SourceCheckpoint {
	if checkpoint == nil {
		return nil
	}
	envelope, ok := DecodeCursorEnvelope(checkpoint.GetCursorOpaque())
	if !ok {
		return checkpoint
	}
	envelope.Token = strings.TrimSpace(token)
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return checkpoint
	}
	checkpoint.CursorOpaque = opaque
	return checkpoint
}

// IncrementalWatermarkPull filters events against the durable watermark and
// attaches a continuation token only when the watermark boundary was not
// reached.
func IncrementalWatermarkPull(source string, family string, events []*primitives.Event, checkpoint *cerebrov1.SourceCheckpoint, nextCursor string) Pull {
	state := IncrementalWatermarkCheckpointState(source, family, checkpoint)
	filtered, reachedWatermark := IncrementalWatermarkEvents(events, state)
	pull := Pull{
		Events:     filtered,
		Checkpoint: IncrementalWatermarkCheckpoint(source, family, filtered, state),
	}
	if reachedWatermark {
		pull.ShortCircuitReason = PullShortCircuitReasonWatermarkReached
		return pull
	}
	if nextCursor = strings.TrimSpace(nextCursor); nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
		pull.Checkpoint = IncrementalWatermarkCheckpointWithToken(pull.Checkpoint, nextCursor)
	}
	return pull
}

// EmptyIncrementalWatermarkPull returns an unchanged pull when a source page is
// empty but a previous incremental watermark exists.
func EmptyIncrementalWatermarkPull(source string, family string, checkpoint *cerebrov1.SourceCheckpoint) Pull {
	state := IncrementalWatermarkCheckpointState(source, family, checkpoint)
	if state.Watermark.IsZero() {
		return Pull{}
	}
	return Pull{
		Checkpoint:         IncrementalWatermarkCheckpoint(source, family, nil, state),
		ShortCircuitReason: PullShortCircuitReasonNotModified,
	}
}

// PullFromRecords projects provider records into events and advances a simple
// page-token checkpoint.
func PullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error), cursorFallback func(T) string) (Pull, error) {
	if len(records) == 0 {
		if next = strings.TrimSpace(next); next != "" {
			return Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
		}
		return Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return Pull{}, err
		}
		events = append(events, event)
	}
	fallback := events[len(events)-1].GetId()
	if cursorFallback != nil {
		fallback = cursorFallback(records[len(records)-1])
	}
	cursorOpaque := strings.TrimSpace(next)
	if cursorOpaque == "" {
		cursorOpaque = fallback
	}
	pull := Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: cursorOpaque,
		},
	}
	if next = strings.TrimSpace(next); next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

// IncrementalPullFromRecords projects records into events and applies durable
// watermark filtering. Continuation cursors carry the original comparison
// checkpoint so later sync calls do not drop older pages that are still newer
// than the run's starting watermark.
func IncrementalPullFromRecords[T any](source string, family string, records []T, next string, checkpoint *cerebrov1.SourceCheckpoint, build func(T) (*primitives.Event, error)) (Pull, error) {
	if len(records) == 0 {
		return IncrementalPullFromEvents(source, family, nil, next, checkpoint), nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return Pull{}, err
		}
		events = append(events, event)
	}
	return IncrementalPullFromEvents(source, family, events, next, checkpoint), nil
}

// IncrementalPullFromEvents applies durable watermark filtering to events that
// were already projected by a provider reader.
func IncrementalPullFromEvents(source string, family string, events []*primitives.Event, next string, checkpoint *cerebrov1.SourceCheckpoint) Pull {
	if len(events) == 0 {
		pull := EmptyIncrementalWatermarkPull(source, family, checkpoint)
		if next = strings.TrimSpace(next); next != "" {
			pull.NextCursor = &cerebrov1.SourceCursor{Opaque: IncrementalCursor(source, family, next, checkpoint)}
		}
		return pull
	}
	pull := IncrementalWatermarkPull(source, family, events, checkpoint, next)
	if pull.NextCursor != nil {
		pull.NextCursor.Opaque = IncrementalCursor(source, family, next, checkpoint)
	}
	return pull
}

// IncrementalCheckpointForCursor restores the starting comparison checkpoint
// from a continuation cursor produced by IncrementalCursor.
func IncrementalCheckpointForCursor(source string, family string, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) *cerebrov1.SourceCheckpoint {
	if cursor == nil || strings.TrimSpace(cursor.GetOpaque()) == "" {
		return checkpoint
	}
	envelope, ok := DecodeCursorEnvelope(cursor.GetOpaque())
	if !ok || strings.TrimSpace(envelope.Source) != strings.TrimSpace(source) || strings.TrimSpace(envelope.Family) != strings.TrimSpace(family) {
		return checkpoint
	}
	envelope.Token = ""
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		opaque = cursor.GetOpaque()
	}
	readCheckpoint := &cerebrov1.SourceCheckpoint{CursorOpaque: opaque}
	if watermark := CursorWatermark(envelope); !watermark.IsZero() {
		readCheckpoint.Watermark = timestamppb.New(watermark.UTC())
	}
	return readCheckpoint
}

// IncrementalCursorToken returns a provider continuation token for an
// incremental scan. Legacy bare provider tokens are ignored once a durable
// watermark exists because provider-side watermark filters usually change the
// token contract for the remote API.
func IncrementalCursorToken(source string, family string, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) string {
	if cursor == nil {
		return ""
	}
	opaque := strings.TrimSpace(cursor.GetOpaque())
	if opaque == "" {
		return ""
	}
	if envelope, ok := DecodeCursorEnvelope(opaque); ok {
		if !incrementalCursorMatches(envelope, source, family) {
			return ""
		}
		return strings.TrimSpace(envelope.Token)
	}
	if checkpointHasWatermark(checkpoint) {
		return ""
	}
	return opaque
}

// IncrementalCursor wraps a provider token with the comparison watermark and
// boundary IDs used for this incremental scan.
func IncrementalCursor(source string, family string, token string, checkpoint *cerebrov1.SourceCheckpoint) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	state := IncrementalWatermarkCheckpointState(source, family, checkpoint)
	envelope := CursorEnvelope{
		Source:              source,
		Family:              family,
		Mode:                incrementalWatermarkMode,
		ResumableCheckpoint: true,
		Token:               token,
	}
	if !state.Watermark.IsZero() {
		SetCursorWatermark(&envelope, state.Watermark)
	}
	for id := range state.BoundaryIDs {
		envelope.BoundaryIDs = append(envelope.BoundaryIDs, id)
	}
	opaque, err := EncodeCursorEnvelope(envelope)
	if err != nil {
		return token
	}
	return opaque
}

// WatermarkString returns the later of watermark and fallback, rendered as a
// UTC RFC3339Nano string. It prefers watermark on ties and returns an empty
// string when both times are zero.
func WatermarkString(watermark time.Time, fallback time.Time) string {
	if !watermark.IsZero() && !fallback.IsZero() && fallback.After(watermark) {
		watermark = fallback
	} else if watermark.IsZero() {
		watermark = fallback
	}
	if watermark.IsZero() {
		return ""
	}
	return watermark.UTC().Format(time.RFC3339Nano)
}

func checkpointHasWatermark(checkpoint *cerebrov1.SourceCheckpoint) bool {
	return checkpoint != nil && checkpoint.GetWatermark() != nil && !checkpoint.GetWatermark().AsTime().IsZero()
}

func incrementalCursorMatches(envelope CursorEnvelope, source string, family string) bool {
	if strings.TrimSpace(envelope.Source) != "" && strings.TrimSpace(envelope.Source) != strings.TrimSpace(source) {
		return false
	}
	return strings.TrimSpace(envelope.Family) == "" || strings.TrimSpace(envelope.Family) == strings.TrimSpace(family)
}

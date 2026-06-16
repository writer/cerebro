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

func incrementalCursorMatches(envelope CursorEnvelope, source string, family string) bool {
	if strings.TrimSpace(envelope.Source) != "" && strings.TrimSpace(envelope.Source) != strings.TrimSpace(source) {
		return false
	}
	return strings.TrimSpace(envelope.Family) == "" || strings.TrimSpace(envelope.Family) == strings.TrimSpace(family)
}

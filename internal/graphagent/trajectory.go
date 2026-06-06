package graphagent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	maxTrajectoryStringBytes = 8192
	maxTrajectoryRows        = 25
)

type trajectoryRecorder struct {
	store      ports.AskTrajectoryStore
	traceID    string
	started    time.Time
	eventCount int
}

func newTrajectoryRecorder(store ports.AskTrajectoryStore, traceID string, started time.Time) *trajectoryRecorder {
	if store == nil || traceID == "" {
		return nil
	}
	return &trajectoryRecorder{store: store, traceID: traceID, started: started}
}

func (r *trajectoryRecorder) start(ctx context.Context, request AskRequest, exec AskExecutionContext) {
	if r == nil {
		return
	}
	_ = r.store.PutAskTrajectoryRun(ctx, ports.AskTrajectoryRun{
		TraceID:       r.traceID,
		ParentTraceID: exec.ParentTraceID,
		TenantID:      request.TenantID,
		ScopeURN:      request.ScopeURN,
		Model:         normalizeModel(request.Model),
		QuestionLen:   len(request.Question),
		Depth:         exec.Depth,
		StartedAt:     r.started,
	})
}

func (r *trajectoryRecorder) wrap(ctx context.Context, emit Emitter) Emitter {
	if r == nil {
		return emit
	}
	return func(event Event) error {
		if err := emit(event); err != nil {
			return err
		}
		r.eventCount++
		payload, err := json.Marshal(redactTrajectoryEventData(event.Data))
		if err == nil {
			_ = r.store.AppendAskTrajectoryEvent(ctx, ports.AskTrajectoryEvent{
				TraceID:  r.traceID,
				Sequence: r.eventCount,
				Name:     event.Name,
				Data:     payload,
				At:       time.Now(),
			})
		}
		return nil
	}
}

func (r *trajectoryRecorder) finish(ctx context.Context, status string) {
	if r == nil {
		return
	}
	_ = r.store.FinishAskTrajectoryRun(ctx, ports.AskTrajectoryFinish{
		TraceID:    r.traceID,
		Status:     status,
		TotalMS:    time.Since(r.started).Milliseconds(),
		EventCount: r.eventCount,
		FinishedAt: time.Now(),
	})
}

func redactTrajectoryEventData(data any) any {
	switch typed := data.(type) {
	case RowsEvent:
		typed.Rows = truncateTrajectoryRows(typed.Rows)
		return typed
	case SummaryEvent:
		typed.Markdown = truncateTrajectoryString(typed.Markdown)
		return typed
	case RationaleEvent:
		typed.Text = truncateTrajectoryString(typed.Text)
		return typed
	default:
		return data
	}
}

func truncateTrajectoryRows(rows []map[string]any) []map[string]any {
	if len(rows) > maxTrajectoryRows {
		rows = rows[:maxTrajectoryRows]
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		copied := make(map[string]any, len(row))
		for key, value := range row {
			copied[key] = truncateTrajectoryValue(value)
		}
		out = append(out, copied)
	}
	return out
}

func truncateTrajectoryValue(value any) any {
	switch typed := value.(type) {
	case string:
		return truncateTrajectoryString(typed)
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, truncateTrajectoryValue(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = truncateTrajectoryValue(item)
		}
		return out
	default:
		return value
	}
}

func truncateTrajectoryString(value string) string {
	if len(value) <= maxTrajectoryStringBytes {
		return value
	}
	return value[:maxTrajectoryStringBytes] + "...[truncated]"
}

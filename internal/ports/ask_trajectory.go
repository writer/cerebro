package ports

import (
	"context"
	"encoding/json"
	"time"
)

// AskTrajectoryRun is the durable header for one /grc/ask execution.
type AskTrajectoryRun struct {
	TraceID       string
	ParentTraceID string
	TenantID      string
	ScopeURN      string
	Model         string
	QuestionLen   int
	Depth         int
	StartedAt     time.Time
}

// AskTrajectoryEvent is one redacted event emitted during an Ask execution.
type AskTrajectoryEvent struct {
	TraceID  string
	Sequence int
	Name     string
	Data     json.RawMessage
	At       time.Time
}

// AskTrajectoryFinish records the terminal status and coarse execution cost.
type AskTrajectoryFinish struct {
	TraceID    string
	Status     string
	TotalMS    int64
	EventCount int
	FinishedAt time.Time
}

// AskTrajectoryStore persists Ask execution traces for debugging and evals.
type AskTrajectoryStore interface {
	PutAskTrajectoryRun(context.Context, AskTrajectoryRun) error
	AppendAskTrajectoryEvent(context.Context, AskTrajectoryEvent) error
	FinishAskTrajectoryRun(context.Context, AskTrajectoryFinish) error
}

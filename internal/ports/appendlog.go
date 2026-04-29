package ports

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const EventAttributeSourceRuntimeID = "source_runtime_id"

// AppendLog is the future append-only event log boundary.
type AppendLog interface {
	Ping(context.Context) error
	Append(context.Context, *cerebrov1.EventEnvelope) error
}

// ReplayRequest scopes a bounded event replay from the append log.
type ReplayRequest struct {
	RuntimeID string
	Limit     uint32
}

// EventReplayer replays stored event envelopes from the append log.
type EventReplayer interface {
	Replay(context.Context, ReplayRequest) ([]*cerebrov1.EventEnvelope, error)
}

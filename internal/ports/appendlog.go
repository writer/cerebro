package ports

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// AppendLog is the future append-only event log boundary.
type AppendLog interface {
	Ping(context.Context) error
	Append(context.Context, *cerebrov1.EventEnvelope) error
}

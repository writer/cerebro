package ports

import (
	"context"
	"errors"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ErrSourceRuntimeNotFound indicates that a stored source runtime does not exist.
var ErrSourceRuntimeNotFound = errors.New("source runtime not found")

// SourceRuntimeStore persists source runtime configuration and checkpoints.
type SourceRuntimeStore interface {
	StateStore
	PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error
	GetSourceRuntime(context.Context, string) (*cerebrov1.SourceRuntime, error)
}

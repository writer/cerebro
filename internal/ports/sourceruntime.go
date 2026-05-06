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

// SourceRuntimeFilter scopes persisted source runtime listing.
type SourceRuntimeFilter struct {
	TenantID string
	SourceID string
	Limit    uint32
}

// SourceRuntimeListStore lists persisted source runtime definitions.
type SourceRuntimeListStore interface {
	SourceRuntimeStore
	ListSourceRuntimes(context.Context, SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error)
}

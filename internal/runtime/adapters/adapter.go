package adapters

import (
	"context"

	"github.com/evalops/cerebro/internal/runtime"
)

// Adapter normalizes provider-specific payloads into runtime observations.
type Adapter interface {
	Source() string
	Normalize(context.Context, []byte) ([]*runtime.RuntimeObservation, error)
}

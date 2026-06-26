package sourceprojection

import (
	"context"
	"fmt"

	"github.com/writer/cerebro/internal/ports"
)

type endpointCheckingGraphRecorder struct {
	projectionRecorder
}

func (r *endpointCheckingGraphRecorder) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if r.entities[link.FromURN] == nil {
		return fmt.Errorf("graph link source entity %q missing", link.FromURN)
	}
	if r.entities[link.ToURN] == nil {
		return fmt.Errorf("graph link target entity %q missing", link.ToURN)
	}
	return r.projectionRecorder.UpsertProjectedLink(ctx, link)
}

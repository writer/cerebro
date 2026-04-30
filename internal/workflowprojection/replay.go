package workflowprojection

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const defaultWorkflowKindPrefix = "workflow.v1."

// ErrRuntimeUnavailable indicates workflow replay dependencies are unavailable.
var ErrRuntimeUnavailable = errors.New("workflow projection runtime is unavailable")

// ReplayRequest scopes durable workflow event replay into the graph projection.
type ReplayRequest struct {
	KindPrefix      string
	TenantID        string
	AttributeEquals map[string]string
	Limit           uint32
}

// ReplayResult reports workflow replay projection impact.
type ReplayResult struct {
	EventsRead        uint32
	EventsProjected   uint32
	EntitiesProjected uint32
	LinksProjected    uint32
}

// Replayer rebuilds workflow graph projections from the append log.
type Replayer struct {
	replayer ports.EventReplayer
	graph    ports.ProjectionGraphStore
}

// NewReplayer constructs one workflow event replayer.
func NewReplayer(replayer ports.EventReplayer, graph ports.ProjectionGraphStore) *Replayer {
	return &Replayer{replayer: replayer, graph: graph}
}

// Replay replays durable workflow events and projects them into the graph.
func (r *Replayer) Replay(ctx context.Context, request ReplayRequest) (*ReplayResult, error) {
	if r == nil || r.replayer == nil || r.graph == nil {
		return nil, ErrRuntimeUnavailable
	}
	kindPrefix := strings.TrimSpace(request.KindPrefix)
	if kindPrefix == "" {
		kindPrefix = defaultWorkflowKindPrefix
	}
	events, err := r.replayer.Replay(ctx, ports.ReplayRequest{
		KindPrefix:      kindPrefix,
		TenantID:        strings.TrimSpace(request.TenantID),
		AttributeEquals: request.AttributeEquals,
		Limit:           request.Limit,
	})
	if err != nil {
		return nil, err
	}
	projector := New(r.graph)
	result := &ReplayResult{}
	for _, event := range events {
		result.EventsRead++
		projection, err := projector.Project(ctx, event)
		if err != nil {
			return nil, err
		}
		if projection.EntitiesProjected == 0 && projection.LinksProjected == 0 {
			continue
		}
		result.EventsProjected++
		result.EntitiesProjected += projection.EntitiesProjected
		result.LinksProjected += projection.LinksProjected
	}
	return result, nil
}

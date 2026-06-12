package workflowprojection

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
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
	projector := New(r.graph)
	result := &ReplayResult{}
	replayRequest := ports.ReplayRequest{
		TenantID:        strings.TrimSpace(request.TenantID),
		AttributeEquals: request.AttributeEquals,
		Limit:           request.Limit,
	}
	kindPrefixes := workflowReplayKindPrefixes(request.KindPrefix)
	if len(kindPrefixes) == 1 {
		replayRequest.KindPrefix = kindPrefixes[0]
	} else {
		replayRequest.KindPrefixes = kindPrefixes
	}
	events, err := r.replayer.Replay(ctx, replayRequest)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		result.EventsRead++
		projection, err := projector.Project(ctx, event)
		if err != nil {
			return nil, err
		}
		eventsProjected := projection.EventsProjected
		if eventsProjected == 0 && (projection.EntitiesProjected != 0 || projection.LinksProjected != 0 || projection.EntitiesDeleted != 0 || projection.LinksDeleted != 0) {
			eventsProjected = 1
		}
		if eventsProjected == 0 {
			continue
		}
		result.EventsProjected += eventsProjected
		result.EntitiesProjected += projection.EntitiesProjected
		result.LinksProjected += projection.LinksProjected
	}
	return result, nil
}

func workflowReplayKindPrefixes(kindPrefix string) []string {
	kindPrefix = strings.TrimSpace(kindPrefix)
	if kindPrefix != "" {
		return []string{kindPrefix}
	}
	return []string{defaultWorkflowKindPrefix, securityevents.FindingsV1Prefix + "."}
}

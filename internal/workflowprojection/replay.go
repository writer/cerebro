package workflowprojection

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
)

const defaultWorkflowKindPrefix = "workflow.v1."
const maxReplayErrorSamples = 10

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
	EventsFailed      uint32
	EntitiesProjected uint32
	LinksProjected    uint32
	Errors            []ReplayError
}

// ReplayError describes one workflow event that failed projection during replay.
type ReplayError struct {
	EventID string
	Kind    string
	Error   string
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
			result.recordError(event, err)
			continue
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

func (r *ReplayResult) recordError(event interface {
	GetId() string
	GetKind() string
}, err error) {
	if r == nil || err == nil {
		return
	}
	r.EventsFailed++
	if len(r.Errors) >= maxReplayErrorSamples {
		return
	}
	replayErr := ReplayError{Error: strings.TrimSpace(err.Error())}
	if event != nil {
		replayErr.EventID = strings.TrimSpace(event.GetId())
		replayErr.Kind = strings.TrimSpace(event.GetKind())
	}
	if replayErr.Error == "" {
		replayErr.Error = fmt.Sprintf("%T", err)
	}
	r.Errors = append(r.Errors, replayErr)
}

func workflowReplayKindPrefixes(kindPrefix string) []string {
	kindPrefix = strings.TrimSpace(kindPrefix)
	if kindPrefix != "" {
		return []string{kindPrefix}
	}
	return []string{defaultWorkflowKindPrefix, securityevents.FindingsV1Prefix + "."}
}

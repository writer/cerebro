package runtimegraph

import (
	"errors"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

// MaterializationResult summarizes one batch of runtime observation graph writes.
type MaterializationResult struct {
	ObservationsConsidered     int   `json:"observations_considered"`
	ObservationsMaterialized   int   `json:"observations_materialized"`
	ObservationsSkipped        int   `json:"observations_skipped"`
	WorkloadTargetEdgesCreated int   `json:"workload_target_edges_created"`
	MissingSubjects            int   `json:"missing_subjects"`
	InvalidObservations        int   `json:"invalid_observations"`
	LastError                  error `json:"-"`
}

// MaterializeObservationsIntoGraph projects runtime observations into graph observation nodes.
func MaterializeObservationsIntoGraph(g *graph.Graph, observations []*runtime.RuntimeObservation, now time.Time) MaterializationResult {
	result := MaterializationResult{}
	if g == nil || len(observations) == 0 {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, observation := range observations {
		result.ObservationsConsidered++

		req, err := BuildObservationWriteRequest(observation)
		if err != nil {
			result.ObservationsSkipped++
			if errors.Is(err, ErrMissingObservationSubject) {
				result.MissingSubjects++
			} else {
				result.InvalidObservations++
			}
			result.LastError = err
			continue
		}

		if _, ok := g.GetNode(req.SubjectID); !ok {
			result.ObservationsSkipped++
			result.MissingSubjects++
			result.LastError = ErrMissingObservationSubject
			continue
		}

		if _, err := graph.WriteObservation(g, req); err != nil {
			result.ObservationsSkipped++
			if classifyObservationMaterializationError(err) == observationMaterializationErrorMissingSubject {
				result.MissingSubjects++
			} else {
				result.InvalidObservations++
			}
			result.LastError = err
			continue
		}

		if subjectNode, ok := g.GetNode(req.SubjectID); ok && isWorkloadSubjectNode(subjectNode) {
			if graph.AddEdgeIfMissing(g, &graph.Edge{
				ID:     req.SubjectID + "->" + req.ID + ":" + string(graph.EdgeKindTargets),
				Source: req.SubjectID,
				Target: req.ID,
				Kind:   graph.EdgeKindTargets,
				Effect: graph.EdgeEffectAllow,
				Properties: map[string]any{
					"source_system":   req.SourceSystem,
					"source_event_id": req.SourceEventID,
					"observed_at":     req.ObservedAt.UTC().Format(time.RFC3339),
					"valid_from":      req.ValidFrom.UTC().Format(time.RFC3339),
				},
			}) {
				result.WorkloadTargetEdgesCreated++
			}
		}

		result.ObservationsMaterialized++
	}

	refreshMaterializedGraphMetadata(g, now)
	return result
}

type observationMaterializationErrorKind int

const (
	observationMaterializationErrorInvalid observationMaterializationErrorKind = iota
	observationMaterializationErrorMissingSubject
)

func classifyObservationMaterializationError(err error) observationMaterializationErrorKind {
	if err == nil {
		return observationMaterializationErrorInvalid
	}
	if errors.Is(err, ErrMissingObservationSubject) || strings.HasPrefix(strings.TrimSpace(err.Error()), "subject not found:") {
		return observationMaterializationErrorMissingSubject
	}
	return observationMaterializationErrorInvalid
}

func isWorkloadSubjectNode(node *graph.Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case graph.NodeKindWorkload,
		graph.NodeKindDeployment,
		graph.NodeKindPod:
		return true
	default:
		return false
	}
}

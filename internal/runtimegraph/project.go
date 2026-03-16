package runtimegraph

import (
	"errors"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

// MaterializationResult summarizes one batch of runtime observation graph writes.
type MaterializationResult struct {
	ObservationsConsidered   int   `json:"observations_considered"`
	ObservationsMaterialized int   `json:"observations_materialized"`
	ObservationsSkipped      int   `json:"observations_skipped"`
	MissingSubjects          int   `json:"missing_subjects"`
	InvalidObservations      int   `json:"invalid_observations"`
	LastError                error `json:"-"`
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

		result.ObservationsMaterialized++
	}

	g.BuildIndex()
	meta := g.Metadata()
	meta.BuiltAt = now.UTC()
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
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

package runtimegraph

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

// MaterializationResult summarizes one batch of runtime observation graph writes.
type MaterializationResult struct {
	ObservationsConsidered      int   `json:"observations_considered"`
	ObservationsMaterialized    int   `json:"observations_materialized"`
	ObservationsSkipped         int   `json:"observations_skipped"`
	WorkloadTargetEdgesCreated  int   `json:"workload_target_edges_created"`
	ResponseBasedOnEdgesCreated int   `json:"response_based_on_edges_created"`
	MissingSubjects             int   `json:"missing_subjects"`
	InvalidObservations         int   `json:"invalid_observations"`
	LastError                   error `json:"-"`
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

		graph.MergeEdgeProperties(g, observationTargetEdgeID(req.ID, req.SubjectID), responseOutcomeTargetEdgeProperties(observation))

		if subjectNode, ok := g.GetNode(req.SubjectID); ok && isWorkloadSubjectNode(subjectNode) {
			properties := map[string]any{
				"source_system":   req.SourceSystem,
				"source_event_id": req.SourceEventID,
				"observed_at":     req.ObservedAt.UTC().Format(time.RFC3339),
				"valid_from":      req.ValidFrom.UTC().Format(time.RFC3339),
			}
			for key, value := range responseOutcomeTargetEdgeProperties(observation) {
				properties[key] = value
			}
			if graph.AddEdgeIfMissing(g, &graph.Edge{
				ID:         req.SubjectID + "->" + req.ID + ":" + string(graph.EdgeKindTargets),
				Source:     req.SubjectID,
				Target:     req.ID,
				Kind:       graph.EdgeKindTargets,
				Effect:     graph.EdgeEffectAllow,
				Properties: properties,
			}) {
				result.WorkloadTargetEdgesCreated++
			}
		}

		if evidenceNodeID := responseOutcomeEvidenceNodeID(observation); evidenceNodeID != "" {
			if _, ok := g.GetNode(evidenceNodeID); ok {
				if graph.AddEdgeIfMissing(g, buildResponseOutcomeBasedOnEdge(req.ID, evidenceNodeID, observation)) {
					result.ResponseBasedOnEdgesCreated++
				}
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

func observationTargetEdgeID(observationID, subjectID string) string {
	return fmt.Sprintf("%s->%s:%s", strings.TrimSpace(observationID), strings.TrimSpace(subjectID), graph.EdgeKindTargets)
}

func responseOutcomeTargetEdgeProperties(observation *runtime.RuntimeObservation) map[string]any {
	if observation == nil || observation.Kind != runtime.ObservationKindResponseOutcome {
		return nil
	}

	properties := make(map[string]any, 4)
	addMetadataString(properties, "response_execution_id", metadataString(observation.Metadata, "execution_id"))
	addMetadataString(properties, "response_policy_id", metadataString(observation.Metadata, "policy_id"))
	addMetadataString(properties, "response_action_type", metadataString(observation.Metadata, "action_type"))
	addMetadataString(properties, "response_action_status", metadataString(observation.Metadata, "action_status"))
	if len(properties) == 0 {
		return nil
	}
	return properties
}

func responseOutcomeEvidenceNodeID(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Kind != runtime.ObservationKindResponseOutcome {
		return ""
	}
	findingID := metadataString(observation.Metadata, "finding_id")
	if findingID == "" {
		return ""
	}
	return "evidence:runtime_finding:" + findingID
}

func buildResponseOutcomeBasedOnEdge(observationNodeID, evidenceNodeID string, observation *runtime.RuntimeObservation) *graph.Edge {
	observationNodeID = strings.TrimSpace(observationNodeID)
	evidenceNodeID = strings.TrimSpace(evidenceNodeID)
	if observationNodeID == "" || evidenceNodeID == "" {
		return nil
	}

	properties := map[string]any{
		"source_system": firstNonEmpty(strings.TrimSpace(observation.Source), "runtime_response"),
	}
	addMetadataString(properties, "source_event_id", strings.TrimSpace(observation.ID))
	addMetadataString(properties, "observed_at", observation.ObservedAt.UTC().Format(time.RFC3339))
	addMetadataString(properties, "valid_from", observation.ObservedAt.UTC().Format(time.RFC3339))
	addMetadataString(properties, "finding_id", metadataString(observation.Metadata, "finding_id"))
	for key, value := range responseOutcomeTargetEdgeProperties(observation) {
		properties[key] = value
	}

	return &graph.Edge{
		ID:         observationNodeID + "->" + evidenceNodeID + ":" + string(graph.EdgeKindBasedOn),
		Source:     observationNodeID,
		Target:     evidenceNodeID,
		Kind:       graph.EdgeKindBasedOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	}
}

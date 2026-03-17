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
	ObservationsConsidered             int   `json:"observations_considered"`
	ObservationsMaterialized           int   `json:"observations_materialized"`
	ObservationsSkipped                int   `json:"observations_skipped"`
	WorkloadTargetEdgesCreated         int   `json:"workload_target_edges_created"`
	ResponseBasedOnEdgesCreated        int   `json:"response_based_on_edges_created"`
	DeploymentRunBasedOnEdgesCreated   int   `json:"deployment_run_based_on_edges_created"`
	KubernetesAuditBasedOnEdgesCreated int   `json:"kubernetes_audit_based_on_edges_created"`
	MissingSubjects                    int   `json:"missing_subjects"`
	InvalidObservations                int   `json:"invalid_observations"`
	LastError                          error `json:"-"`
}

const deploymentRunObservationMaxGap = 30 * time.Minute
const kubernetesAuditObservationMaxGap = 10 * time.Minute

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

		normalized, err := runtime.NormalizeObservation(observation)
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

		req, err := buildObservationWriteRequestFromNormalized(normalized)
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
		applyObservationCorroboration(g, req.ID)

		graph.MergeEdgeProperties(g, observationTargetEdgeID(req.ID, req.SubjectID), responseOutcomeTargetEdgeProperties(normalized))

		if subjectNode, ok := g.GetNode(req.SubjectID); ok && isWorkloadSubjectNode(subjectNode) {
			properties := map[string]any{
				"source_system":   req.SourceSystem,
				"source_event_id": req.SourceEventID,
				"observed_at":     req.ObservedAt.UTC().Format(time.RFC3339),
				"valid_from":      req.ValidFrom.UTC().Format(time.RFC3339),
			}
			for key, value := range responseOutcomeTargetEdgeProperties(normalized) {
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

		if evidenceNodeID := responseOutcomeEvidenceNodeID(normalized); evidenceNodeID != "" {
			if _, ok := g.GetNode(evidenceNodeID); ok {
				if graph.AddEdgeIfMissing(g, buildResponseOutcomeBasedOnEdge(req.ID, evidenceNodeID, normalized)) {
					result.ResponseBasedOnEdgesCreated++
				}
			}
		}

		if deploymentRunID, serviceID, gap, ok := observationDeploymentRunCandidate(g, normalized, req.SubjectID); ok {
			if graph.AddEdgeIfMissing(g, buildObservationDeploymentRunBasedOnEdge(req.ID, deploymentRunID, serviceID, gap, normalized)) {
				result.DeploymentRunBasedOnEdgesCreated++
			}
		}

		if auditObservationID, gap, ok := observationKubernetesAuditCandidate(g, req.ID, normalized, req.SubjectID); ok {
			if graph.AddEdgeIfMissing(g, buildObservationKubernetesAuditBasedOnEdge(req.ID, auditObservationID, req.SubjectID, gap, normalized)) {
				result.KubernetesAuditBasedOnEdgesCreated++
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

func observationDeploymentRunCandidate(g *graph.Graph, observation *runtime.RuntimeObservation, subjectID string) (string, string, time.Duration, bool) {
	if g == nil || observation == nil || observation.ObservedAt.IsZero() {
		return "", "", 0, false
	}

	serviceID := observationDeploymentServiceID(observation, subjectID)
	if serviceID == "" {
		return "", "", 0, false
	}

	var candidateID string
	var candidateGap time.Duration
	for _, node := range g.GetNodesByKind(graph.NodeKindDeploymentRun) {
		if !deploymentRunTargetsService(g, node, serviceID) {
			continue
		}

		deployedAt, ok := deploymentRunObservedAt(node)
		if !ok || deployedAt.After(observation.ObservedAt) {
			continue
		}

		gap := observation.ObservedAt.Sub(deployedAt)
		if gap < 0 || gap > deploymentRunObservationMaxGap {
			continue
		}

		if candidateID != "" {
			return "", "", 0, false
		}
		candidateID = strings.TrimSpace(node.ID)
		candidateGap = gap
	}

	if candidateID == "" {
		return "", "", 0, false
	}
	return candidateID, serviceID, candidateGap, true
}

func observationDeploymentServiceID(observation *runtime.RuntimeObservation, subjectID string) string {
	subjectID = strings.TrimSpace(subjectID)
	if strings.HasPrefix(subjectID, "service:") {
		return subjectID
	}
	if observation == nil {
		return ""
	}

	resourceID := strings.TrimSpace(observation.ResourceID)
	if strings.HasPrefix(resourceID, "service:") {
		return resourceID
	}

	if serviceID := metadataString(observation.Metadata, "service_id"); strings.HasPrefix(serviceID, "service:") {
		return serviceID
	}

	serviceName := metadataString(observation.Metadata, "service_name")
	if observation.Trace != nil {
		serviceName = firstNonEmpty(observation.Trace.ServiceName, serviceName)
	}
	if serviceName == "" {
		return ""
	}

	namespace := firstNonEmpty(observation.Namespace, metadataString(observation.Metadata, "service_namespace"))
	if namespace == "" {
		return "service:" + serviceName
	}
	return "service:" + namespace + "/" + serviceName
}

func deploymentRunTargetsService(g *graph.Graph, node *graph.Node, serviceID string) bool {
	if g == nil || node == nil || strings.TrimSpace(serviceID) == "" {
		return false
	}
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge == nil || edge.Kind != graph.EdgeKindTargets {
			continue
		}
		if strings.TrimSpace(edge.Target) == serviceID {
			return true
		}
	}
	return false
}

func deploymentRunObservedAt(node *graph.Node) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	if ts, ok := propertyTime(node.Properties, "observed_at"); ok {
		return ts.UTC(), true
	}
	if ts, ok := propertyTime(node.Properties, "valid_from"); ok {
		return ts.UTC(), true
	}
	if !node.CreatedAt.IsZero() {
		return node.CreatedAt.UTC(), true
	}
	return time.Time{}, false
}

func propertyTime(properties map[string]any, key string) (time.Time, bool) {
	if len(properties) == 0 {
		return time.Time{}, false
	}
	raw, ok := properties[key]
	if !ok {
		return time.Time{}, false
	}
	switch typed := raw.(type) {
	case time.Time:
		if typed.IsZero() {
			return time.Time{}, false
		}
		return typed.UTC(), true
	case string:
		return parseRFC3339Time(typed)
	case []byte:
		return parseRFC3339Time(string(typed))
	default:
		return time.Time{}, false
	}
}

func propertyString(properties map[string]any, key string) string {
	if len(properties) == 0 {
		return ""
	}
	raw, ok := properties[key]
	if !ok {
		return ""
	}
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return ""
	}
}

func parseRFC3339Time(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts.UTC(), true
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.UTC(), true
	}
	return time.Time{}, false
}

func buildObservationDeploymentRunBasedOnEdge(observationNodeID, deploymentRunID, serviceID string, gap time.Duration, observation *runtime.RuntimeObservation) *graph.Edge {
	observationNodeID = strings.TrimSpace(observationNodeID)
	deploymentRunID = strings.TrimSpace(deploymentRunID)
	serviceID = strings.TrimSpace(serviceID)
	if observationNodeID == "" || deploymentRunID == "" || serviceID == "" {
		return nil
	}

	properties := map[string]any{
		"source_system":          firstNonEmpty(strings.TrimSpace(observation.Source), "runtime"),
		"service_id":             serviceID,
		"deployment_gap_seconds": int64(gap.Seconds()),
	}
	addMetadataString(properties, "source_event_id", strings.TrimSpace(observation.ID))
	addMetadataString(properties, "observed_at", observation.ObservedAt.UTC().Format(time.RFC3339))
	addMetadataString(properties, "valid_from", observation.ObservedAt.UTC().Format(time.RFC3339))

	return &graph.Edge{
		ID:         observationNodeID + "->" + deploymentRunID + ":" + string(graph.EdgeKindBasedOn),
		Source:     observationNodeID,
		Target:     deploymentRunID,
		Kind:       graph.EdgeKindBasedOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	}
}

func observationKubernetesAuditCandidate(g *graph.Graph, observationNodeID string, observation *runtime.RuntimeObservation, subjectID string) (string, time.Duration, bool) {
	if g == nil || observation == nil || observation.ObservedAt.IsZero() || observation.Kind == runtime.ObservationKindKubernetesAudit {
		return "", 0, false
	}

	observationNodeID = strings.TrimSpace(observationNodeID)
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return "", 0, false
	}

	var candidateID string
	var candidateGap time.Duration
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if node == nil || strings.TrimSpace(node.ID) == observationNodeID {
			continue
		}
		auditProps, ok := node.ObservationProperties()
		if ok {
			if strings.TrimSpace(auditProps.ObservationType) != string(runtime.ObservationKindKubernetesAudit) {
				continue
			}
			if strings.TrimSpace(auditProps.SubjectID) != subjectID {
				continue
			}
		} else {
			if propertyString(node.Properties, "observation_type") != string(runtime.ObservationKindKubernetesAudit) {
				continue
			}
			if propertyString(node.Properties, "subject_id") != subjectID {
				continue
			}
		}

		auditObservedAt := auditProps.ObservedAt
		if auditObservedAt.IsZero() {
			auditObservedAt = auditProps.ValidFrom
		}
		if auditObservedAt.IsZero() {
			auditObservedAt, ok = propertyTime(node.Properties, "observed_at")
		} else {
			ok = true
		}
		if !ok {
			auditObservedAt, ok = propertyTime(node.Properties, "valid_from")
		}
		if !ok || auditObservedAt.After(observation.ObservedAt) {
			continue
		}

		gap := observation.ObservedAt.Sub(auditObservedAt)
		if gap < 0 || gap > kubernetesAuditObservationMaxGap {
			continue
		}

		if candidateID != "" {
			return "", 0, false
		}
		candidateID = strings.TrimSpace(node.ID)
		candidateGap = gap
	}

	if candidateID == "" {
		return "", 0, false
	}
	return candidateID, candidateGap, true
}

func buildObservationKubernetesAuditBasedOnEdge(observationNodeID, auditObservationID, subjectID string, gap time.Duration, observation *runtime.RuntimeObservation) *graph.Edge {
	observationNodeID = strings.TrimSpace(observationNodeID)
	auditObservationID = strings.TrimSpace(auditObservationID)
	subjectID = strings.TrimSpace(subjectID)
	if observationNodeID == "" || auditObservationID == "" || subjectID == "" {
		return nil
	}

	properties := map[string]any{
		"source_system":     firstNonEmpty(strings.TrimSpace(observation.Source), "runtime"),
		"subject_id":        subjectID,
		"audit_gap_seconds": int64(gap.Seconds()),
	}
	addMetadataString(properties, "source_event_id", strings.TrimSpace(observation.ID))
	addMetadataString(properties, "observed_at", observation.ObservedAt.UTC().Format(time.RFC3339))
	addMetadataString(properties, "valid_from", observation.ObservedAt.UTC().Format(time.RFC3339))

	return &graph.Edge{
		ID:         observationNodeID + "->" + auditObservationID + ":" + string(graph.EdgeKindBasedOn),
		Source:     observationNodeID,
		Target:     auditObservationID,
		Kind:       graph.EdgeKindBasedOn,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	}
}

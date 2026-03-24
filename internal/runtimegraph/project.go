package runtimegraph

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/runtime"
)

// MaterializationResult summarizes one batch of runtime observation graph writes.
type MaterializationResult struct {
	ObservationsConsidered             int   `json:"observations_considered"`
	ObservationsMaterialized           int   `json:"observations_materialized"`
	ObservationsSkipped                int   `json:"observations_skipped"`
	WorkloadTargetEdgesCreated         int   `json:"workload_target_edges_created"`
	TraceCallEdgesCreated              int   `json:"trace_call_edges_created"`
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

		if _, ok := g.GetNode(req.SubjectID); !ok && !ensureObservationSubjectNode(g, normalized, req.SubjectID) {
			result.ObservationsSkipped++
			result.MissingSubjects++
			result.LastError = ErrMissingObservationSubject
			continue
		}

		existingObservationNode, _ := g.GetNode(req.ID)
		traceCallAlreadyProjected := observationTraceCallProjectionApplied(existingObservationNode)

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

		if !traceCallAlreadyProjected {
			created, edgeID, sourceID, targetID := materializeObservationTraceCallEdge(g, normalized, req.SubjectID)
			if edgeID != "" {
				markObservationTraceCallProjection(g, req.ID, edgeID, sourceID, targetID)
			}
			if created {
				result.TraceCallEdgesCreated++
			}
		}

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

func observationTraceCallProjectionApplied(node *graph.Node) bool {
	return node != nil && propertyString(node.Properties, "trace_calls_edge_id") != ""
}

func markObservationTraceCallProjection(g *graph.Graph, observationNodeID, edgeID, sourceID, targetID string) {
	if g == nil {
		return
	}
	node, ok := g.GetNode(strings.TrimSpace(observationNodeID))
	if !ok || node == nil {
		return
	}

	updated := *node
	updated.Properties = cloneProperties(node.Properties)
	if updated.Properties == nil {
		updated.Properties = make(map[string]any, 3)
	}
	addMetadataString(updated.Properties, "trace_calls_edge_id", edgeID)
	addMetadataString(updated.Properties, "trace_calls_source_id", sourceID)
	addMetadataString(updated.Properties, "trace_calls_target_id", targetID)
	g.AddNode(&updated)
}

func materializeObservationTraceCallEdge(g *graph.Graph, observation *runtime.RuntimeObservation, subjectID string) (bool, string, string, string) {
	if g == nil || !isTraceCallObservation(observation) {
		return false, "", "", ""
	}

	sourceID := observationTraceCallSourceID(g, observation, subjectID)
	targetID := observationTraceCallTargetID(g, observation)
	if sourceID == "" || targetID == "" || sourceID == targetID {
		return false, "", "", ""
	}

	edgeID := traceCallEdgeID(sourceID, targetID)
	properties := traceCallEdgeProperties(g, edgeID, observation)
	created := graph.AddEdgeIfMissing(g, &graph.Edge{
		ID:         edgeID,
		Source:     sourceID,
		Target:     targetID,
		Kind:       graph.EdgeKindCalls,
		Effect:     graph.EdgeEffectAllow,
		Properties: properties,
	})
	if created {
		return true, edgeID, sourceID, targetID
	}
	graph.MergeEdgeProperties(g, edgeID, properties)
	return false, edgeID, sourceID, targetID
}

func isTraceCallObservation(observation *runtime.RuntimeObservation) bool {
	if observation == nil || observation.Kind != runtime.ObservationKindTraceLink {
		return false
	}
	switch metadataString(observation.Metadata, "span_kind") {
	case "client", "producer":
		return true
	default:
		return false
	}
}

func observationTraceCallSourceID(g *graph.Graph, observation *runtime.RuntimeObservation, subjectID string) string {
	if g == nil || observation == nil {
		return ""
	}
	serviceID := observationDeploymentServiceID(observation, subjectID)
	if serviceID != "" {
		if _, ok := g.GetNode(serviceID); ok {
			return serviceID
		}
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return ""
	}
	node, ok := g.GetNode(subjectID)
	if !ok || node == nil {
		return ""
	}
	switch node.Kind {
	case graph.NodeKindService, graph.NodeKindWorkload, graph.NodeKindDeployment, graph.NodeKindPod:
		return subjectID
	default:
		return ""
	}
}

func observationTraceCallTargetID(g *graph.Graph, observation *runtime.RuntimeObservation) string {
	if g == nil || observation == nil {
		return ""
	}
	serviceName := metadataString(observation.Metadata, "destination_service_name")
	if serviceName == "" {
		return ""
	}
	namespace := firstNonEmpty(
		metadataString(observation.Metadata, "destination_service_namespace"),
		metadataString(observation.Metadata, "peer_namespace"),
	)
	serviceID := "service:" + serviceName
	if namespace != "" {
		serviceID = "service:" + namespace + "/" + serviceName
	}
	if _, ok := g.GetNode(serviceID); ok {
		return serviceID
	}
	return ""
}

func traceCallEdgeID(sourceID, targetID string) string {
	return fmt.Sprintf("%s->%s:%s", strings.TrimSpace(sourceID), strings.TrimSpace(targetID), graph.EdgeKindCalls)
}

func traceCallEdgeProperties(g *graph.Graph, edgeID string, observation *runtime.RuntimeObservation) map[string]any {
	observedAt := observation.ObservedAt.UTC()
	latencyMS := traceCallLatencyMS(observation)
	errorCount := int64(0)
	if traceCallErrored(observation) {
		errorCount = 1
	}

	callCount := int64(1)
	totalLatencyMS := latencyMS
	firstSeen := observedAt
	lastSeen := observedAt
	if existing := activeEdgeByID(g, edgeID); existing != nil {
		callCount = maxInt64(propertyInt64(existing.Properties, "call_count"), 0) + 1
		totalLatencyMS = maxInt64(propertyInt64(existing.Properties, "total_latency_ms"), 0) + latencyMS
		errorCount += maxInt64(propertyInt64(existing.Properties, "error_count"), 0)
		if ts, ok := propertyTime(existing.Properties, "first_seen"); ok && ts.Before(firstSeen) {
			firstSeen = ts
		}
		if ts, ok := propertyTime(existing.Properties, "last_seen"); ok && ts.After(lastSeen) {
			lastSeen = ts
		}
	}

	properties := map[string]any{
		"source_system":      firstNonEmpty(strings.TrimSpace(observation.Source), "runtime_trace"),
		"source_event_id":    strings.TrimSpace(observation.ID),
		"trace_id":           traceID(observation),
		"span_id":            spanID(observation),
		"parent_span_id":     metadataString(observation.Metadata, "parent_span_id"),
		"protocol":           firstNonEmpty(metadataString(observation.Metadata, "call_protocol"), networkProtocol(observation)),
		"call_count":         callCount,
		"error_count":        errorCount,
		"total_latency_ms":   totalLatencyMS,
		"avg_latency_ms":     traceCallAverageLatencyMS(totalLatencyMS, callCount),
		"error_rate":         traceCallErrorRate(errorCount, callCount),
		"call_rate_per_min":  traceCallRatePerMinute(firstSeen, lastSeen, callCount),
		"first_seen":         firstSeen.Format(time.RFC3339),
		"last_seen":          lastSeen.Format(time.RFC3339),
		"observed_at":        observedAt.Format(time.RFC3339),
		"valid_from":         observedAt.Format(time.RFC3339),
		"destination_system": "runtime_trace",
	}
	if statusCode := metadataString(observation.Metadata, "span_status_code"); statusCode != "" {
		properties["span_status_code"] = statusCode
	}
	return properties
}

func traceCallLatencyMS(observation *runtime.RuntimeObservation) int64 {
	if observation == nil || observation.RecordedAt.IsZero() || observation.RecordedAt.Before(observation.ObservedAt) {
		return 0
	}
	return observation.RecordedAt.Sub(observation.ObservedAt).Milliseconds()
}

func traceCallErrored(observation *runtime.RuntimeObservation) bool {
	if observation == nil {
		return false
	}
	if metadataString(observation.Metadata, "span_status_code") == "error" {
		return true
	}
	if attrs, ok := observation.Metadata["otel_span_attributes"].(map[string]any); ok {
		if status, ok := numericMapValue(attrs, "http.response.status_code"); ok && status >= 500 {
			return true
		}
	}
	return false
}

func traceCallAverageLatencyMS(totalLatencyMS, callCount int64) float64 {
	if callCount <= 0 {
		return 0
	}
	return float64(totalLatencyMS) / float64(callCount)
}

func traceCallErrorRate(errorCount, callCount int64) float64 {
	if callCount <= 0 {
		return 0
	}
	return float64(errorCount) / float64(callCount)
}

func traceCallRatePerMinute(firstSeen, lastSeen time.Time, callCount int64) float64 {
	if callCount <= 0 {
		return 0
	}
	window := lastSeen.Sub(firstSeen)
	if window < time.Minute {
		window = time.Minute
	}
	return float64(callCount) / window.Minutes()
}

func activeEdgeByID(g *graph.Graph, edgeID string) *graph.Edge {
	if g == nil || strings.TrimSpace(edgeID) == "" {
		return nil
	}
	sourceID, _, _ := strings.Cut(strings.TrimSpace(edgeID), "->")
	for _, edges := range g.GetOutEdges(sourceID) {
		if edges != nil && edges.ID == edgeID {
			return edges
		}
	}
	return nil
}

func propertyInt64(properties map[string]any, key string) int64 {
	if len(properties) == 0 {
		return 0
	}
	switch typed := properties[key].(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return uintToInt64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		return uint64ToInt64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func numericMapValue(values map[string]any, key string) (int64, bool) {
	if len(values) == 0 {
		return 0, false
	}
	value, ok := values[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		return uintToInt64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		return uint64ToInt64(typed), true
	case float64:
		return int64(typed), true
	default:
		return 0, false
	}
}

func uintToInt64(value uint) int64 {
	return uint64ToInt64(uint64(value))
}

func uint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func cloneProperties(properties map[string]any) map[string]any {
	if len(properties) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(properties))
	for key, value := range properties {
		cloned[key] = value
	}
	return cloned
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
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
	if ts, ok := graphNodePropertyTime(node, "observed_at"); ok {
		return ts.UTC(), true
	}
	if ts, ok := graphNodePropertyTime(node, "valid_from"); ok {
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

func graphNodePropertyTime(node *graph.Node, key string) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	if value, ok := node.PropertyValue(key); ok {
		return propertyTime(map[string]any{key: value}, key)
	}
	return propertyTime(node.Properties, key)
}

func graphNodePropertyString(node *graph.Node, key string) string {
	if node == nil {
		return ""
	}
	if value, ok := node.PropertyValue(key); ok {
		return propertyString(map[string]any{key: value}, key)
	}
	return propertyString(node.Properties, key)
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
			auditObservedAt, ok = graphNodePropertyTime(node, "observed_at")
		} else {
			ok = true
		}
		if !ok {
			auditObservedAt, ok = graphNodePropertyTime(node, "valid_from")
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

package runtimegraph

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/runtime"
)

var ErrMissingObservationSubject = errors.New("runtime observation missing concrete graph subject")

// FinalizeMaterializedGraph rebuilds graph indexes and refreshes metadata after
// one or more runtimegraph materialization batches.
func FinalizeMaterializedGraph(g *graph.Graph, now time.Time) {
	if g == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	CompactHistoricalObservations(g, now, DefaultObservationCompactionPolicy())
	MaterializeObservationSequences(g, now, DefaultObservationSequencePolicy())
	g.BuildIndex()
	refreshMaterializedGraphMetadata(g, now)
}

func refreshMaterializedGraphMetadata(g *graph.Graph, now time.Time) {
	if g == nil {
		return
	}
	meta := g.Metadata()
	meta.BuiltAt = now.UTC()
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
}

// BuildObservationWriteRequest converts one normalized runtime observation into
// a first-class graph observation write request.
func BuildObservationWriteRequest(observation *runtime.RuntimeObservation) (graph.ObservationWriteRequest, error) {
	normalized, err := runtime.NormalizeObservation(observation)
	if err != nil {
		return graph.ObservationWriteRequest{}, err
	}
	return buildObservationWriteRequestFromNormalized(normalized)
}

func buildObservationWriteRequestFromNormalized(normalized *runtime.RuntimeObservation) (graph.ObservationWriteRequest, error) {
	if normalized == nil {
		return graph.ObservationWriteRequest{}, fmt.Errorf("runtime observation is required")
	}

	subjectID := observationSubjectID(normalized)
	if subjectID == "" {
		return graph.ObservationWriteRequest{}, ErrMissingObservationSubject
	}

	return graph.ObservationWriteRequest{
		ID:              "observation:" + normalized.ID,
		SubjectID:       subjectID,
		ObservationType: string(normalized.Kind),
		Summary:         observationSummary(normalized),
		SourceSystem:    normalized.Source,
		SourceEventID:   normalized.ID,
		ObservedAt:      normalized.ObservedAt,
		ValidFrom:       normalized.ObservedAt,
		RecordedAt:      normalized.RecordedAt,
		TransactionFrom: normalized.RecordedAt,
		Confidence:      1.0,
		Metadata:        observationMetadata(normalized),
	}, nil
}

func observationSubjectID(observation *runtime.RuntimeObservation) string {
	if observation == nil {
		return ""
	}
	if value := strings.TrimSpace(observation.WorkloadRef); value != "" {
		return value
	}
	if value := strings.TrimSpace(observation.ContainerID); value != "" {
		return "container:" + value
	}
	if value := strings.TrimSpace(observation.ResourceID); hasConcreteResourceID(value) {
		return value
	}
	return ""
}

func hasConcreteResourceID(value string) bool {
	kind, remainder, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return false
	}
	kind = strings.TrimSpace(kind)
	remainder = strings.TrimSpace(remainder)
	return kind != "" && remainder != ""
}

func observationSummary(observation *runtime.RuntimeObservation) string {
	if observation == nil {
		return "runtime observation"
	}
	switch observation.Kind {
	case runtime.ObservationKindProcessExec:
		return "process exec " + firstNonEmpty(observation.Process.Path, observation.Process.Name, "process")
	case runtime.ObservationKindProcessExit:
		return "process exit " + firstNonEmpty(observation.Process.Path, observation.Process.Name, "process")
	case runtime.ObservationKindFileOpen:
		return "file open " + firstNonEmpty(observation.File.Path, "file")
	case runtime.ObservationKindFileWrite:
		return "file write " + firstNonEmpty(observation.File.Path, "file")
	case runtime.ObservationKindDNSQuery:
		return "dns query " + firstNonEmpty(observation.Network.Domain, observation.Network.DstIP, "lookup")
	case runtime.ObservationKindNetworkFlow:
		return fmt.Sprintf(
			"network flow %s %s:%d -> %s:%d",
			firstNonEmpty(observation.Network.Protocol, "unknown"),
			firstNonEmpty(observation.Network.SrcIP, "unknown"),
			observation.Network.SrcPort,
			firstNonEmpty(observation.Network.DstIP, "unknown"),
			observation.Network.DstPort,
		)
	case runtime.ObservationKindKubernetesAudit:
		return fmt.Sprintf(
			"k8s audit %s %s %s",
			firstNonEmpty(observation.ControlPlane.Verb, "observe"),
			firstNonEmpty(observation.ControlPlane.Resource, "resource"),
			firstNonEmpty(joinNamespacedName(observation.ControlPlane.Namespace, observation.ControlPlane.Name), "cluster"),
		)
	case runtime.ObservationKindTraceLink:
		return "trace link " + firstNonEmpty(observation.Trace.ServiceName, observation.Trace.TraceID, "service")
	case runtime.ObservationKindResponseOutcome:
		return "response outcome " + strings.TrimSpace(firstNonEmpty(
			metadataString(observation.Metadata, "action_type")+" "+metadataString(observation.Metadata, "action_status"),
			metadataString(observation.Metadata, "execution_id"),
			"action",
		))
	case runtime.ObservationKindRuntimeAlert:
		return "runtime alert " + firstNonEmpty(
			metadataString(observation.Metadata, "signal_name"),
			metadataString(observation.Metadata, "severity"),
			"alert",
		)
	default:
		return "runtime observation " + firstNonEmpty(string(observation.Kind), "unknown")
	}
}

func observationMetadata(observation *runtime.RuntimeObservation) map[string]any {
	metadata := make(map[string]any, 35)
	metadata["runtime_observation_id"] = observation.ID
	metadata["runtime_source"] = observation.Source
	addMetadataString(metadata, "resource_id", observation.ResourceID)
	addMetadataString(metadata, "resource_type", observation.ResourceType)
	addMetadataString(metadata, "cluster", observation.Cluster)
	addMetadataString(metadata, "namespace", observation.Namespace)
	addMetadataString(metadata, "node_name", observation.NodeName)
	addMetadataString(metadata, "workload_ref", observation.WorkloadRef)
	addMetadataString(metadata, "workload_uid", observation.WorkloadUID)
	addMetadataString(metadata, "container_id", observation.ContainerID)
	addMetadataString(metadata, "image_ref", observation.ImageRef)
	addMetadataString(metadata, "image_id", observation.ImageID)
	addMetadataString(metadata, "principal_id", observation.PrincipalID)
	addMetadataString(metadata, "trace_id", traceID(observation))
	addMetadataString(metadata, "span_id", spanID(observation))
	addMetadataString(metadata, "service_name", serviceName(observation))
	addMetadataString(metadata, "process_name", processName(observation))
	addMetadataString(metadata, "process_path", processPath(observation))
	addMetadataString(metadata, "file_operation", fileOperation(observation))
	addMetadataString(metadata, "file_path", filePath(observation))
	addMetadataString(metadata, "network_protocol", networkProtocol(observation))
	addMetadataString(metadata, "network_domain", networkDomain(observation))
	addMetadataString(metadata, "audit_verb", auditVerb(observation))
	addMetadataString(metadata, "audit_resource", auditResource(observation))
	addMetadataString(metadata, "audit_user", auditUser(observation))

	for _, key := range []string{
		"execution_id",
		"execution_status",
		"action_type",
		"action_status",
		"policy_id",
		"policy_name",
		"signal_name",
		"severity",
	} {
		addMetadataString(metadata, key, metadataString(observation.Metadata, key))
	}
	if len(observation.Tags) > 0 {
		metadata["tags"] = append([]string(nil), observation.Tags...)
	}
	return metadata
}

func processName(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Process == nil {
		return ""
	}
	return observation.Process.Name
}

func processPath(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Process == nil {
		return ""
	}
	return observation.Process.Path
}

func fileOperation(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.File == nil {
		return ""
	}
	return observation.File.Operation
}

func filePath(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.File == nil {
		return ""
	}
	return observation.File.Path
}

func networkProtocol(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Network == nil {
		return ""
	}
	return observation.Network.Protocol
}

func networkDomain(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Network == nil {
		return ""
	}
	return observation.Network.Domain
}

func traceID(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Trace == nil {
		return ""
	}
	return observation.Trace.TraceID
}

func spanID(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Trace == nil {
		return ""
	}
	return observation.Trace.SpanID
}

func serviceName(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.Trace == nil {
		return ""
	}
	return observation.Trace.ServiceName
}

func auditVerb(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.ControlPlane == nil {
		return ""
	}
	return observation.ControlPlane.Verb
}

func auditResource(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.ControlPlane == nil {
		return ""
	}
	return observation.ControlPlane.Resource
}

func auditUser(observation *runtime.RuntimeObservation) string {
	if observation == nil || observation.ControlPlane == nil {
		return ""
	}
	return observation.ControlPlane.User
}

func joinNamespacedName(namespace, name string) string {
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if namespace == "" {
		return name
	}
	if name == "" {
		return namespace
	}
	return namespace + "/" + name
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func addMetadataString(metadata map[string]any, key, value string) {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		metadata[key] = trimmed
	}
}

func metadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const runtimeObservationLegacyEventTypeKey = "legacy_event_type"
const runtimeObservationKindKey = "runtime_observation_kind"

const (
	maxObservationPayloadEntries   = 32
	maxObservationPayloadDepth     = 2
	maxObservationStringValueBytes = 1024
	maxObservationListEntries      = 32
)

var ErrInvalidObservation = errors.New("invalid runtime observation")

type RuntimeObservationKind string

const (
	ObservationKindProcessExec     RuntimeObservationKind = "process_exec"
	ObservationKindProcessExit     RuntimeObservationKind = "process_exit"
	ObservationKindFileOpen        RuntimeObservationKind = "file_open"
	ObservationKindFileWrite       RuntimeObservationKind = "file_write"
	ObservationKindNetworkFlow     RuntimeObservationKind = "network_flow"
	ObservationKindDNSQuery        RuntimeObservationKind = "dns_query"
	ObservationKindKubernetesAudit RuntimeObservationKind = "k8s_audit"
	ObservationKindRuntimeAlert    RuntimeObservationKind = "runtime_alert"
	ObservationKindTraceLink       RuntimeObservationKind = "trace_link"
	ObservationKindResponseOutcome RuntimeObservationKind = "response_outcome"
	ObservationKindUnknown         RuntimeObservationKind = "unknown"
)

type ControlPlaneContext struct {
	Source           string            `json:"source,omitempty"`
	Verb             string            `json:"verb,omitempty"`
	Stage            string            `json:"stage,omitempty"`
	User             string            `json:"user,omitempty"`
	ImpersonatedUser string            `json:"impersonated_user,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	RequestURI       string            `json:"request_uri,omitempty"`
	Resource         string            `json:"resource,omitempty"`
	Namespace        string            `json:"namespace,omitempty"`
	Name             string            `json:"name,omitempty"`
	Subresource      string            `json:"subresource,omitempty"`
	SourceIPs        []string          `json:"source_ips,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
}

type TraceContext struct {
	TraceID     string `json:"trace_id,omitempty"`
	SpanID      string `json:"span_id,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}

type RuntimeObservation struct {
	ID           string                 `json:"id"`
	Kind         RuntimeObservationKind `json:"kind"`
	Source       string                 `json:"source"`
	ObservedAt   time.Time              `json:"observed_at"`
	RecordedAt   time.Time              `json:"recorded_at,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	ResourceType string                 `json:"resource_type,omitempty"`

	Cluster     string `json:"cluster,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	NodeName    string `json:"node_name,omitempty"`
	WorkloadRef string `json:"workload_ref,omitempty"`
	WorkloadUID string `json:"workload_uid,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	ImageRef    string `json:"image_ref,omitempty"`
	ImageID     string `json:"image_id,omitempty"`
	PrincipalID string `json:"principal_id,omitempty"`

	Process      *ProcessEvent        `json:"process,omitempty"`
	Network      *NetworkEvent        `json:"network,omitempty"`
	File         *FileEvent           `json:"file,omitempty"`
	Container    *ContainerEvent      `json:"container,omitempty"`
	ControlPlane *ControlPlaneContext `json:"control_plane,omitempty"`
	Trace        *TraceContext        `json:"trace,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	Metadata     map[string]any       `json:"metadata,omitempty"`
	Raw          map[string]any       `json:"raw,omitempty"`
	Provenance   map[string]any       `json:"provenance,omitempty"`
}

func ObservationFromEvent(event *RuntimeEvent) (*RuntimeObservation, error) {
	if event == nil {
		return nil, nil
	}

	observation := observationFromEventBase(event)
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func observationFromEventBase(event *RuntimeEvent) *RuntimeObservation {
	if event == nil {
		return nil
	}

	observation := &RuntimeObservation{
		ID:           event.ID,
		Kind:         observationKindFromEvent(event),
		Source:       event.Source,
		ObservedAt:   event.Timestamp,
		ResourceID:   event.ResourceID,
		ResourceType: event.ResourceType,
		Process:      cloneProcessEvent(event.Process),
		Network:      cloneNetworkEvent(event.Network),
		File:         cloneFileEvent(event.File),
		Container:    cloneContainerEvent(event.Container),
		Metadata:     cloneRuntimeAnyMap(event.Metadata),
	}
	if strings.TrimSpace(event.EventType) != "" {
		if observation.Metadata == nil {
			observation.Metadata = make(map[string]any, 1)
		}
		observation.Metadata[runtimeObservationLegacyEventTypeKey] = strings.TrimSpace(event.EventType)
	}
	normalizeObservationContexts(observation)
	return observation
}

func (o *RuntimeObservation) AsRuntimeEvent() *RuntimeEvent {
	if o == nil {
		return nil
	}

	event := &RuntimeEvent{
		ID:           o.ID,
		Timestamp:    o.ObservedAt,
		Source:       o.Source,
		ResourceID:   firstNonEmptyRuntime(o.ResourceID, o.WorkloadRef, o.ContainerID),
		ResourceType: firstNonEmptyRuntime(o.ResourceType, observationResourceType(o)),
		EventType:    legacyEventTypeFromObservation(o),
		Process:      cloneProcessEvent(o.Process),
		Network:      cloneNetworkEvent(o.Network),
		File:         cloneFileEvent(o.File),
		Container:    cloneContainerEvent(o.Container),
		Metadata:     cloneRuntimeAnyMap(o.Metadata),
	}

	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	addMetadataString(event.Metadata, runtimeObservationKindKey, string(o.Kind))
	addMetadataString(event.Metadata, "cluster", o.Cluster)
	addMetadataString(event.Metadata, "node_name", o.NodeName)
	addMetadataString(event.Metadata, "namespace", o.Namespace)
	addMetadataString(event.Metadata, "workload_ref", o.WorkloadRef)
	addMetadataString(event.Metadata, "workload_uid", o.WorkloadUID)
	addMetadataString(event.Metadata, "principal_id", o.PrincipalID)
	addMetadataString(event.Metadata, "container_id", o.ContainerID)
	addMetadataString(event.Metadata, "image_ref", o.ImageRef)
	addMetadataString(event.Metadata, "image_id", o.ImageID)

	if o.Trace != nil {
		addMetadataString(event.Metadata, "trace_id", o.Trace.TraceID)
		addMetadataString(event.Metadata, "span_id", o.Trace.SpanID)
		addMetadataString(event.Metadata, "service_name", o.Trace.ServiceName)
	}
	if o.ControlPlane != nil {
		addMetadataString(event.Metadata, "audit_source", o.ControlPlane.Source)
		addMetadataString(event.Metadata, "audit_verb", o.ControlPlane.Verb)
		addMetadataString(event.Metadata, "audit_stage", o.ControlPlane.Stage)
		addMetadataString(event.Metadata, "audit_user", o.ControlPlane.User)
		addMetadataString(event.Metadata, "audit_impersonated_user", o.ControlPlane.ImpersonatedUser)
		addMetadataString(event.Metadata, "audit_user_agent", o.ControlPlane.UserAgent)
		addMetadataString(event.Metadata, "audit_request_uri", o.ControlPlane.RequestURI)
		addMetadataString(event.Metadata, "audit_resource", o.ControlPlane.Resource)
		addMetadataString(event.Metadata, "audit_subresource", o.ControlPlane.Subresource)
		if len(o.ControlPlane.SourceIPs) > 0 {
			event.Metadata["audit_source_ips"] = append([]string(nil), o.ControlPlane.SourceIPs...)
		}
		if len(o.ControlPlane.Annotations) > 0 {
			event.Metadata["audit_annotations"] = cloneRuntimeStringMap(o.ControlPlane.Annotations)
		}
	}

	return event
}

func observationFromResponseExecution(execution *ResponseExecution, action *ActionExecution) *RuntimeObservation {
	if execution == nil || action == nil {
		return nil
	}

	observedAt := action.StartTime
	if action.EndTime != nil {
		observedAt = *action.EndTime
	} else if execution.EndTime != nil {
		observedAt = *execution.EndTime
	}

	metadata := map[string]any{
		"policy_id":        execution.PolicyID,
		"policy_name":      execution.PolicyName,
		"execution_id":     execution.ID,
		"execution_status": execution.Status,
		"trigger_event":    execution.TriggerEvent,
		"action_type":      action.Type,
		"action_status":    action.Status,
		"approved_by":      execution.ApprovedBy,
		"approved_at":      execution.ApprovedAt,
	}
	if action.Output != "" {
		metadata["action_output"] = action.Output
	}
	if action.Error != "" {
		metadata["action_error"] = action.Error
	}
	if execution.Error != "" {
		metadata["execution_error"] = execution.Error
	}

	observation := &RuntimeObservation{
		ID:           execution.ID + ":" + string(action.Type),
		Kind:         ObservationKindResponseOutcome,
		Source:       "runtime_response",
		ObservedAt:   observedAt,
		ResourceID:   execution.ResourceID,
		ResourceType: execution.ResourceType,
		Metadata:     metadata,
		Tags:         []string{"response_outcome"},
	}
	normalized, err := NormalizeObservation(observation)
	if err != nil {
		return observation
	}
	return normalized
}

func NormalizeObservation(observation *RuntimeObservation) (*RuntimeObservation, error) {
	if observation == nil {
		return nil, nil
	}

	normalized := &RuntimeObservation{
		ID:           strings.TrimSpace(observation.ID),
		Kind:         RuntimeObservationKind(strings.TrimSpace(string(observation.Kind))),
		Source:       strings.TrimSpace(observation.Source),
		ObservedAt:   observation.ObservedAt.UTC(),
		RecordedAt:   observation.RecordedAt.UTC(),
		ResourceID:   strings.TrimSpace(observation.ResourceID),
		ResourceType: strings.TrimSpace(observation.ResourceType),
		Cluster:      strings.TrimSpace(observation.Cluster),
		Namespace:    strings.TrimSpace(observation.Namespace),
		NodeName:     strings.TrimSpace(observation.NodeName),
		WorkloadRef:  strings.TrimSpace(observation.WorkloadRef),
		WorkloadUID:  strings.TrimSpace(observation.WorkloadUID),
		ContainerID:  strings.TrimSpace(observation.ContainerID),
		ImageRef:     strings.TrimSpace(observation.ImageRef),
		ImageID:      strings.TrimSpace(observation.ImageID),
		PrincipalID:  strings.TrimSpace(observation.PrincipalID),
		Process:      cloneProcessEvent(observation.Process),
		Network:      cloneNetworkEvent(observation.Network),
		File:         cloneFileEvent(observation.File),
		Container:    cloneContainerEvent(observation.Container),
		ControlPlane: cloneControlPlaneContext(observation.ControlPlane),
		Trace:        cloneTraceContext(observation.Trace),
		Tags:         compactObservationTags(observation.Tags),
		Metadata:     cloneRuntimeAnyMap(observation.Metadata),
		Raw:          normalizeObservationAnyMap(cloneRuntimeAnyMap(observation.Raw), 0),
		Provenance:   normalizeObservationAnyMap(cloneRuntimeAnyMap(observation.Provenance), 0),
	}

	normalizeObservationContexts(normalized)

	if normalized.Kind == "" || normalized.Kind == ObservationKindUnknown {
		normalized.Kind = inferObservationKind(normalized)
	}
	if normalized.ObservedAt.IsZero() {
		normalized.ObservedAt = normalized.RecordedAt
	}
	if normalized.RecordedAt.IsZero() {
		normalized.RecordedAt = normalized.ObservedAt
	}
	if normalized.ResourceType == "" {
		normalized.ResourceType = observationResourceType(normalized)
	}
	if normalized.ResourceID == "" {
		normalized.ResourceID = firstNonEmptyRuntime(
			normalized.WorkloadRef,
			containerResourceID(normalized.ContainerID),
			controlPlaneResourceID(normalized.ControlPlane),
		)
	}
	if normalized.ID == "" {
		normalized.ID = generatedObservationID(normalized)
	}

	if err := validateObservation(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func observationKindFromEvent(event *RuntimeEvent) RuntimeObservationKind {
	if event == nil {
		return ObservationKindUnknown
	}
	if kind := observationKindFromMetadata(event.Metadata); kind != ObservationKindUnknown {
		return kind
	}
	switch event.EventType {
	case "process":
		return ObservationKindProcessExec
	case "network":
		if event.Network != nil && event.Network.Domain != "" {
			return ObservationKindDNSQuery
		}
		return ObservationKindNetworkFlow
	case "file":
		if event.File != nil && event.File.Operation == "read" {
			return ObservationKindFileOpen
		}
		return ObservationKindFileWrite
	default:
		return ObservationKindUnknown
	}
}

func legacyEventTypeFromObservation(observation *RuntimeObservation) string {
	if observation == nil {
		return ""
	}
	if eventType := stringMapValue(observation.Metadata, runtimeObservationLegacyEventTypeKey); eventType != "" {
		return eventType
	}
	switch observation.Kind {
	case ObservationKindProcessExec, ObservationKindProcessExit:
		return "process"
	case ObservationKindNetworkFlow, ObservationKindDNSQuery:
		return "network"
	case ObservationKindFileOpen, ObservationKindFileWrite:
		return "file"
	default:
		switch {
		case observation.Process != nil:
			return "process"
		case observation.Network != nil:
			return "network"
		case observation.File != nil:
			return "file"
		default:
			return string(observation.Kind)
		}
	}
}

func observationResourceType(observation *RuntimeObservation) string {
	switch {
	case observation.ContainerID != "":
		return "container"
	case observation.WorkloadRef != "":
		return "workload"
	case observation.ControlPlane != nil && observation.ControlPlane.Resource != "":
		return observation.ControlPlane.Resource
	default:
		return ""
	}
}

func normalizeObservationContexts(observation *RuntimeObservation) {
	if observation == nil {
		return
	}
	if observation.Process != nil {
		observation.Process.Name = strings.TrimSpace(observation.Process.Name)
		observation.Process.Path = strings.TrimSpace(observation.Process.Path)
		observation.Process.Cmdline = strings.TrimSpace(observation.Process.Cmdline)
		observation.Process.User = strings.TrimSpace(observation.Process.User)
		observation.Process.Hash = strings.TrimSpace(observation.Process.Hash)
		observation.Process.ParentName = strings.TrimSpace(observation.Process.ParentName)
		observation.Process.Ancestors = compactObservationTags(observation.Process.Ancestors)
	}
	if observation.Network != nil {
		observation.Network.Direction = strings.TrimSpace(observation.Network.Direction)
		observation.Network.Protocol = strings.TrimSpace(observation.Network.Protocol)
		observation.Network.SrcIP = strings.TrimSpace(observation.Network.SrcIP)
		observation.Network.DstIP = strings.TrimSpace(observation.Network.DstIP)
		observation.Network.Domain = strings.TrimSpace(observation.Network.Domain)
	}
	if observation.File != nil {
		observation.File.Operation = strings.TrimSpace(observation.File.Operation)
		observation.File.Path = strings.TrimSpace(observation.File.Path)
		observation.File.Hash = strings.TrimSpace(observation.File.Hash)
		observation.File.User = strings.TrimSpace(observation.File.User)
	}
	if observation.Container != nil {
		observation.Container.ContainerID = strings.TrimSpace(observation.Container.ContainerID)
		observation.Container.ContainerName = strings.TrimSpace(observation.Container.ContainerName)
		observation.Container.Image = strings.TrimSpace(observation.Container.Image)
		observation.Container.ImageID = strings.TrimSpace(observation.Container.ImageID)
		observation.Container.Namespace = strings.TrimSpace(observation.Container.Namespace)
		observation.Container.PodName = strings.TrimSpace(observation.Container.PodName)
		observation.Container.Capabilities = compactObservationTags(observation.Container.Capabilities)
		if observation.Namespace == "" {
			observation.Namespace = observation.Container.Namespace
		}
		if observation.ContainerID == "" {
			observation.ContainerID = observation.Container.ContainerID
		}
		if observation.ImageRef == "" {
			observation.ImageRef = observation.Container.Image
		}
		if observation.ImageID == "" {
			observation.ImageID = observation.Container.ImageID
		}
	}
	if observation.ControlPlane != nil {
		observation.ControlPlane.Source = strings.TrimSpace(observation.ControlPlane.Source)
		observation.ControlPlane.Verb = strings.TrimSpace(observation.ControlPlane.Verb)
		observation.ControlPlane.Stage = strings.TrimSpace(observation.ControlPlane.Stage)
		observation.ControlPlane.User = strings.TrimSpace(observation.ControlPlane.User)
		observation.ControlPlane.ImpersonatedUser = strings.TrimSpace(observation.ControlPlane.ImpersonatedUser)
		observation.ControlPlane.UserAgent = strings.TrimSpace(observation.ControlPlane.UserAgent)
		observation.ControlPlane.RequestURI = strings.TrimSpace(observation.ControlPlane.RequestURI)
		observation.ControlPlane.Resource = strings.TrimSpace(observation.ControlPlane.Resource)
		observation.ControlPlane.Namespace = strings.TrimSpace(observation.ControlPlane.Namespace)
		observation.ControlPlane.Name = strings.TrimSpace(observation.ControlPlane.Name)
		observation.ControlPlane.Subresource = strings.TrimSpace(observation.ControlPlane.Subresource)
		observation.ControlPlane.SourceIPs = compactObservationTags(observation.ControlPlane.SourceIPs)
		observation.ControlPlane.Annotations = cloneRuntimeStringMap(observation.ControlPlane.Annotations)
		if observation.Namespace == "" {
			observation.Namespace = observation.ControlPlane.Namespace
		}
		if observation.PrincipalID == "" {
			observation.PrincipalID = observation.ControlPlane.User
		}
	}
	if observation.Metadata != nil {
		serviceName := stringMapValue(observation.Metadata, "service_name")
		serviceNamespace := stringMapValue(observation.Metadata, "service_namespace")
		if observation.Cluster == "" {
			observation.Cluster = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "cluster"),
				stringMapValue(observation.Metadata, "cluster_name"),
				stringMapValue(observation.Metadata, "k8s_cluster_name"),
			)
		}
		if observation.NodeName == "" {
			observation.NodeName = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "node_name"),
				stringMapValue(observation.Metadata, "node"),
			)
		}
		if observation.WorkloadRef == "" {
			observation.WorkloadRef = stringMapValue(observation.Metadata, "workload_ref")
		}
		if observation.WorkloadUID == "" {
			observation.WorkloadUID = stringMapValue(observation.Metadata, "workload_uid")
		}
		if observation.ContainerID == "" {
			observation.ContainerID = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "container_id"),
				stringMapValue(observation.Metadata, "k8s_container_id"),
			)
		}
		if observation.ImageRef == "" {
			observation.ImageRef = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "image_ref"),
				stringMapValue(observation.Metadata, "image"),
				stringMapValue(observation.Metadata, "container_image"),
			)
		}
		if observation.ImageID == "" {
			observation.ImageID = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "image_id"),
				stringMapValue(observation.Metadata, "container_image_id"),
			)
		}
		if observation.Namespace == "" {
			observation.Namespace = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "namespace"),
				stringMapValue(observation.Metadata, "kubernetes_namespace"),
				serviceNamespace,
			)
		}
		if observation.PrincipalID == "" {
			observation.PrincipalID = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "principal_id"),
				stringMapValue(observation.Metadata, "credential_id"),
				stringMapValue(observation.Metadata, "access_key_id"),
				stringMapValue(observation.Metadata, "username"),
				stringMapValue(observation.Metadata, "user"),
			)
		}
		if observation.Trace == nil {
			observation.Trace = traceContextFromMetadata(observation.Metadata)
		} else if observation.Trace.ServiceName == "" {
			observation.Trace.ServiceName = serviceName
		}
	}
	observation.Trace = normalizeTraceContext(observation.Trace)
	if observation.WorkloadRef == "" {
		if kind, namespace, _ := parseObservationResourceRef(observation.ResourceID); isWorkloadResourceKind(kind) {
			observation.WorkloadRef = observation.ResourceID
			if observation.Namespace == "" {
				observation.Namespace = namespace
			}
		}
	}
	if observation.Namespace == "" {
		if _, namespace, _ := parseObservationResourceRef(observation.WorkloadRef); namespace != "" {
			observation.Namespace = namespace
		} else if _, namespace, _ := parseObservationResourceRef(observation.ResourceID); namespace != "" {
			observation.Namespace = namespace
		}
	}
	if observation.ContainerID == "" {
		if kind, _, name := parseObservationResourceRef(observation.ResourceID); kind == "container" {
			observation.ContainerID = name
		}
	}
	if observation.Trace != nil && observation.Trace.ServiceName != "" && observation.WorkloadRef == "" && observation.ContainerID == "" && controlPlaneResourceID(observation.ControlPlane) == "" {
		observation.ResourceID = serviceObservationResourceID(observation)
		observation.ResourceType = "service"
	}
	if observation.PrincipalID == "" {
		observation.PrincipalID = firstNonEmptyRuntime(
			observation.Process.GetUser(),
			observation.File.GetUser(),
		)
	}
}

func inferObservationKind(observation *RuntimeObservation) RuntimeObservationKind {
	switch {
	case observation == nil:
		return ObservationKindUnknown
	case observation.ControlPlane != nil:
		return ObservationKindKubernetesAudit
	case observation.Network != nil && observation.Network.Domain != "":
		return ObservationKindDNSQuery
	case observation.Network != nil:
		return ObservationKindNetworkFlow
	case observation.File != nil && strings.EqualFold(strings.TrimSpace(observation.File.Operation), "read"):
		return ObservationKindFileOpen
	case observation.File != nil:
		return ObservationKindFileWrite
	case observation.Process != nil:
		return ObservationKindProcessExec
	case observation.Trace != nil:
		return ObservationKindTraceLink
	case stringMapValue(observation.Metadata, "execution_id") != "" || slices.Contains(observation.Tags, "response_outcome"):
		return ObservationKindResponseOutcome
	default:
		return ObservationKindUnknown
	}
}

func parseObservationResourceRef(value string) (string, string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", ""
	}
	kind, remainder, ok := strings.Cut(value, ":")
	if !ok {
		return "", "", ""
	}
	kind = strings.TrimSpace(kind)
	remainder = strings.TrimSpace(remainder)
	if kind == "" || remainder == "" {
		return "", "", ""
	}
	if kind == "container" {
		return kind, "", remainder
	}
	namespace, name, hasNamespace := strings.Cut(remainder, "/")
	if hasNamespace {
		namespace = strings.TrimSpace(namespace)
		name = strings.TrimSpace(name)
		if namespace == "" || name == "" {
			return kind, "", ""
		}
		return kind, namespace, name
	}
	return kind, "", remainder
}

func isWorkloadResourceKind(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "workload", "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob":
		return true
	default:
		return false
	}
}

func traceContextFromMetadata(metadata map[string]any) *TraceContext {
	if len(metadata) == 0 {
		return nil
	}
	return normalizeTraceContext(&TraceContext{
		TraceID:     stringMapValue(metadata, "trace_id"),
		SpanID:      stringMapValue(metadata, "span_id"),
		ServiceName: stringMapValue(metadata, "service_name"),
	})
}

func normalizeTraceContext(trace *TraceContext) *TraceContext {
	if trace == nil {
		return nil
	}
	trace.TraceID = strings.TrimSpace(trace.TraceID)
	trace.SpanID = strings.TrimSpace(trace.SpanID)
	trace.ServiceName = strings.TrimSpace(trace.ServiceName)
	if trace.TraceID == "" && trace.SpanID == "" && trace.ServiceName == "" {
		return nil
	}
	return trace
}

func serviceObservationResourceID(observation *RuntimeObservation) string {
	if observation == nil || observation.Trace == nil {
		return ""
	}
	serviceName := strings.TrimSpace(observation.Trace.ServiceName)
	if serviceName == "" {
		return ""
	}
	namespace := strings.TrimSpace(observation.Namespace)
	if namespace == "" && observation.Metadata != nil {
		namespace = stringMapValue(observation.Metadata, "service_namespace")
	}
	if namespace != "" {
		return "service:" + namespace + "/" + serviceName
	}
	return "service:" + serviceName
}

func (p *ProcessEvent) GetUser() string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p.User)
}

func (f *FileEvent) GetUser() string {
	if f == nil {
		return ""
	}
	return strings.TrimSpace(f.User)
}

func validateObservation(observation *RuntimeObservation) error {
	if observation == nil {
		return nil
	}
	if observation.Source == "" {
		return fmt.Errorf("%w: missing source", ErrInvalidObservation)
	}
	if observation.Kind == "" || observation.Kind == ObservationKindUnknown {
		return fmt.Errorf("%w: missing observation kind", ErrInvalidObservation)
	}
	if observation.ObservedAt.IsZero() {
		return fmt.Errorf("%w: missing observed_at", ErrInvalidObservation)
	}
	switch observation.Kind {
	case ObservationKindProcessExec, ObservationKindProcessExit:
		if observation.Process == nil {
			return fmt.Errorf("%w: %s observations require process context", ErrInvalidObservation, observation.Kind)
		}
	case ObservationKindNetworkFlow, ObservationKindDNSQuery:
		if observation.Network == nil {
			return fmt.Errorf("%w: %s observations require network context", ErrInvalidObservation, observation.Kind)
		}
	case ObservationKindFileOpen, ObservationKindFileWrite:
		if observation.File == nil {
			return fmt.Errorf("%w: %s observations require file context", ErrInvalidObservation, observation.Kind)
		}
	case ObservationKindKubernetesAudit:
		if observation.ControlPlane == nil {
			return fmt.Errorf("%w: %s observations require control-plane context", ErrInvalidObservation, observation.Kind)
		}
	case ObservationKindTraceLink:
		if observation.Trace == nil {
			return fmt.Errorf("%w: %s observations require trace context", ErrInvalidObservation, observation.Kind)
		}
	}
	return nil
}

func addMetadataString(metadata map[string]any, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	metadata[key] = value
}

func stringMapValue(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func observationKindFromMetadata(metadata map[string]any) RuntimeObservationKind {
	switch kind := RuntimeObservationKind(strings.TrimSpace(stringMapValue(metadata, runtimeObservationKindKey))); kind {
	case ObservationKindProcessExec,
		ObservationKindProcessExit,
		ObservationKindFileOpen,
		ObservationKindFileWrite,
		ObservationKindNetworkFlow,
		ObservationKindDNSQuery,
		ObservationKindKubernetesAudit,
		ObservationKindRuntimeAlert,
		ObservationKindTraceLink,
		ObservationKindResponseOutcome:
		return kind
	default:
		return ObservationKindUnknown
	}
}

func cloneProcessEvent(input *ProcessEvent) *ProcessEvent {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.Ancestors = append([]string(nil), input.Ancestors...)
	return &cloned
}

func cloneControlPlaneContext(input *ControlPlaneContext) *ControlPlaneContext {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.SourceIPs = append([]string(nil), input.SourceIPs...)
	cloned.Annotations = cloneRuntimeStringMap(input.Annotations)
	return &cloned
}

func cloneTraceContext(input *TraceContext) *TraceContext {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

func cloneNetworkEvent(input *NetworkEvent) *NetworkEvent {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

func cloneFileEvent(input *FileEvent) *FileEvent {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

func cloneContainerEvent(input *ContainerEvent) *ContainerEvent {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.Capabilities = append([]string(nil), input.Capabilities...)
	return &cloned
}

func compactObservationTags(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	compacted := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || slices.Contains(compacted, trimmed) {
			continue
		}
		compacted = append(compacted, trimmed)
	}
	if len(compacted) == 0 {
		return nil
	}
	return compacted
}

func normalizeObservationAnyMap(input map[string]any, depth int) map[string]any {
	if len(input) == 0 {
		return nil
	}

	originalKeys := make([]string, 0, len(input))
	for key := range input {
		if trimmed := strings.TrimSpace(key); trimmed != "" {
			originalKeys = append(originalKeys, key)
		}
	}
	if len(originalKeys) == 0 {
		return nil
	}
	sort.Slice(originalKeys, func(i, j int) bool {
		leftTrimmed := strings.TrimSpace(originalKeys[i])
		rightTrimmed := strings.TrimSpace(originalKeys[j])
		if leftTrimmed == rightTrimmed {
			return originalKeys[i] < originalKeys[j]
		}
		return leftTrimmed < rightTrimmed
	})

	originalByTrimmed := make(map[string]string, len(originalKeys))
	keys := make([]string, 0, len(originalKeys))
	for _, key := range originalKeys {
		trimmed := strings.TrimSpace(key)
		if _, exists := originalByTrimmed[trimmed]; exists {
			continue
		}
		originalByTrimmed[trimmed] = key
		keys = append(keys, trimmed)
	}
	if len(keys) == 0 {
		return nil
	}
	if len(keys) > maxObservationPayloadEntries {
		keys = keys[:maxObservationPayloadEntries]
	}
	normalized := make(map[string]any, len(keys))
	for _, key := range keys {
		value := normalizeObservationValue(input[originalByTrimmed[key]], depth+1)
		if value == nil {
			continue
		}
		normalized[key] = value
	}
	if len(normalized) == 0 {
		if depth > 0 {
			return map[string]any{}
		}
		return nil
	}
	return normalized
}

func normalizeObservationValue(value any, depth int) any {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		trimmed = truncateObservationString(trimmed)
		if trimmed == "" {
			return nil
		}
		return trimmed
	case []string:
		return compactLimitedObservationStrings(typed)
	case []any:
		if depth >= maxObservationPayloadDepth {
			return nil
		}
		normalized := make([]any, 0, min(len(typed), maxObservationListEntries))
		for _, entry := range typed {
			if len(normalized) == maxObservationListEntries {
				break
			}
			next := normalizeObservationValue(entry, depth+1)
			if next != nil {
				normalized = append(normalized, next)
			}
		}
		if len(normalized) == 0 {
			return nil
		}
		return normalized
	case map[string]any:
		if depth >= maxObservationPayloadDepth {
			return nil
		}
		return normalizeObservationAnyMap(typed, depth)
	default:
		return value
	}
}

func compactLimitedObservationStrings(values []string) []string {
	compacted := compactObservationTags(values)
	if len(compacted) == 0 {
		return nil
	}
	if len(compacted) > maxObservationListEntries {
		compacted = compacted[:maxObservationListEntries]
	}
	for i := range compacted {
		compacted[i] = truncateObservationString(compacted[i])
	}
	return compacted
}

func truncateObservationString(value string) string {
	if len(value) <= maxObservationStringValueBytes {
		return value
	}
	value = value[:maxObservationStringValueBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func generatedObservationID(observation *RuntimeObservation) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		observation.Source,
		string(observation.Kind),
		observation.ResourceID,
		observation.ResourceType,
		observation.WorkloadRef,
		observation.ContainerID,
		observation.PrincipalID,
		observation.ObservedAt.UTC().Format(time.RFC3339Nano),
		observationDetailKey(observation),
	}, "|")))
	return "runtime:" + string(observation.Kind) + ":" + hex.EncodeToString(digest[:8])
}

func observationDetailKey(observation *RuntimeObservation) string {
	switch {
	case observation == nil:
		return ""
	case observation.Process != nil:
		return strings.Join([]string{observation.Process.Name, observation.Process.Path, observation.Process.Cmdline}, "|")
	case observation.Network != nil:
		return strings.Join([]string{
			observation.Network.Protocol,
			observation.Network.SrcIP,
			fmt.Sprintf("%d", observation.Network.SrcPort),
			observation.Network.DstIP,
			fmt.Sprintf("%d", observation.Network.DstPort),
			observation.Network.Domain,
		}, "|")
	case observation.File != nil:
		return strings.Join([]string{observation.File.Operation, observation.File.Path, observation.File.Hash}, "|")
	case observation.ControlPlane != nil:
		return strings.Join([]string{
			observation.ControlPlane.Verb,
			observation.ControlPlane.Resource,
			observation.ControlPlane.Namespace,
			observation.ControlPlane.Name,
			observation.ControlPlane.Subresource,
		}, "|")
	default:
		return ""
	}
}

func containerResourceID(containerID string) string {
	containerID = strings.TrimSpace(containerID)
	if containerID == "" {
		return ""
	}
	return "container:" + containerID
}

func controlPlaneResourceID(controlPlane *ControlPlaneContext) string {
	if controlPlane == nil {
		return ""
	}
	resource := strings.TrimSpace(controlPlane.Resource)
	if resource == "" {
		return ""
	}
	name := strings.TrimSpace(controlPlane.Name)
	namespace := strings.TrimSpace(controlPlane.Namespace)
	if name == "" {
		return resource
	}
	if namespace == "" {
		return resource + ":" + name
	}
	return resource + ":" + namespace + "/" + name
}

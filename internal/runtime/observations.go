package runtime

import (
	"strings"
	"time"
)

const runtimeObservationLegacyEventTypeKey = "legacy_event_type"

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

func ObservationFromEvent(event *RuntimeEvent) *RuntimeObservation {
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

	if event.Container != nil {
		observation.Namespace = event.Container.Namespace
		observation.ContainerID = event.Container.ContainerID
		observation.ImageRef = event.Container.Image
		observation.ImageID = event.Container.ImageID
	}

	if observation.Metadata != nil {
		observation.Cluster = stringMapValue(observation.Metadata, "cluster")
		observation.NodeName = firstNonEmptyRuntime(stringMapValue(observation.Metadata, "node_name"), stringMapValue(observation.Metadata, "node"))
		observation.WorkloadRef = stringMapValue(observation.Metadata, "workload_ref")
		observation.WorkloadUID = stringMapValue(observation.Metadata, "workload_uid")
		observation.PrincipalID = firstNonEmptyRuntime(
			stringMapValue(observation.Metadata, "principal_id"),
			stringMapValue(observation.Metadata, "credential_id"),
			stringMapValue(observation.Metadata, "access_key_id"),
		)
		if observation.Namespace == "" {
			observation.Namespace = firstNonEmptyRuntime(
				stringMapValue(observation.Metadata, "namespace"),
				stringMapValue(observation.Metadata, "kubernetes_namespace"),
			)
		}
	}

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

	return &RuntimeObservation{
		ID:           execution.ID + ":" + string(action.Type),
		Kind:         ObservationKindResponseOutcome,
		Source:       "runtime_response",
		ObservedAt:   observedAt,
		ResourceID:   execution.ResourceID,
		ResourceType: execution.ResourceType,
		Metadata:     metadata,
		Tags:         []string{"response_outcome"},
	}
}

func observationKindFromEvent(event *RuntimeEvent) RuntimeObservationKind {
	if event == nil {
		return ObservationKindUnknown
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

func cloneProcessEvent(input *ProcessEvent) *ProcessEvent {
	if input == nil {
		return nil
	}
	cloned := *input
	cloned.Ancestors = append([]string(nil), input.Ancestors...)
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

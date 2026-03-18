package otel

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/runtime/adapters"
)

const sourceName = "opentelemetry"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	ResourceLogs  []resourceLogs  `json:"resourceLogs,omitempty"`
	ResourceSpans []resourceSpans `json:"resourceSpans,omitempty"`
}

type resourceLogs struct {
	Resource  resource    `json:"resource,omitempty"`
	ScopeLogs []scopeLogs `json:"scopeLogs,omitempty"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource,omitempty"`
	ScopeSpans []scopeSpans `json:"scopeSpans,omitempty"`
}

type resource struct {
	Attributes []keyValue `json:"attributes,omitempty"`
}

type scopeLogs struct {
	Scope      instrumentationScope `json:"scope,omitempty"`
	LogRecords []logRecord          `json:"logRecords,omitempty"`
}

type scopeSpans struct {
	Scope instrumentationScope `json:"scope,omitempty"`
	Spans []span               `json:"spans,omitempty"`
}

type instrumentationScope struct {
	Name       string     `json:"name,omitempty"`
	Version    string     `json:"version,omitempty"`
	Attributes []keyValue `json:"attributes,omitempty"`
}

type logRecord struct {
	TimeUnixNano         uint64Value `json:"timeUnixNano,omitempty"`
	ObservedTimeUnixNano uint64Value `json:"observedTimeUnixNano,omitempty"`
	SeverityNumber       int64Value  `json:"severityNumber,omitempty"`
	SeverityText         string      `json:"severityText,omitempty"`
	Body                 *anyValue   `json:"body,omitempty"`
	Attributes           []keyValue  `json:"attributes,omitempty"`
	TraceID              string      `json:"traceId,omitempty"`
	SpanID               string      `json:"spanId,omitempty"`
	Flags                uint64Value `json:"flags,omitempty"`
}

type span struct {
	TraceID           string      `json:"traceId,omitempty"`
	SpanID            string      `json:"spanId,omitempty"`
	ParentSpanID      string      `json:"parentSpanId,omitempty"`
	StartTimeUnixNano uint64Value `json:"startTimeUnixNano,omitempty"`
	EndTimeUnixNano   uint64Value `json:"endTimeUnixNano,omitempty"`
	Name              string      `json:"name,omitempty"`
	Kind              int64Value  `json:"kind,omitempty"`
	Attributes        []keyValue  `json:"attributes,omitempty"`
	Events            []spanEvent `json:"events,omitempty"`
	Status            *spanStatus `json:"status,omitempty"`
}

type spanEvent struct {
	Name                   string      `json:"name,omitempty"`
	TimeUnixNano           uint64Value `json:"timeUnixNano,omitempty"`
	DroppedAttributesCount uint64Value `json:"droppedAttributesCount,omitempty"`
}

type spanStatus struct {
	Message string     `json:"message,omitempty"`
	Code    int64Value `json:"code,omitempty"`
}

type keyValue struct {
	Key   string    `json:"key,omitempty"`
	Value *anyValue `json:"value,omitempty"`
}

type arrayValue struct {
	Values []*anyValue `json:"values,omitempty"`
}

type kvlistValue struct {
	Values []keyValue `json:"values,omitempty"`
}

type anyValue struct {
	StringValue *string      `json:"stringValue,omitempty"`
	BoolValue   *bool        `json:"boolValue,omitempty"`
	IntValue    int64Value   `json:"intValue,omitempty"`
	DoubleValue float64Value `json:"doubleValue,omitempty"`
	ArrayValue  *arrayValue  `json:"arrayValue,omitempty"`
	KvlistValue *kvlistValue `json:"kvlistValue,omitempty"`
	BytesValue  *string      `json:"bytesValue,omitempty"`
}

type uint64Value struct {
	Value uint64
	Set   bool
}

type int64Value struct {
	Value int64
	Set   bool
}

type float64Value struct {
	Value float64
	Set   bool
}

func (Adapter) Source() string {
	return sourceName
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	var topLevel map[string]json.RawMessage
	if err := json.Unmarshal(raw, &topLevel); err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: %w", err)
	}

	var envelope payload
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: %w", err)
	}

	observations := make([]*runtime.RuntimeObservation, 0)
	for _, resourceLogs := range envelope.ResourceLogs {
		resourceAttrs := attributesToMap(resourceLogs.Resource.Attributes)
		for _, scopeLogs := range resourceLogs.ScopeLogs {
			scopeAttrs := attributesToMap(scopeLogs.Scope.Attributes)
			for idx, record := range scopeLogs.LogRecords {
				observation, err := observationFromLogRecord(resourceAttrs, scopeLogs.Scope, scopeAttrs, record, idx)
				if err != nil {
					return nil, err
				}
				observations = append(observations, observation)
			}
		}
	}

	for _, resourceSpans := range envelope.ResourceSpans {
		resourceAttrs := attributesToMap(resourceSpans.Resource.Attributes)
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			scopeAttrs := attributesToMap(scopeSpans.Scope.Attributes)
			for idx, span := range scopeSpans.Spans {
				observation, err := observationFromSpan(resourceAttrs, scopeSpans.Scope, scopeAttrs, span, idx)
				if err != nil {
					return nil, err
				}
				observations = append(observations, observation)
			}
		}
	}

	if len(observations) == 0 && !hasKnownOTLPEnvelope(topLevel) {
		return nil, fmt.Errorf("decode opentelemetry payload: unsupported event")
	}
	return observations, nil
}

func observationFromLogRecord(resourceAttrs map[string]any, scope instrumentationScope, scopeAttrs map[string]any, record logRecord, index int) (*runtime.RuntimeObservation, error) {
	observedAt, err := unixNanoToTime(record.TimeUnixNano)
	if err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: invalid log timestamp: %w", err)
	}
	recordedAt, err := unixNanoToTime(record.ObservedTimeUnixNano)
	if err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: invalid log observed timestamp: %w", err)
	}
	recordAttrs := attributesToMap(record.Attributes)

	traceID := normalizeTraceID(record.TraceID)
	spanID := normalizeTraceID(record.SpanID)
	serviceName := firstStringAttr(resourceAttrs, "service.name")
	kind := runtime.ObservationKindRuntimeAlert
	if traceID != "" || spanID != "" || serviceName != "" {
		kind = runtime.ObservationKindTraceLink
	}

	metadata := map[string]any{
		"otel_source_type":  "log",
		"otel_record_index": index,
	}
	if severityText := strings.TrimSpace(record.SeverityText); severityText != "" {
		metadata["severity_text"] = severityText
	}
	if record.SeverityNumber.Set {
		metadata["severity_number"] = record.SeverityNumber.Value
	}
	if record.Flags.Set {
		metadata["trace_flags"] = record.Flags.Value
	}
	if body := record.Body.value(); body != nil {
		metadata["log_body"] = body
	}
	applyScopeMetadata(metadata, scope, scopeAttrs)

	observation := &runtime.RuntimeObservation{
		Kind:       kind,
		Source:     sourceName,
		ObservedAt: observedAt,
		RecordedAt: recordedAt,
		Metadata:   metadata,
		Raw: map[string]any{
			"attributes": recordAttrs,
		},
		Provenance: map[string]any{
			"resource_attributes": resourceAttrs,
			"scope_attributes":    scopeAttrs,
		},
		Tags: adapters.CompactTags(
			"opentelemetry",
			"otlp_log",
			string(kind),
			strings.ToLower(strings.TrimSpace(record.SeverityText)),
		),
	}
	if traceID != "" || spanID != "" || serviceName != "" {
		observation.Trace = &runtime.TraceContext{
			TraceID:     traceID,
			SpanID:      spanID,
			ServiceName: serviceName,
		}
	}
	applyResourceContext(observation, resourceAttrs)
	applyPrincipalContext(observation, recordAttrs)
	if len(recordAttrs) > 0 {
		observation.Metadata["otel_log_attributes"] = recordAttrs
	}

	normalized, err := runtime.NormalizeObservation(observation)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func observationFromSpan(resourceAttrs map[string]any, scope instrumentationScope, scopeAttrs map[string]any, span span, index int) (*runtime.RuntimeObservation, error) {
	observedAt, err := unixNanoToTime(span.StartTimeUnixNano)
	if err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: invalid span start timestamp: %w", err)
	}
	recordedAt, err := unixNanoToTime(span.EndTimeUnixNano)
	if err != nil {
		return nil, fmt.Errorf("decode opentelemetry payload: invalid span end timestamp: %w", err)
	}
	spanAttrs := attributesToMap(span.Attributes)

	metadata := map[string]any{
		"otel_source_type":  "span",
		"otel_record_index": index,
		"span_name":         strings.TrimSpace(span.Name),
		"span_kind":         spanKindName(span.Kind.Value),
		"parent_span_id":    normalizeTraceID(span.ParentSpanID),
		"span_event_count":  len(span.Events),
	}
	if span.Status != nil {
		metadata["span_status_code"] = spanStatusName(span.Status.Code.Value)
		if message := strings.TrimSpace(span.Status.Message); message != "" {
			metadata["span_status_message"] = message
		}
	}
	applyScopeMetadata(metadata, scope, scopeAttrs)

	observation := &runtime.RuntimeObservation{
		Kind:       runtime.ObservationKindTraceLink,
		Source:     sourceName,
		ObservedAt: observedAt,
		RecordedAt: recordedAt,
		Trace: &runtime.TraceContext{
			TraceID:     normalizeTraceID(span.TraceID),
			SpanID:      normalizeTraceID(span.SpanID),
			ServiceName: firstStringAttr(resourceAttrs, "service.name"),
		},
		Metadata: metadata,
		Raw: map[string]any{
			"attributes": spanAttrs,
		},
		Provenance: map[string]any{
			"resource_attributes": resourceAttrs,
			"scope_attributes":    scopeAttrs,
		},
		Tags: adapters.CompactTags(
			"opentelemetry",
			"otlp_span",
			spanKindName(span.Kind.Value),
		),
	}
	applyResourceContext(observation, resourceAttrs)
	applyPrincipalContext(observation, spanAttrs)
	if len(spanAttrs) > 0 {
		observation.Metadata["otel_span_attributes"] = spanAttrs
	}

	normalized, err := runtime.NormalizeObservation(observation)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func applyScopeMetadata(metadata map[string]any, scope instrumentationScope, scopeAttrs map[string]any) {
	if metadata == nil {
		return
	}
	if name := strings.TrimSpace(scope.Name); name != "" {
		metadata["otel_scope_name"] = name
	}
	if version := strings.TrimSpace(scope.Version); version != "" {
		metadata["otel_scope_version"] = version
	}
	if len(scopeAttrs) > 0 {
		metadata["otel_scope_attributes"] = scopeAttrs
	}
}

func applyResourceContext(observation *runtime.RuntimeObservation, resourceAttrs map[string]any) {
	if observation == nil || len(resourceAttrs) == 0 {
		return
	}

	kubernetesNamespace := firstStringAttr(resourceAttrs, "k8s.namespace.name")
	observation.Cluster = firstStringAttr(resourceAttrs, "k8s.cluster.name", "k8s.cluster.uid")
	observation.Namespace = firstStringAttr(resourceAttrs, "k8s.namespace.name", "service.namespace")
	observation.NodeName = firstStringAttr(resourceAttrs, "k8s.node.name", "host.name")
	observation.ContainerID = firstStringAttr(resourceAttrs, "container.id")
	observation.ImageRef = firstStringAttr(resourceAttrs, "container.image.name")
	observation.ImageID = firstStringAttr(resourceAttrs, "container.image.id")
	observation.WorkloadRef, observation.WorkloadUID = workloadFromResourceAttrs(resourceAttrs, kubernetesNamespace)

	if observation.ResourceID == "" && observation.WorkloadRef == "" {
		serviceName := firstStringAttr(resourceAttrs, "service.name")
		serviceNamespace := firstStringAttr(resourceAttrs, "service.namespace")
		if serviceName != "" {
			observation.ResourceType = "service"
			observation.ResourceID = serviceResourceID(serviceNamespace, serviceName)
		}
	}

	if observation.Metadata == nil {
		observation.Metadata = make(map[string]any)
	}
	if serviceNamespace := firstStringAttr(resourceAttrs, "service.namespace"); serviceNamespace != "" {
		observation.Metadata["service_namespace"] = serviceNamespace
	}
	if serviceInstanceID := firstStringAttr(resourceAttrs, "service.instance.id"); serviceInstanceID != "" {
		observation.Metadata["service_instance_id"] = serviceInstanceID
	}
	if podName := firstStringAttr(resourceAttrs, "k8s.pod.name"); podName != "" {
		observation.Metadata["k8s_pod_name"] = podName
	}
	if podUID := firstStringAttr(resourceAttrs, "k8s.pod.uid"); podUID != "" && observation.WorkloadUID == "" {
		observation.WorkloadUID = podUID
	}
	if containerName := firstStringAttr(resourceAttrs, "k8s.container.name"); containerName != "" {
		observation.Metadata["k8s_container_name"] = containerName
	}
}

func applyPrincipalContext(observation *runtime.RuntimeObservation, attrs map[string]any) {
	if observation == nil {
		return
	}
	observation.PrincipalID = firstNonEmpty(
		observation.PrincipalID,
		firstStringAttr(attrs, "enduser.id", "user.id", "principal.id"),
	)
}

func workloadFromResourceAttrs(resourceAttrs map[string]any, namespace string) (string, string) {
	candidates := []struct {
		kind string
		name string
		uid  string
	}{
		{kind: "deployment", name: firstStringAttr(resourceAttrs, "k8s.deployment.name"), uid: firstStringAttr(resourceAttrs, "k8s.deployment.uid")},
		{kind: "statefulset", name: firstStringAttr(resourceAttrs, "k8s.statefulset.name"), uid: firstStringAttr(resourceAttrs, "k8s.statefulset.uid")},
		{kind: "daemonset", name: firstStringAttr(resourceAttrs, "k8s.daemonset.name"), uid: firstStringAttr(resourceAttrs, "k8s.daemonset.uid")},
		{kind: "job", name: firstStringAttr(resourceAttrs, "k8s.job.name"), uid: firstStringAttr(resourceAttrs, "k8s.job.uid")},
		{kind: "cronjob", name: firstStringAttr(resourceAttrs, "k8s.cronjob.name"), uid: firstStringAttr(resourceAttrs, "k8s.cronjob.uid")},
		{kind: "replicaset", name: firstStringAttr(resourceAttrs, "k8s.replicaset.name"), uid: firstStringAttr(resourceAttrs, "k8s.replicaset.uid")},
		{kind: "pod", name: firstStringAttr(resourceAttrs, "k8s.pod.name"), uid: firstStringAttr(resourceAttrs, "k8s.pod.uid")},
	}
	for _, candidate := range candidates {
		if candidate.name == "" {
			continue
		}
		if namespace != "" {
			return candidate.kind + ":" + namespace + "/" + candidate.name, candidate.uid
		}
		return candidate.kind + ":" + candidate.name, candidate.uid
	}
	return "", ""
}

func serviceResourceID(namespace, name string) string {
	if namespace != "" {
		return "service:" + namespace + "/" + name
	}
	return "service:" + name
}

func attributesToMap(values []keyValue) map[string]any {
	if len(values) == 0 {
		return nil
	}
	attrs := make(map[string]any, len(values))
	for _, kv := range values {
		key := strings.TrimSpace(kv.Key)
		if key == "" || kv.Value == nil {
			continue
		}
		if value := kv.Value.value(); value != nil {
			attrs[key] = value
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func (v *anyValue) value() any {
	if v == nil {
		return nil
	}
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.BoolValue != nil:
		return *v.BoolValue
	case v.IntValue.Set:
		return v.IntValue.Value
	case v.DoubleValue.Set:
		return v.DoubleValue.Value
	case v.ArrayValue != nil:
		values := make([]any, 0, len(v.ArrayValue.Values))
		for _, entry := range v.ArrayValue.Values {
			if next := entry.value(); next != nil {
				values = append(values, next)
			}
		}
		if len(values) == 0 {
			return nil
		}
		return values
	case v.KvlistValue != nil:
		return attributesToMap(v.KvlistValue.Values)
	case v.BytesValue != nil:
		return *v.BytesValue
	default:
		return nil
	}
}

func firstStringAttr(attrs map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := attrs[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeTraceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func hasKnownOTLPEnvelope(topLevel map[string]json.RawMessage) bool {
	if len(topLevel) == 0 {
		return false
	}
	_, hasLogs := topLevel["resourceLogs"]
	_, hasSpans := topLevel["resourceSpans"]
	return hasLogs || hasSpans
}

func spanKindName(value int64) string {
	switch value {
	case 1:
		return "internal"
	case 2:
		return "server"
	case 3:
		return "client"
	case 4:
		return "producer"
	case 5:
		return "consumer"
	default:
		return ""
	}
}

func spanStatusName(value int64) string {
	switch value {
	case 1:
		return "ok"
	case 2:
		return "error"
	default:
		return "unset"
	}
}

func unixNanoToTime(value uint64Value) (time.Time, error) {
	if !value.Set || value.Value == 0 {
		return time.Time{}, nil
	}
	if value.Value > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("timestamp %d overflows int64", value.Value)
	}
	return time.Unix(0, int64(value.Value)).UTC(), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (v *uint64Value) UnmarshalJSON(data []byte) error {
	parsed, set, err := parseUnsignedValue(data)
	if err != nil {
		return err
	}
	v.Value = parsed
	v.Set = set
	return nil
}

func (v *int64Value) UnmarshalJSON(data []byte) error {
	parsed, set, err := parseSignedValue(data)
	if err != nil {
		return err
	}
	v.Value = parsed
	v.Set = set
	return nil
}

func (v *float64Value) UnmarshalJSON(data []byte) error {
	parsed, set, err := parseFloatValue(data)
	if err != nil {
		return err
	}
	v.Value = parsed
	v.Set = set
	return nil
}

func parseUnsignedValue(data []byte) (uint64, bool, error) {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return 0, false, nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse uint64: %w", err)
	}
	return value, true, nil
}

func parseSignedValue(data []byte) (int64, bool, error) {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return 0, false, nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse int64: %w", err)
	}
	return value, true, nil
}

func parseFloatValue(data []byte) (float64, bool, error) {
	text := strings.TrimSpace(string(data))
	if text == "" || text == "null" {
		return 0, false, nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse float64: %w", err)
	}
	return value, true, nil
}

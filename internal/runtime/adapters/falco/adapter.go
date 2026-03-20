package falco

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

const sourceName = "falco"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	Time         string         `json:"time"`
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Output       string         `json:"output"`
	Hostname     string         `json:"hostname"`
	Source       string         `json:"source"`
	Tags         []string       `json:"tags"`
	OutputFields map[string]any `json:"output_fields"`
}

func (Adapter) Source() string {
	return sourceName
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	var event payload
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("decode falco payload: %w", err)
	}

	observedAt, err := falcoObservedAt(event)
	if err != nil {
		return nil, err
	}
	if observedAt.IsZero() || strings.TrimSpace(event.Rule) == "" {
		return nil, fmt.Errorf("decode falco payload: unsupported event")
	}

	outputFields := cloneAnyMap(event.OutputFields)
	metadata := map[string]any{
		"rule_name":           strings.TrimSpace(event.Rule),
		"severity":            strings.TrimSpace(event.Priority),
		"description":         strings.TrimSpace(event.Output),
		"falco_event_source":  strings.TrimSpace(event.Source),
		"falco_hostname":      strings.TrimSpace(event.Hostname),
		"falco_rule_tags":     compactAnyStrings(event.Tags),
		"falco_output_fields": outputFields,
	}
	if eventType := stringField(outputFields, "evt.type"); eventType != "" {
		metadata["falco_event_type"] = eventType
	}
	if direction := falcoDirection(outputFields); direction != "" {
		metadata["falco_event_direction"] = direction
	}

	observation := &runtime.RuntimeObservation{
		Kind:       runtime.ObservationKindRuntimeAlert,
		Source:     sourceName,
		ObservedAt: observedAt,
		NodeName:   strings.TrimSpace(event.Hostname),
		Process:    falcoProcess(outputFields),
		Network:    falcoNetwork(outputFields),
		File:       falcoFile(outputFields),
		Container:  falcoContainer(outputFields),
		Metadata:   metadata,
		Raw: map[string]any{
			"output_fields": outputFields,
		},
		Provenance: map[string]any{
			"rule":     strings.TrimSpace(event.Rule),
			"priority": strings.TrimSpace(event.Priority),
			"output":   strings.TrimSpace(event.Output),
			"source":   strings.TrimSpace(event.Source),
			"hostname": strings.TrimSpace(event.Hostname),
			"tags":     compactAnyStrings(event.Tags),
		},
		Tags: adapters.CompactTags(append(
			[]string{
				sourceName,
				strings.ToLower(strings.TrimSpace(event.Priority)),
				strings.ToLower(strings.TrimSpace(event.Source)),
			},
			compactAnyStrings(event.Tags)...,
		)...),
	}

	applyFalcoKubernetesContext(observation, outputFields)
	applyFalcoPrincipalContext(observation, outputFields)

	normalized, err := runtime.NormalizeObservation(observation)
	if err != nil {
		return nil, err
	}
	return []*runtime.RuntimeObservation{normalized}, nil
}

func falcoObservedAt(event payload) (time.Time, error) {
	if timestamp := strings.TrimSpace(event.Time); timestamp != "" {
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return time.Time{}, fmt.Errorf("decode falco payload: invalid time: %w", err)
		}
		return parsed.UTC(), nil
	}
	for _, key := range []string{"evt.time", "evt.rawtime"} {
		value, ok := event.OutputFields[key]
		if !ok {
			continue
		}
		parsed, ok, err := anyUnixNano(value)
		if err != nil {
			continue
		}
		if ok {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, nil
}

func falcoProcess(fields map[string]any) *runtime.ProcessEvent {
	process := &runtime.ProcessEvent{
		PID:        intField(fields, "proc.pid"),
		PPID:       intField(fields, "proc.ppid"),
		Name:       stringField(fields, "proc.name"),
		Path:       stringField(fields, "proc.exepath", "proc.exe"),
		Cmdline:    stringField(fields, "proc.cmdline"),
		User:       stringField(fields, "user.name"),
		UID:        intField(fields, "user.uid"),
		Hash:       stringField(fields, "proc.hash.sha256", "proc.hash"),
		ParentName: stringField(fields, "proc.pname"),
	}
	if isEmptyProcess(process) {
		return nil
	}
	return process
}

func falcoNetwork(fields map[string]any) *runtime.NetworkEvent {
	if !hasNetworkFields(fields) {
		return nil
	}

	direction := falcoDirection(fields)
	localIP := stringField(fields, "fd.lip")
	localPort := intField(fields, "fd.lport")
	remoteIP := stringField(fields, "fd.rip")
	remotePort := intField(fields, "fd.rport")
	localFallbackIP, localFallbackPort, remoteFallbackIP, remoteFallbackPort := falcoDirectionalEndpointFallbacks(fields, direction)
	if localIP == "" {
		localIP = localFallbackIP
	}
	if localPort == 0 {
		localPort = localFallbackPort
	}
	if remoteIP == "" {
		remoteIP = remoteFallbackIP
	}
	if remotePort == 0 {
		remotePort = remoteFallbackPort
	}

	network := &runtime.NetworkEvent{
		Direction: direction,
		Protocol:  strings.ToLower(stringField(fields, "fd.l4proto", "fd.type")),
		Domain:    stringField(fields, "fd.cip.name", "fd.rip.name"),
	}
	switch direction {
	case "inbound":
		network.SrcIP = remoteIP
		network.SrcPort = remotePort
		network.DstIP = localIP
		network.DstPort = localPort
	default:
		network.SrcIP = localIP
		network.SrcPort = localPort
		network.DstIP = remoteIP
		network.DstPort = remotePort
	}
	if isEmptyNetwork(network) {
		return nil
	}
	return network
}

func falcoFile(fields map[string]any) *runtime.FileEvent {
	switch strings.ToLower(strings.TrimSpace(stringField(fields, "fd.type"))) {
	case "unix", "ipv4", "ipv6":
		return nil
	}
	path := stringField(fields, "fd.name", "fs.path.name")
	if hasNetworkFields(fields) && looksLikeSocketDescriptor(path) {
		return nil
	}
	operation := falcoFileOperation(stringField(fields, "evt.type"), stringField(fields, "evt.arg.flags"), boolField(fields, "evt.is_open_write"))
	if path == "" || operation == "" {
		return nil
	}
	return &runtime.FileEvent{
		Operation: operation,
		Path:      path,
		User:      stringField(fields, "user.name"),
		Size:      int64Field(fields, "fd.size", "file.size"),
		Hash:      stringField(fields, "fd.hash", "file.sha256"),
	}
}

func falcoContainer(fields map[string]any) *runtime.ContainerEvent {
	image := strings.TrimSpace(stringField(fields, "container.image"))
	if image == "" {
		repository := stringField(fields, "container.image.repository")
		tag := stringField(fields, "container.image.tag")
		switch {
		case repository != "" && tag != "":
			image = repository + ":" + tag
		case repository != "":
			image = repository
		}
	}

	container := &runtime.ContainerEvent{
		ContainerID:   stringField(fields, "container.id", "container.full_id"),
		ContainerName: stringField(fields, "container.name"),
		Image:         image,
		ImageID:       stringField(fields, "container.image.digest", "container.image.id"),
		Namespace:     stringField(fields, "k8s.ns.name"),
		PodName:       stringField(fields, "k8s.pod.name"),
		Privileged:    boolField(fields, "container.privileged"),
		Capabilities: compactAnyStrings([]string{
			stringField(fields, "container.capabilities"),
		}),
	}
	if isEmptyContainer(container) {
		return nil
	}
	return container
}

func applyFalcoKubernetesContext(observation *runtime.RuntimeObservation, fields map[string]any) {
	if observation == nil {
		return
	}
	namespace := stringField(fields, "k8s.ns.name")
	podName := stringField(fields, "k8s.pod.name")
	if namespace != "" {
		observation.Namespace = namespace
	}
	if observation.Metadata == nil {
		observation.Metadata = make(map[string]any)
	}
	if podName != "" {
		observation.Metadata["k8s_pod_name"] = podName
		if namespace != "" {
			observation.WorkloadRef = "pod:" + namespace + "/" + podName
		} else {
			observation.WorkloadRef = "pod:" + podName
		}
	}
	if podUID := stringField(fields, "k8s.pod.uid"); podUID != "" {
		observation.WorkloadUID = podUID
	}
	if cluster := stringField(fields, "k8s.cluster.name", "k8s.cluster.uid"); cluster != "" {
		observation.Cluster = cluster
	}
}

func applyFalcoPrincipalContext(observation *runtime.RuntimeObservation, fields map[string]any) {
	if observation == nil {
		return
	}
	observation.PrincipalID = stringField(fields, "user.name", "user.loginname")
}

func falcoDirection(fields map[string]any) string {
	switch strings.ToLower(stringField(fields, "evt.type")) {
	case "connect", "connectat", "sendto", "sendmsg", "sendmmsg":
		return "outbound"
	case "accept", "accept4", "listen", "recvfrom", "recvmsg", "recvmmsg":
		return "inbound"
	default:
		return ""
	}
}

func falcoDirectionalEndpointFallbacks(fields map[string]any, direction string) (string, int, string, int) {
	switch direction {
	case "outbound":
		return stringField(fields, "fd.cip"), intField(fields, "fd.cport"), stringField(fields, "fd.sip"), intField(fields, "fd.sport")
	case "inbound":
		return stringField(fields, "fd.sip"), intField(fields, "fd.sport"), stringField(fields, "fd.cip"), intField(fields, "fd.cport")
	default:
		return stringField(fields, "fd.cip"), intField(fields, "fd.cport"), stringField(fields, "fd.sip"), intField(fields, "fd.sport")
	}
}

func falcoFileOperation(eventType, flags string, openWrite bool) string {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	flags = strings.ToUpper(strings.TrimSpace(flags))

	switch eventType {
	case "creat":
		return "modify"
	case "open", "openat", "openat2":
		if openWrite ||
			strings.Contains(flags, "O_WRONLY") ||
			strings.Contains(flags, "O_RDWR") ||
			strings.Contains(flags, "O_CREAT") ||
			strings.Contains(flags, "O_TRUNC") ||
			strings.Contains(flags, "O_APPEND") {
			return "modify"
		}
		return "read"
	case "read", "pread", "preadv", "readv":
		return "read"
	case "write", "pwrite", "pwritev", "writev", "truncate", "ftruncate", "chmod", "fchmod", "chown", "fchown", "mkdir", "mkdirat", "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat", "setxattr", "fsetxattr", "removexattr", "fremovexattr":
		return "modify"
	case "unlink", "unlinkat", "rmdir":
		return "delete"
	default:
		return ""
	}
}

func hasNetworkFields(fields map[string]any) bool {
	fdType := strings.ToLower(stringField(fields, "fd.type"))
	if fdType == "ipv4" || fdType == "ipv6" || fdType == "unix" {
		return true
	}
	return hasAnyField(fields, "fd.l4proto", "fd.lip", "fd.rip", "fd.sip", "fd.cip", "fd.lport", "fd.rport", "fd.sport", "fd.cport")
}

func isEmptyProcess(process *runtime.ProcessEvent) bool {
	return process == nil ||
		(process.PID == 0 &&
			process.PPID == 0 &&
			process.Name == "" &&
			process.Path == "" &&
			process.Cmdline == "" &&
			process.User == "" &&
			process.UID == 0 &&
			process.Hash == "" &&
			process.ParentName == "")
}

func isEmptyNetwork(network *runtime.NetworkEvent) bool {
	return network == nil ||
		(network.Direction == "" &&
			network.Protocol == "" &&
			network.SrcIP == "" &&
			network.SrcPort == 0 &&
			network.DstIP == "" &&
			network.DstPort == 0 &&
			network.Domain == "")
}

func isEmptyContainer(container *runtime.ContainerEvent) bool {
	return container == nil ||
		(container.ContainerID == "" &&
			container.ContainerName == "" &&
			container.Image == "" &&
			container.ImageID == "" &&
			container.Namespace == "" &&
			container.PodName == "" &&
			!container.Privileged &&
			len(container.Capabilities) == 0)
}

func stringField(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func boolField(fields map[string]any, key string) bool {
	value, ok := fields[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	default:
		return false
	}
}

func intField(fields map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		if parsed, ok := anyInt64(value); ok {
			return int(parsed)
		}
	}
	return 0
}

func int64Field(fields map[string]any, keys ...string) int64 {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		if parsed, ok := anyInt64(value); ok {
			return parsed
		}
	}
	return 0
}

func anyInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < math.MinInt64 || typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func anyUnixNano(value any) (time.Time, bool, error) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return time.Time{}, false, nil
		}
		if parsed, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return parsed.UTC(), true, nil
		}
		unixNano, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return time.Time{}, false, err
		}
		return time.Unix(0, unixNano).UTC(), true, nil
	case float64:
		if typed < math.MinInt64 || typed > math.MaxInt64 {
			return time.Time{}, false, fmt.Errorf("timestamp %v overflows int64", typed)
		}
		return time.Unix(0, int64(typed)).UTC(), true, nil
	case json.Number:
		unixNano, err := typed.Int64()
		if err != nil {
			return time.Time{}, false, err
		}
		return time.Unix(0, unixNano).UTC(), true, nil
	default:
		return time.Time{}, false, nil
	}
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func compactAnyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return adapters.CompactTags(values...)
}

func hasAnyField(fields map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := fields[key]; ok {
			return true
		}
	}
	return false
}

func looksLikeSocketDescriptor(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if strings.Contains(path, "->") {
		return true
	}
	return strings.HasPrefix(path, "unix://")
}

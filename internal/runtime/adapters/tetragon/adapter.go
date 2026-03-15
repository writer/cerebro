package tetragon

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/runtime"
	"github.com/evalops/cerebro/internal/runtime/adapters"
)

const sourceName = "tetragon"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	ProcessExec    *processExecEnvelope    `json:"process_exec,omitempty"`
	ProcessExit    *processExitEnvelope    `json:"process_exit,omitempty"`
	ProcessConnect *processConnectEnvelope `json:"process_connect,omitempty"`
	ProcessKprobe  *processKprobeEnvelope  `json:"process_kprobe,omitempty"`
	NodeName       string                  `json:"node_name"`
	Time           time.Time               `json:"time"`
}

type processExecEnvelope struct {
	Process processInfo `json:"process"`
	Parent  processInfo `json:"parent"`
}

type processExitEnvelope struct {
	Process processInfo `json:"process"`
	Parent  processInfo `json:"parent"`
	Signal  string      `json:"signal"`
	Status  uint32      `json:"status"`
}

type processConnectEnvelope struct {
	Process         processInfo `json:"process"`
	Parent          processInfo `json:"parent"`
	SourceIP        string      `json:"source_ip"`
	SourcePort      uint32      `json:"source_port"`
	DestinationIP   string      `json:"destination_ip"`
	DestinationPort uint32      `json:"destination_port"`
	Protocol        string      `json:"protocol"`
}

type processKprobeEnvelope struct {
	Process      processInfo `json:"process"`
	Parent       processInfo `json:"parent"`
	FunctionName string      `json:"function_name"`
	Args         []kprobeArg `json:"args"`
	Return       *kprobeArg  `json:"return,omitempty"`
	Action       string      `json:"action"`
	PolicyName   string      `json:"policy_name"`
	ReturnAction string      `json:"return_action"`
}

type kprobeArg struct {
	SockArg     *sockArg     `json:"sock_arg,omitempty"`
	SockaddrArg *sockaddrArg `json:"sockaddr_arg,omitempty"`
	FileArg     *pathLikeArg `json:"file_arg,omitempty"`
	PathArg     *pathLikeArg `json:"path_arg,omitempty"`
	IntArg      *int64       `json:"int_arg,omitempty"`
	UintArg     *uint64      `json:"uint_arg,omitempty"`
}

type sockArg struct {
	Family   string `json:"family"`
	Type     string `json:"type"`
	Protocol string `json:"protocol"`
	SAddr    string `json:"saddr"`
	DAddr    string `json:"daddr"`
	SPort    uint32 `json:"sport"`
	DPort    uint32 `json:"dport"`
}

type sockaddrArg struct {
	Family string `json:"family"`
	Addr   string `json:"addr"`
	Port   uint32 `json:"port"`
}

type pathLikeArg struct {
	Path       string `json:"path"`
	Permission string `json:"permission"`
}

type processInfo struct {
	ExecID       string    `json:"exec_id"`
	ParentExecID string    `json:"parent_exec_id"`
	PID          int       `json:"pid"`
	UID          int       `json:"uid"`
	CWD          string    `json:"cwd"`
	Binary       string    `json:"binary"`
	Arguments    string    `json:"arguments"`
	Flags        string    `json:"flags"`
	StartTime    time.Time `json:"start_time"`
	Pod          podInfo   `json:"pod"`
	Docker       string    `json:"docker"`
}

type podInfo struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Workload  string            `json:"workload"`
	Labels    map[string]string `json:"pod_labels"`
	Container containerInfo     `json:"container"`
}

type containerInfo struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Image imageInfo `json:"image"`
}

type imageInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (Adapter) Source() string {
	return sourceName
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	var event payload
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("decode tetragon payload: %w", err)
	}
	switch {
	case event.ProcessExec != nil:
		return []*runtime.RuntimeObservation{observationFromProcessExec(event)}, nil
	case event.ProcessExit != nil:
		return []*runtime.RuntimeObservation{observationFromProcessExit(event)}, nil
	case event.ProcessConnect != nil:
		return []*runtime.RuntimeObservation{observationFromProcessConnect(event)}, nil
	case event.ProcessKprobe != nil:
		observation, err := observationFromProcessKprobe(event)
		if err != nil {
			return nil, err
		}
		return []*runtime.RuntimeObservation{observation}, nil
	default:
		return nil, fmt.Errorf("decode tetragon payload: unsupported event")
	}
}

func observationFromProcessExec(event payload) *runtime.RuntimeObservation {
	process := event.ProcessExec.Process
	parent := event.ProcessExec.Parent
	return newProcessObservation(
		runtime.ObservationKindProcessExec,
		"process_exec",
		event.Time,
		event.NodeName,
		process,
		parent,
		map[string]any{
			"exec_id":        process.ExecID,
			"parent_exec_id": process.ParentExecID,
			"cwd":            process.CWD,
			"flags":          process.Flags,
			"workload_name":  process.Pod.Workload,
			"pod_labels":     runtime.CloneStringMap(process.Pod.Labels),
			"node_name":      event.NodeName,
		},
	)
}

func observationFromProcessExit(event payload) *runtime.RuntimeObservation {
	process := event.ProcessExit.Process
	parent := event.ProcessExit.Parent
	return newProcessObservation(
		runtime.ObservationKindProcessExit,
		"process_exit",
		event.Time,
		event.NodeName,
		process,
		parent,
		map[string]any{
			"exec_id":        process.ExecID,
			"parent_exec_id": process.ParentExecID,
			"cwd":            process.CWD,
			"flags":          process.Flags,
			"workload_name":  process.Pod.Workload,
			"pod_labels":     runtime.CloneStringMap(process.Pod.Labels),
			"node_name":      event.NodeName,
			"exit_signal":    strings.TrimSpace(event.ProcessExit.Signal),
			"exit_status":    event.ProcessExit.Status,
		},
	)
}

func observationFromProcessKprobe(event payload) (*runtime.RuntimeObservation, error) {
	kprobe := event.ProcessKprobe
	functionName := strings.TrimSpace(kprobe.FunctionName)

	if isNetworkKprobe(functionName) {
		observation, err := observationFromNetworkKprobe(event)
		if err != nil {
			return nil, err
		}
		return observation, nil
	}

	var (
		kind         runtime.RuntimeObservationKind
		operation    string
		path         string
		permission   string
		accessValue  int64
		accessValueU uint64
		accessKey    string
		metadata     = map[string]any{
			"exec_id":        kprobe.Process.ExecID,
			"parent_exec_id": kprobe.Process.ParentExecID,
			"cwd":            kprobe.Process.CWD,
			"flags":          kprobe.Process.Flags,
			"workload_name":  kprobe.Process.Pod.Workload,
			"pod_labels":     runtime.CloneStringMap(kprobe.Process.Pod.Labels),
			"node_name":      event.NodeName,
			"function_name":  functionName,
			"policy_name":    strings.TrimSpace(kprobe.PolicyName),
			"action":         strings.TrimSpace(kprobe.Action),
			"return_action":  strings.TrimSpace(kprobe.ReturnAction),
		}
	)

	switch functionName {
	case "security_file_permission":
		path, permission = firstFilePathArg(kprobe.Args)
		accessValue = firstSignedArgValue(kprobe.Args)
		kind, operation = filePermissionAccess(accessValue)
		accessKey = "access_mask"
	case "security_mmap_file":
		path, permission = firstFilePathArg(kprobe.Args)
		accessValueU = firstUnsignedArgValue(kprobe.Args)
		kind, operation = fileMmapAccess(accessValueU)
		accessKey = "prot_flags"
	case "security_path_truncate":
		path, permission = firstPathArg(kprobe.Args)
		kind, operation = runtime.ObservationKindFileWrite, "modify"
	case "security_file_truncate":
		path, permission = firstFilePathArg(kprobe.Args)
		kind, operation = runtime.ObservationKindFileWrite, "modify"
	default:
		return nil, fmt.Errorf("decode tetragon payload: unsupported event")
	}

	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("decode tetragon payload: missing file path for %s", functionName)
	}

	if permission = strings.TrimSpace(permission); permission != "" {
		metadata["file_permission"] = permission
	}
	if accessKey != "" {
		if functionName == "security_mmap_file" {
			metadata[accessKey] = accessValueU
		} else {
			metadata[accessKey] = accessValue
		}
	}
	if returnCode, ok := firstReturnCode(kprobe.Return); ok {
		metadata["return_code"] = returnCode
	}

	observation := newProcessObservation(
		kind,
		"process_kprobe",
		event.Time,
		event.NodeName,
		kprobe.Process,
		kprobe.Parent,
		metadata,
	)
	observation.ID = fileObservationID(kprobe.Process, kind, functionName, path, observation.ObservedAt)
	observation.File = &runtime.FileEvent{
		Operation: operation,
		Path:      path,
		User:      fmt.Sprintf("%d", kprobe.Process.UID),
	}
	observation.Tags = compactTags("tetragon", "process_kprobe", string(kind), functionName)
	return observation, nil
}

func observationFromProcessConnect(event payload) *runtime.RuntimeObservation {
	connect := event.ProcessConnect
	metadata := map[string]any{
		"exec_id":        connect.Process.ExecID,
		"parent_exec_id": connect.Process.ParentExecID,
		"cwd":            connect.Process.CWD,
		"flags":          connect.Process.Flags,
		"workload_name":  connect.Process.Pod.Workload,
		"pod_labels":     runtime.CloneStringMap(connect.Process.Pod.Labels),
		"node_name":      event.NodeName,
		"event_type":     "process_connect",
	}
	observation := newProcessObservation(
		runtime.ObservationKindNetworkFlow,
		"process_connect",
		event.Time,
		event.NodeName,
		connect.Process,
		connect.Parent,
		metadata,
	)
	observation.ID = networkObservationID(connect.Process, "process_connect", connect.DestinationIP, connect.DestinationPort, observation.ObservedAt)
	observation.Network = &runtime.NetworkEvent{
		Direction: "outbound",
		Protocol:  strings.TrimSpace(connect.Protocol),
		SrcIP:     strings.TrimSpace(connect.SourceIP),
		SrcPort:   int(connect.SourcePort),
		DstIP:     strings.TrimSpace(connect.DestinationIP),
		DstPort:   int(connect.DestinationPort),
	}
	observation.Tags = compactTags("tetragon", "process_connect", "network_flow", strings.TrimSpace(connect.Protocol))
	return observation
}

func observationFromNetworkKprobe(event payload) (*runtime.RuntimeObservation, error) {
	kprobe := event.ProcessKprobe
	functionName := strings.TrimSpace(kprobe.FunctionName)
	sock, sockaddr := firstSocketArgs(kprobe.Args)

	protocol := ""
	srcIP := ""
	srcPort := 0
	dstIP := ""
	dstPort := 0
	if sock != nil {
		protocol = strings.TrimSpace(sock.Protocol)
		srcIP = strings.TrimSpace(sock.SAddr)
		srcPort = int(sock.SPort)
		dstIP = strings.TrimSpace(sock.DAddr)
		dstPort = int(sock.DPort)
	}
	if sockaddr != nil {
		if dstIP == "" {
			dstIP = strings.TrimSpace(sockaddr.Addr)
		}
		if dstPort == 0 {
			dstPort = int(sockaddr.Port)
		}
	}
	if dstIP == "" || dstPort == 0 {
		return nil, fmt.Errorf("decode tetragon payload: missing network destination for %s", functionName)
	}

	metadata := map[string]any{
		"exec_id":        kprobe.Process.ExecID,
		"parent_exec_id": kprobe.Process.ParentExecID,
		"cwd":            kprobe.Process.CWD,
		"flags":          kprobe.Process.Flags,
		"workload_name":  kprobe.Process.Pod.Workload,
		"pod_labels":     runtime.CloneStringMap(kprobe.Process.Pod.Labels),
		"node_name":      event.NodeName,
		"function_name":  functionName,
		"policy_name":    strings.TrimSpace(kprobe.PolicyName),
		"action":         strings.TrimSpace(kprobe.Action),
		"return_action":  strings.TrimSpace(kprobe.ReturnAction),
	}
	if returnCode, ok := firstReturnCode(kprobe.Return); ok {
		metadata["return_code"] = returnCode
	}
	if sock != nil {
		if value := strings.TrimSpace(sock.Family); value != "" {
			metadata["socket_family"] = value
		}
		if value := strings.TrimSpace(sock.Type); value != "" {
			metadata["socket_type"] = value
		}
	}
	if sockaddr != nil {
		if value := strings.TrimSpace(sockaddr.Family); value != "" {
			metadata["sockaddr_family"] = value
		}
	}

	observation := newProcessObservation(
		runtime.ObservationKindNetworkFlow,
		"process_kprobe",
		event.Time,
		event.NodeName,
		kprobe.Process,
		kprobe.Parent,
		metadata,
	)
	observation.ID = networkObservationID(kprobe.Process, functionName, dstIP, uint32(dstPort), observation.ObservedAt)
	observation.Network = &runtime.NetworkEvent{
		Direction: "outbound",
		Protocol:  protocol,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
	}
	observation.Tags = compactTags("tetragon", "process_kprobe", "network_flow", functionName, protocol)
	return observation, nil
}

func newProcessObservation(
	kind runtime.RuntimeObservationKind,
	tag string,
	eventTime time.Time,
	nodeName string,
	process processInfo,
	parent processInfo,
	metadata map[string]any,
) *runtime.RuntimeObservation {
	observedAt := eventTime
	if observedAt.IsZero() {
		observedAt = process.StartTime
	}

	processName := baseNameOrEmpty(process.Binary)
	parentName := baseNameOrEmpty(parent.Binary)
	cmdline := strings.TrimSpace(strings.Join([]string{process.Binary, process.Arguments}, " "))
	resourceID := podResourceID(process.Pod.Namespace, process.Pod.Name)

	workloadRef := ""
	if process.Pod.Namespace != "" && process.Pod.Workload != "" {
		workloadRef = "workload:" + process.Pod.Namespace + "/" + process.Pod.Workload
	}

	return &runtime.RuntimeObservation{
		ID:           processObservationID(process.ExecID, kind, process),
		Kind:         kind,
		Source:       sourceName,
		ObservedAt:   observedAt,
		ResourceID:   resourceID,
		ResourceType: "pod",
		Namespace:    process.Pod.Namespace,
		NodeName:     nodeName,
		WorkloadRef:  workloadRef,
		ContainerID:  runtime.FirstNonEmpty(process.Pod.Container.ID, process.Docker),
		ImageRef:     process.Pod.Container.Image.Name,
		ImageID:      process.Pod.Container.Image.ID,
		Process: &runtime.ProcessEvent{
			PID:        process.PID,
			Name:       processName,
			Path:       process.Binary,
			Cmdline:    cmdline,
			UID:        process.UID,
			ParentName: parentName,
		},
		Container: &runtime.ContainerEvent{
			ContainerID:   runtime.FirstNonEmpty(process.Pod.Container.ID, process.Docker),
			ContainerName: process.Pod.Container.Name,
			Image:         process.Pod.Container.Image.Name,
			ImageID:       process.Pod.Container.Image.ID,
			Namespace:     process.Pod.Namespace,
			PodName:       process.Pod.Name,
		},
		Metadata: metadata,
		Tags:     []string{"tetragon", tag},
	}
}

func processObservationID(execID string, kind runtime.RuntimeObservationKind, process processInfo) string {
	if execID = strings.TrimSpace(execID); execID != "" {
		return execID + ":" + string(kind)
	}
	fallback := []string{
		string(kind),
		strings.TrimSpace(process.Binary),
		strings.TrimSpace(process.Pod.Namespace),
		strings.TrimSpace(process.Pod.Name),
		process.StartTime.UTC().Format(time.RFC3339Nano),
	}
	return strings.Join(fallback, ":")
}

func fileObservationID(process processInfo, kind runtime.RuntimeObservationKind, functionName, path string, observedAt time.Time) string {
	base := processObservationID(process.ExecID, kind, process)
	parts := []string{base, strings.TrimSpace(functionName), strings.TrimSpace(path)}
	if !observedAt.IsZero() {
		parts = append(parts, observedAt.UTC().Format(time.RFC3339Nano))
	}
	return strings.Join(parts, ":")
}

func networkObservationID(process processInfo, eventType, dstIP string, dstPort uint32, observedAt time.Time) string {
	parts := []string{
		processObservationID(process.ExecID, runtime.ObservationKindNetworkFlow, process),
		strings.TrimSpace(eventType),
		strings.TrimSpace(dstIP),
		fmt.Sprintf("%d", dstPort),
	}
	if !observedAt.IsZero() {
		parts = append(parts, observedAt.UTC().Format(time.RFC3339Nano))
	}
	return strings.Join(parts, ":")
}

func podResourceID(namespace, name string) string {
	if namespace == "" || name == "" {
		return ""
	}
	return "pod:" + namespace + "/" + name
}

func baseNameOrEmpty(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func firstFilePathArg(args []kprobeArg) (string, string) {
	for _, arg := range args {
		if arg.FileArg != nil {
			return strings.TrimSpace(arg.FileArg.Path), strings.TrimSpace(arg.FileArg.Permission)
		}
	}
	return "", ""
}

func firstPathArg(args []kprobeArg) (string, string) {
	for _, arg := range args {
		if arg.PathArg != nil {
			return strings.TrimSpace(arg.PathArg.Path), strings.TrimSpace(arg.PathArg.Permission)
		}
	}
	return "", ""
}

func firstSignedArgValue(args []kprobeArg) int64 {
	for _, arg := range args {
		if arg.IntArg != nil {
			return *arg.IntArg
		}
	}
	return 0
}

func firstUnsignedArgValue(args []kprobeArg) uint64 {
	for _, arg := range args {
		if arg.UintArg != nil {
			return *arg.UintArg
		}
	}
	return 0
}

func firstSocketArgs(args []kprobeArg) (*sockArg, *sockaddrArg) {
	var sock *sockArg
	var sockaddr *sockaddrArg
	for _, arg := range args {
		if sock == nil && arg.SockArg != nil {
			sock = arg.SockArg
		}
		if sockaddr == nil && arg.SockaddrArg != nil {
			sockaddr = arg.SockaddrArg
		}
	}
	return sock, sockaddr
}

func firstReturnCode(arg *kprobeArg) (any, bool) {
	if arg == nil {
		return 0, false
	}
	if arg.IntArg != nil {
		return *arg.IntArg, true
	}
	if arg.UintArg != nil {
		return *arg.UintArg, true
	}
	return 0, false
}

func filePermissionAccess(mask int64) (runtime.RuntimeObservationKind, string) {
	switch {
	case mask&(0x02|0x08) != 0:
		return runtime.ObservationKindFileWrite, "modify"
	case mask&0x04 != 0:
		return runtime.ObservationKindFileOpen, "read"
	case mask&0x01 != 0:
		return runtime.ObservationKindFileOpen, "execute"
	default:
		return runtime.ObservationKindFileOpen, "read"
	}
}

func fileMmapAccess(protFlags uint64) (runtime.RuntimeObservationKind, string) {
	switch {
	case protFlags&0x02 != 0:
		return runtime.ObservationKindFileWrite, "modify"
	case protFlags&0x01 != 0:
		return runtime.ObservationKindFileOpen, "read"
	case protFlags&0x04 != 0:
		return runtime.ObservationKindFileOpen, "execute"
	default:
		return runtime.ObservationKindFileOpen, "read"
	}
}

func compactTags(values ...string) []string {
	tags := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			tags = append(tags, value)
		}
	}
	return tags
}

func isNetworkKprobe(functionName string) bool {
	switch functionName {
	case "tcp_connect", "security_socket_connect":
		return true
	default:
		return false
	}
}

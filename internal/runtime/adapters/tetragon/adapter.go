package tetragon

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/runtime/adapters"
)

const sourceName = "tetragon"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

type payload struct {
	ProcessExec *processExecEnvelope `json:"process_exec,omitempty"`
	NodeName    string               `json:"node_name"`
	Time        time.Time            `json:"time"`
}

type processExecEnvelope struct {
	Process processInfo `json:"process"`
	Parent  processInfo `json:"parent"`
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
	if event.ProcessExec == nil {
		return nil, fmt.Errorf("decode tetragon payload: unsupported event")
	}
	return []*runtime.RuntimeObservation{observationFromProcessExec(event)}, nil
}

func observationFromProcessExec(event payload) *runtime.RuntimeObservation {
	process := event.ProcessExec.Process
	parent := event.ProcessExec.Parent
	observedAt := event.Time
	if observedAt.IsZero() {
		observedAt = process.StartTime
	}

	processName := baseNameOrEmpty(process.Binary)
	parentName := baseNameOrEmpty(parent.Binary)
	cmdline := strings.TrimSpace(strings.Join([]string{process.Binary, process.Arguments}, " "))
	resourceID := podResourceID(process.Pod.Namespace, process.Pod.Name)
	metadata := map[string]any{
		"exec_id":        process.ExecID,
		"parent_exec_id": process.ParentExecID,
		"cwd":            process.CWD,
		"flags":          process.Flags,
		"workload_name":  process.Pod.Workload,
		"pod_labels":     runtime.CloneStringMap(process.Pod.Labels),
		"node_name":      event.NodeName,
	}

	workloadRef := ""
	if process.Pod.Namespace != "" && process.Pod.Workload != "" {
		workloadRef = "workload:" + process.Pod.Namespace + "/" + process.Pod.Workload
	}

	return &runtime.RuntimeObservation{
		ID:           process.ExecID,
		Kind:         runtime.ObservationKindProcessExec,
		Source:       sourceName,
		ObservedAt:   observedAt,
		ResourceID:   resourceID,
		ResourceType: "pod",
		Namespace:    process.Pod.Namespace,
		NodeName:     event.NodeName,
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
		Tags:     []string{"tetragon", "process_exec"},
	}
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

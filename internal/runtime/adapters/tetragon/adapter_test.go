package tetragon

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/runtime"
)

func TestAdapterNormalizeProcessExec(t *testing.T) {
	raw := []byte(`{
		"process_exec": {
			"process": {
				"exec_id": "exec-1",
				"pid": 52699,
				"uid": 0,
				"cwd": "/",
				"binary": "/usr/bin/curl",
				"arguments": "https://ebpf.io/applications/#tetragon",
				"flags": "execve rootcwd",
				"start_time": "2023-10-06T22:03:57.700327580Z",
				"pod": {
					"namespace": "default",
					"name": "xwing",
					"workload": "xwing",
					"container": {
						"id": "containerd://abc",
						"name": "spaceship",
						"image": {
							"id": "docker.io/tgraf/netperf@sha256:deadbeef",
							"name": "docker.io/tgraf/netperf:latest"
						}
					},
					"pod_labels": {
						"app.kubernetes.io/name": "xwing"
					}
				},
				"docker": "abc",
				"parent_exec_id": "parent-1"
			},
			"parent": {
				"binary": "/bin/bash",
				"arguments": "-c curl https://ebpf.io/applications/#tetragon"
			}
		},
		"node_name": "worker-1",
		"time": "2023-10-06T22:03:57.700326678Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindProcessExec {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindProcessExec)
	}
	if observation.ResourceID != "pod:default/xwing" {
		t.Fatalf("resource_id = %q, want %q", observation.ResourceID, "pod:default/xwing")
	}
	if observation.Process == nil || observation.Process.Name != "curl" {
		t.Fatalf("process = %#v, want curl", observation.Process)
	}
	if observation.Process.ParentName != "bash" {
		t.Fatalf("parent_name = %q, want %q", observation.Process.ParentName, "bash")
	}
	if observation.WorkloadRef != "workload:default/xwing" {
		t.Fatalf("workload_ref = %q, want %q", observation.WorkloadRef, "workload:default/xwing")
	}
}

func TestAdapterNormalizeUnsupportedEvent(t *testing.T) {
	raw := []byte(`{"process_exit":{"process":{"exec_id":"exec-1"}}}`)
	if _, err := (Adapter{}).Normalize(context.Background(), raw); err == nil {
		t.Fatal("expected unsupported event error")
	}
}

func TestAdapterNormalizeEmptyBinaryDoesNotEmitDotNames(t *testing.T) {
	raw := []byte(`{
		"process_exec": {
			"process": {
				"exec_id": "exec-2",
				"pid": 100,
				"uid": 0,
				"binary": "",
				"arguments": "",
				"pod": {
					"namespace": "default",
					"name": "xwing",
					"container": {
						"id": "containerd://abc",
						"name": "spaceship",
						"image": {
							"id": "sha256:deadbeef",
							"name": "docker.io/tgraf/netperf:latest"
						}
					}
				}
			},
			"parent": {
				"binary": ""
			}
		},
		"time": "2023-10-06T22:03:57.700326678Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	observation := observations[0]
	if observation.Process == nil {
		t.Fatal("expected process context")
	}
	if observation.Process.Name != "" {
		t.Fatalf("process name = %q, want empty", observation.Process.Name)
	}
	if observation.Process.ParentName != "" {
		t.Fatalf("parent name = %q, want empty", observation.Process.ParentName)
	}
}

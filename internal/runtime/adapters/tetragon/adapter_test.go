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
	if observation.ID != "exec-1:process_exec" {
		t.Fatalf("id = %q, want %q", observation.ID, "exec-1:process_exec")
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

func TestAdapterNormalizeProcessExit(t *testing.T) {
	raw := []byte(`{
		"process_exit": {
			"process": {
				"exec_id": "exec-exit-1",
				"pid": 51583,
				"uid": 0,
				"cwd": "/",
				"binary": "/usr/bin/whoami",
				"arguments": "--version",
				"flags": "execve rootcwd clone",
				"start_time": "2022-05-11T12:54:45.615Z",
				"pod": {
					"namespace": "default",
					"name": "xwing",
					"workload": "xwing",
					"container": {
						"id": "containerd://1fb931d2f6e5",
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
				"docker": "1fb931d2f6e5",
				"parent_exec_id": "parent-exit-1"
			},
			"parent": {
				"binary": "/bin/bash",
				"arguments": "-c whoami --version"
			},
			"signal": "SIGTERM",
			"status": 143
		},
		"node_name": "worker-2",
		"time": "2022-05-11T12:54:46.000Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindProcessExit {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindProcessExit)
	}
	if observation.ID != "exec-exit-1:process_exit" {
		t.Fatalf("id = %q, want %q", observation.ID, "exec-exit-1:process_exit")
	}
	if observation.Process == nil || observation.Process.Name != "whoami" {
		t.Fatalf("process = %#v, want whoami", observation.Process)
	}
	if observation.Process.ParentName != "bash" {
		t.Fatalf("parent_name = %q, want bash", observation.Process.ParentName)
	}
	if got := observation.Metadata["exit_signal"]; got != "SIGTERM" {
		t.Fatalf("exit_signal = %#v, want SIGTERM", got)
	}
	if got := observation.Metadata["exit_status"]; got != float64(143) && got != uint32(143) && got != 143 {
		t.Fatalf("exit_status = %#v, want 143", got)
	}
	if len(observation.Tags) != 2 || observation.Tags[1] != "process_exit" {
		t.Fatalf("tags = %#v, want process_exit tag", observation.Tags)
	}
}

func TestAdapterNormalizeUnsupportedEvent(t *testing.T) {
	raw := []byte(`{"process_kprobe":{"process":{"exec_id":"exec-1"}}}`)
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

func TestProcessExecAndExitObservationsUseDistinctIDs(t *testing.T) {
	execRaw := []byte(`{
		"process_exec": {
			"process": {
				"exec_id": "shared-exec-id",
				"pid": 42,
				"uid": 0,
				"binary": "/usr/bin/sh",
				"pod": {
					"namespace": "default",
					"name": "api-0",
					"container": {
						"id": "containerd://abc",
						"name": "api",
						"image": {
							"id": "sha256:abc",
							"name": "ghcr.io/acme/api:latest"
						}
					}
				}
			},
			"parent": {
				"binary": "/bin/bash"
			}
		}
	}`)
	exitRaw := []byte(`{
		"process_exit": {
			"process": {
				"exec_id": "shared-exec-id",
				"pid": 42,
				"uid": 0,
				"binary": "/usr/bin/sh",
				"pod": {
					"namespace": "default",
					"name": "api-0",
					"container": {
						"id": "containerd://abc",
						"name": "api",
						"image": {
							"id": "sha256:abc",
							"name": "ghcr.io/acme/api:latest"
						}
					}
				}
			},
			"parent": {
				"binary": "/bin/bash"
			},
			"status": 0
		}
	}`)

	execObservations, err := (Adapter{}).Normalize(context.Background(), execRaw)
	if err != nil {
		t.Fatalf("Normalize exec: %v", err)
	}
	exitObservations, err := (Adapter{}).Normalize(context.Background(), exitRaw)
	if err != nil {
		t.Fatalf("Normalize exit: %v", err)
	}
	if execObservations[0].ID == exitObservations[0].ID {
		t.Fatalf("observation IDs collided: %q", execObservations[0].ID)
	}
}

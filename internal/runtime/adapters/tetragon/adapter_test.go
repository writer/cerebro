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

func TestAdapterNormalizeFileWriteKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-file-1",
				"pid": 64746,
				"uid": 0,
				"cwd": "/",
				"binary": "/bin/vi",
				"arguments": "/etc/passwd",
				"flags": "execve rootcwd clone",
				"start_time": "2024-04-14T02:18:02.240856427Z",
				"pod": {
					"namespace": "default",
					"name": "file-access",
					"workload": "file-access",
					"container": {
						"id": "containerd://6b742e38",
						"name": "file-access",
						"image": {
							"id": "docker.io/library/busybox@sha256:c3839dd8",
							"name": "docker.io/library/busybox:latest"
						}
					},
					"pod_labels": {
						"run": "file-access"
					}
				},
				"docker": "6b742e38",
				"parent_exec_id": "parent-file-1"
			},
			"parent": {
				"binary": "/bin/sh"
			},
			"function_name": "security_file_permission",
			"args": [
				{
					"file_arg": {
						"path": "/etc/passwd",
						"permission": "-rw-r--r--"
					}
				},
				{
					"int_arg": 2
				}
			],
			"return": {
				"int_arg": 0
			},
			"action": "KPROBE_ACTION_POST",
			"policy_name": "file-monitoring",
			"return_action": "KPROBE_ACTION_POST"
		},
		"node_name": "worker-1",
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindFileWrite {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindFileWrite)
	}
	if observation.File == nil {
		t.Fatal("expected file context")
	}
	if observation.File.Operation != "modify" {
		t.Fatalf("file.operation = %q, want %q", observation.File.Operation, "modify")
	}
	if observation.File.Path != "/etc/passwd" {
		t.Fatalf("file.path = %q, want %q", observation.File.Path, "/etc/passwd")
	}
	if observation.Process == nil || observation.Process.Name != "vi" {
		t.Fatalf("process = %#v, want vi", observation.Process)
	}
	if got := observation.Metadata["function_name"]; got != "security_file_permission" {
		t.Fatalf("function_name = %#v, want security_file_permission", got)
	}
	if got := observation.Metadata["return_code"]; got != int64(0) && got != uint64(0) && got != 0 {
		t.Fatalf("return_code = %#v, want 0", got)
	}
}

func TestAdapterNormalizeFileReadAndTruncateKprobes(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		wantKind      runtime.RuntimeObservationKind
		wantOperation string
	}{
		{
			name: "read",
			raw: `{
				"process_kprobe": {
					"process": {
						"exec_id": "exec-file-read-1",
						"pid": 123,
						"uid": 0,
						"binary": "/usr/bin/cat",
						"start_time": "2024-04-14T02:18:02.240856427Z",
						"pod": {
							"namespace": "default",
							"name": "file-access",
							"container": {
								"id": "containerd://read",
								"name": "file-access",
								"image": {
									"id": "sha256:read",
									"name": "busybox:latest"
								}
							}
						}
					},
					"parent": {
						"binary": "/bin/sh"
					},
					"function_name": "security_mmap_file",
					"args": [
						{
							"file_arg": {
								"path": "/etc/shadow",
								"permission": "-rw-------"
							}
						},
						{
							"uint_arg": 1
						}
					],
					"return": {
						"int_arg": 0
					}
				},
				"time": "2024-04-14T02:18:14.376304204Z"
			}`,
			wantKind:      runtime.ObservationKindFileOpen,
			wantOperation: "read",
		},
		{
			name: "append",
			raw: `{
				"process_kprobe": {
					"process": {
						"exec_id": "exec-file-append-1",
						"pid": 124,
						"uid": 0,
						"binary": "/usr/bin/tee",
						"start_time": "2024-04-14T02:18:02.240856427Z",
						"pod": {
							"namespace": "default",
							"name": "file-access",
							"container": {
								"id": "containerd://append",
								"name": "file-access",
								"image": {
									"id": "sha256:append",
									"name": "busybox:latest"
								}
							}
						}
					},
					"parent": {
						"binary": "/bin/sh"
					},
					"function_name": "security_file_permission",
					"args": [
						{
							"file_arg": {
								"path": "/var/log/app.log",
								"permission": "-rw-r--r--"
							}
						},
						{
							"int_arg": 8
						}
					],
					"return": {
						"int_arg": 0
					}
				},
				"time": "2024-04-14T02:18:14.376304204Z"
			}`,
			wantKind:      runtime.ObservationKindFileWrite,
			wantOperation: "modify",
		},
		{
			name: "truncate",
			raw: `{
				"process_kprobe": {
					"process": {
						"exec_id": "exec-file-truncate-1",
						"pid": 321,
						"uid": 0,
						"binary": "/usr/bin/truncate",
						"start_time": "2024-04-14T02:18:02.240856427Z",
						"pod": {
							"namespace": "default",
							"name": "file-access",
							"container": {
								"id": "containerd://truncate",
								"name": "file-access",
								"image": {
									"id": "sha256:truncate",
									"name": "busybox:latest"
								}
							}
						}
					},
					"parent": {
						"binary": "/bin/sh"
					},
					"function_name": "security_path_truncate",
					"args": [
						{
							"path_arg": {
								"path": "/etc/passwd",
								"permission": "-rw-r--r--"
							}
						}
					],
					"return": {
						"int_arg": 0
					}
				},
				"time": "2024-04-14T02:18:14.376304204Z"
			}`,
			wantKind:      runtime.ObservationKindFileWrite,
			wantOperation: "modify",
		},
		{
			name: "file truncate",
			raw: `{
				"process_kprobe": {
					"process": {
						"exec_id": "exec-file-truncate-2",
						"pid": 322,
						"uid": 0,
						"binary": "/usr/bin/truncate",
						"start_time": "2024-04-14T02:18:02.240856427Z",
						"pod": {
							"namespace": "default",
							"name": "file-access",
							"container": {
								"id": "containerd://truncate-fd",
								"name": "file-access",
								"image": {
									"id": "sha256:truncate-fd",
									"name": "busybox:latest"
								}
							}
						}
					},
					"parent": {
						"binary": "/bin/sh"
					},
					"function_name": "security_file_truncate",
					"args": [
						{
							"file_arg": {
								"path": "/etc/shadow",
								"permission": "-rw-------"
							}
						}
					],
					"return": {
						"int_arg": 0
					}
				},
				"time": "2024-04-14T02:18:14.376304204Z"
			}`,
			wantKind:      runtime.ObservationKindFileWrite,
			wantOperation: "modify",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observations, err := (Adapter{}).Normalize(context.Background(), []byte(tt.raw))
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if len(observations) != 1 {
				t.Fatalf("len(observations) = %d, want 1", len(observations))
			}
			observation := observations[0]
			if observation.Kind != tt.wantKind {
				t.Fatalf("kind = %s, want %s", observation.Kind, tt.wantKind)
			}
			if observation.File == nil {
				t.Fatal("expected file context")
			}
			if observation.File.Operation != tt.wantOperation {
				t.Fatalf("file.operation = %q, want %q", observation.File.Operation, tt.wantOperation)
			}
		})
	}
}

func TestFileKprobeObservationsUseDistinctIDs(t *testing.T) {
	firstRaw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "shared-file-exec-id",
				"pid": 42,
				"uid": 0,
				"binary": "/usr/bin/cat",
				"start_time": "2024-04-14T02:18:02.240856427Z",
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
			"function_name": "security_file_permission",
			"args": [
				{"file_arg": {"path": "/etc/passwd"}},
				{"int_arg": 4}
			]
		},
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)
	secondRaw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "shared-file-exec-id",
				"pid": 42,
				"uid": 0,
				"binary": "/usr/bin/cat",
				"start_time": "2024-04-14T02:18:02.240856427Z",
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
			"function_name": "security_file_permission",
			"args": [
				{"file_arg": {"path": "/etc/shadow"}},
				{"int_arg": 4}
			]
		},
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)

	firstObservations, err := (Adapter{}).Normalize(context.Background(), firstRaw)
	if err != nil {
		t.Fatalf("Normalize first: %v", err)
	}
	secondObservations, err := (Adapter{}).Normalize(context.Background(), secondRaw)
	if err != nil {
		t.Fatalf("Normalize second: %v", err)
	}
	if firstObservations[0].ID == secondObservations[0].ID {
		t.Fatalf("file observation IDs collided: %q", firstObservations[0].ID)
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

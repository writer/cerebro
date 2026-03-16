package tetragon

import (
	"context"
	"testing"

	"github.com/evalops/cerebro/internal/runtime"
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

func TestAdapterNormalizeProcessConnect(t *testing.T) {
	raw := []byte(`{
		"process_connect":{
			"process":{
				"exec_id":"exec-connect-1",
				"pid":115153,
				"uid":0,
				"cwd":"/usr/share/elasticsearch/",
				"binary":"/usr/bin/curl",
				"arguments":"www.google.com",
				"flags":"execve clone",
				"start_time":"2022-01-19T16:29:01.861Z",
				"pod":{
					"namespace":"tenant-jobs",
					"name":"elasticsearch-56f8fc6988-pb8c7",
					"workload":"elasticsearch",
					"container":{
						"id":"docker://86eb9e29",
						"name":"elasticsearch",
						"image":{
							"id":"docker-pullable://quay.io/isovalent/jobs-app-elasticsearch@sha256:ff3aa586",
							"name":"quay.io/isovalent/jobs-app-elasticsearch:latest"
						}
					}
				},
				"docker":"86eb9e29",
				"parent_exec_id":"parent-connect-1"
			},
			"parent":{
				"binary":"/bin/bash"
			},
			"source_ip":"10.88.0.7",
			"source_port":49168,
			"destination_ip":"142.250.180.196",
			"destination_port":80,
			"protocol":"TCP"
		},
		"node_name":"minikube",
		"time":"2022-01-19T16:29:02.021Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindNetworkFlow {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindNetworkFlow)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Direction != "outbound" {
		t.Fatalf("direction = %q, want outbound", observation.Network.Direction)
	}
	if observation.Network.Protocol != "TCP" {
		t.Fatalf("protocol = %q, want TCP", observation.Network.Protocol)
	}
	if observation.Network.SrcIP != "10.88.0.7" || observation.Network.DstIP != "142.250.180.196" {
		t.Fatalf("network = %#v, want src/dst IPs", observation.Network)
	}
	if observation.Network.SrcPort != 49168 || observation.Network.DstPort != 80 {
		t.Fatalf("network ports = %#v, want 49168 -> 80", observation.Network)
	}
	if observation.Process == nil || observation.Process.Name != "curl" {
		t.Fatalf("process = %#v, want curl", observation.Process)
	}
}

func TestAdapterNormalizeTcpConnectKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-tcp-connect-1",
				"pid": 64746,
				"uid": 0,
				"cwd": "/",
				"binary": "/usr/bin/curl",
				"arguments": "http://ebpf.io",
				"flags": "execve rootcwd clone",
				"start_time": "2024-04-14T02:18:02.240856427Z",
				"pod": {
					"namespace": "default",
					"name": "net-access",
					"workload": "net-access",
					"container": {
						"id": "containerd://6b742e38",
						"name": "net-access",
						"image": {
							"id": "docker.io/library/busybox@sha256:c3839dd8",
							"name": "docker.io/library/busybox:latest"
						}
					},
					"pod_labels": {
						"run": "net-access"
					}
				},
				"docker": "6b742e38",
				"parent_exec_id": "parent-tcp-connect-1"
			},
			"parent": {
				"binary": "/bin/sh"
			},
			"function_name": "tcp_connect",
			"args": [
				{
					"sock_arg": {
						"family": "AF_INET",
						"type": "SOCK_STREAM",
						"protocol": "IPPROTO_TCP",
						"saddr": "10.88.0.6",
						"daddr": "104.198.14.52",
						"sport": 48272,
						"dport": 80
					}
				}
			]
		},
		"node_name": "worker-1",
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindNetworkFlow {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindNetworkFlow)
	}
	if observation.Network == nil || observation.Network.DstIP != "104.198.14.52" || observation.Network.DstPort != 80 {
		t.Fatalf("network = %#v, want outbound connect", observation.Network)
	}
	if got := observation.Metadata["function_name"]; got != "tcp_connect" {
		t.Fatalf("function_name = %#v, want tcp_connect", got)
	}
}

func TestAdapterNormalizeSecuritySocketConnectKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-socket-connect-1",
				"pid": 64746,
				"uid": 0,
				"cwd": "/",
				"binary": "/usr/bin/nc",
				"arguments": "127.0.0.1 9939",
				"flags": "execve rootcwd clone",
				"start_time": "2024-04-14T02:18:02.240856427Z",
				"pod": {
					"namespace": "default",
					"name": "net-access",
					"workload": "net-access",
					"container": {
						"id": "containerd://6b742e38",
						"name": "net-access",
						"image": {
							"id": "docker.io/library/busybox@sha256:c3839dd8",
							"name": "docker.io/library/busybox:latest"
						}
					}
				},
				"docker": "6b742e38",
				"parent_exec_id": "parent-socket-connect-1"
			},
			"parent": {
				"binary": "/bin/sh"
			},
			"function_name": "security_socket_connect",
			"args": [
				{
					"sock_arg": {
						"protocol": "IPPROTO_TCP"
					}
				},
				{
					"sockaddr_arg": {
						"family": "AF_INET",
						"addr": "127.0.0.1",
						"port": 9939
					}
				}
			],
			"return": {
				"int_arg": 0
			}
		},
		"node_name": "worker-1",
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	observation := observations[0]
	if observation.Kind != runtime.ObservationKindNetworkFlow {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindNetworkFlow)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Protocol != "IPPROTO_TCP" {
		t.Fatalf("protocol = %q, want IPPROTO_TCP", observation.Network.Protocol)
	}
	if observation.Network.DstIP != "127.0.0.1" || observation.Network.DstPort != 9939 {
		t.Fatalf("network = %#v, want dst 127.0.0.1:9939", observation.Network)
	}
}

func TestAdapterNormalizeDNSKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-dns-1",
				"pid": 3141,
				"uid": 0,
				"cwd": "/",
				"binary": "/usr/bin/dig",
				"arguments": "api.github.com",
				"flags": "execve rootcwd clone",
				"start_time": "2024-04-14T02:18:02.240856427Z",
				"pod": {
					"namespace": "default",
					"name": "dns-client",
					"workload": "dns-client",
					"container": {
						"id": "containerd://dns-client",
						"name": "dns-client",
						"image": {
							"id": "sha256:dns-client",
							"name": "busybox:latest"
						}
					},
					"pod_labels": {
						"run": "dns-client"
					}
				},
				"docker": "dns-client",
				"parent_exec_id": "parent-dns-1"
			},
			"parent": {
				"binary": "/bin/sh"
			},
			"function_name": "ip_output",
			"args": [
				{
					"skb_arg": {
						"family": "AF_INET",
						"protocol": "IPPROTO_UDP",
						"saddr": "10.88.0.6",
						"daddr": "10.96.0.10",
						"sport": 45612,
						"dport": 53,
						"len": 88,
						"proto": 17
					}
				}
			],
			"return": {
				"int_arg": 0
			},
			"action": "KPROBE_ACTION_POST",
			"policy_name": "dns-only-specified-servers",
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
	if observation.Kind != runtime.ObservationKindDNSQuery {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindDNSQuery)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Protocol != "dns" {
		t.Fatalf("network.protocol = %q, want dns", observation.Network.Protocol)
	}
	if observation.Network.SrcIP != "10.88.0.6" || observation.Network.DstIP != "10.96.0.10" {
		t.Fatalf("network = %#v, want DNS src/dst IPs", observation.Network)
	}
	if observation.Network.SrcPort != 45612 || observation.Network.DstPort != 53 {
		t.Fatalf("network ports = %#v, want 45612 -> 53", observation.Network)
	}
	if observation.Network.BytesSent != 88 {
		t.Fatalf("bytes_sent = %d, want 88", observation.Network.BytesSent)
	}
	if got := observation.Metadata["transport_protocol"]; got != "IPPROTO_UDP" {
		t.Fatalf("transport_protocol = %#v, want IPPROTO_UDP", got)
	}
	if got := observation.Metadata["transport_protocol_number"]; got != float64(17) && got != uint32(17) && got != 17 {
		t.Fatalf("transport_protocol_number = %#v, want 17", got)
	}
}

func TestAdapterNormalizeDNSKprobeRequiresDestination(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-dns-2",
				"pid": 3142,
				"uid": 0,
				"binary": "/usr/bin/dig",
				"start_time": "2024-04-14T02:18:02.240856427Z",
				"pod": {
					"namespace": "default",
					"name": "dns-client",
					"container": {
						"id": "containerd://dns-client",
						"name": "dns-client",
						"image": {
							"id": "sha256:dns-client",
							"name": "busybox:latest"
						}
					}
				}
			},
			"function_name": "ip_output",
			"args": [
				{
					"skb_arg": {
						"protocol": "IPPROTO_UDP",
						"dport": 53
					}
				}
			]
		},
		"time": "2024-04-14T02:18:14.376304204Z"
	}`)

	if _, err := (Adapter{}).Normalize(context.Background(), raw); err == nil {
		t.Fatal("expected missing DNS destination error")
	}
}

func TestAdapterNormalizeSecuritySignalCapabilityKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-cap-1",
				"pid": 7157,
				"uid": 1000,
				"binary": "/usr/bin/unshare",
				"arguments": "-Ur /bin/sh",
				"start_time": "2024-03-01T12:00:00Z",
				"pod": {
					"namespace": "default",
					"name": "security-lab",
					"workload": "security-lab",
					"container": {
						"id": "containerd://cap",
						"name": "security-lab",
						"image": {
							"id": "sha256:cap",
							"name": "busybox:latest"
						}
					}
				}
			},
			"parent": {
				"binary": "/bin/bash"
			},
			"function_name": "cap_capable",
			"policy_name": "trace-capabilities",
			"action": "SIGKILL",
			"return_action": "SIGKILL",
			"args": [
				{
					"capability_arg": {
						"value": 21,
						"name": "CAP_SYS_ADMIN"
					}
				},
				{
					"user_ns_arg": {
						"level": 0,
						"uid": 1000,
						"gid": 1000,
						"ns": 4026531837
					}
				}
			],
			"return": {
				"int_arg": -1
			}
		},
		"node_name": "worker-7",
		"time": "2024-03-01T12:00:01Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindRuntimeAlert {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindRuntimeAlert)
	}
	if observation.ID != "exec-cap-1:runtime_alert:cap_capable:2024-03-01T12:00:01Z" {
		t.Fatalf("id = %q, want runtime alert security-signal id", observation.ID)
	}
	if got := observation.Metadata["signal_category"]; got != "capability_check" {
		t.Fatalf("signal_category = %#v, want capability_check", got)
	}
	if got := observation.Metadata["capability_name"]; got != "CAP_SYS_ADMIN" {
		t.Fatalf("capability_name = %#v, want CAP_SYS_ADMIN", got)
	}
	if got := observation.Metadata["capability_value"]; got != 21 && got != float64(21) {
		t.Fatalf("capability_value = %#v, want 21", got)
	}
	if got := observation.Metadata["user_ns_level"]; got != uint32(0) && got != 0 && got != float64(0) {
		t.Fatalf("user_ns_level = %#v, want 0", got)
	}
	if got := observation.Metadata["return_code"]; got != int64(-1) && got != -1 && got != float64(-1) {
		t.Fatalf("return_code = %#v, want -1", got)
	}
	if observation.Process == nil || observation.Process.Name != "unshare" {
		t.Fatalf("process = %#v, want unshare", observation.Process)
	}
	if observation.WorkloadRef != "workload:default/security-lab" {
		t.Fatalf("workload_ref = %q, want workload ref", observation.WorkloadRef)
	}
}

func TestAdapterNormalizeSecuritySignalCredentialKprobe(t *testing.T) {
	raw := []byte(`{
		"process_kprobe": {
			"process": {
				"exec_id": "exec-creds-1",
				"pid": 417430,
				"uid": 1000,
				"binary": "/usr/bin/sudo",
				"arguments": "id",
				"start_time": "2024-03-01T12:00:00Z",
				"pod": {
					"namespace": "default",
					"name": "cred-lab",
					"workload": "cred-lab",
					"container": {
						"id": "containerd://creds",
						"name": "cred-lab",
						"image": {
							"id": "sha256:creds",
							"name": "busybox:latest"
						}
					}
				}
			},
			"parent": {
				"binary": "/bin/bash"
			},
			"function_name": "commit_creds",
			"policy_name": "trace-credentials",
			"action": "KPROBE_ACTION_POST",
			"return_action": "KPROBE_ACTION_POST",
			"args": [
				{
					"user_ns_arg": {
						"level": 1,
						"uid": 1000,
						"gid": 1000,
						"ns": 4026532000
					}
				},
				{
					"process_credentials_arg": {
						"uid": 0,
						"euid": 0,
						"suid": 0,
						"fsuid": 0,
						"gid": 0,
						"egid": 0,
						"sgid": 0,
						"fsgid": 0,
						"securebits": 0,
						"cap_inheritable": "0x0",
						"cap_permitted": "0x1ffffffffff",
						"cap_effective": "0x1ffffffffff",
						"user_ns": {
							"level": 0,
							"uid": 0,
							"gid": 0,
							"ns": 4026531837
						}
					}
				}
			],
			"return": {
				"int_arg": 0
			}
		},
		"node_name": "worker-8",
		"time": "2024-03-01T12:00:02Z"
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindRuntimeAlert {
		t.Fatalf("kind = %s, want %s", observation.Kind, runtime.ObservationKindRuntimeAlert)
	}
	if got := observation.Metadata["signal_category"]; got != "credential_change" {
		t.Fatalf("signal_category = %#v, want credential_change", got)
	}
	if got := observation.Metadata["credential_euid"]; got != uint32(0) && got != 0 && got != float64(0) {
		t.Fatalf("credential_euid = %#v, want 0", got)
	}
	if got := observation.Metadata["cap_effective"]; got != "0x1ffffffffff" {
		t.Fatalf("cap_effective = %#v, want capability mask", got)
	}
	if got := observation.Metadata["policy_name"]; got != "trace-credentials" {
		t.Fatalf("policy_name = %#v, want trace-credentials", got)
	}
	if got := observation.Metadata["user_ns_level"]; got != uint32(1) && got != 1 && got != float64(1) {
		t.Fatalf("user_ns_level = %#v, want top-level namespace level 1", got)
	}
	if got := observation.Metadata["credential_user_ns_level"]; got != uint32(0) && got != 0 && got != float64(0) {
		t.Fatalf("credential_user_ns_level = %#v, want credential namespace level 0", got)
	}
	if len(observation.Tags) == 0 || observation.Tags[2] != "runtime_alert" {
		t.Fatalf("tags = %#v, want runtime_alert tag", observation.Tags)
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

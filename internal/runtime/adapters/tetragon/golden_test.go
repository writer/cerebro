package tetragon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/evalops/cerebro/internal/runtime"
)

func TestAdapterNormalizeGoldenPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		fixture       string
		wantKind      runtime.RuntimeObservationKind
		wantProcess   string
		wantPath      string
		wantProtocol  string
		wantDstIP     string
		wantDstPort   int
		wantOperation string
	}{
		{
			name:        "process exec",
			fixture:     "process_exec.golden.json",
			wantKind:    runtime.ObservationKindProcessExec,
			wantProcess: "curl",
		},
		{
			name:        "process exit",
			fixture:     "process_exit.golden.json",
			wantKind:    runtime.ObservationKindProcessExit,
			wantProcess: "curl",
		},
		{
			name:         "process connect",
			fixture:      "process_connect.golden.json",
			wantKind:     runtime.ObservationKindNetworkFlow,
			wantProcess:  "curl",
			wantProtocol: "TCP",
			wantDstIP:    "142.250.180.196",
			wantDstPort:  80,
		},
		{
			name:          "security file permission",
			fixture:       "security_file_permission.golden.json",
			wantKind:      runtime.ObservationKindFileWrite,
			wantProcess:   "vi",
			wantPath:      "/etc/passwd",
			wantOperation: "modify",
		},
		{
			name:         "tcp connect kprobe",
			fixture:      "tcp_connect.golden.json",
			wantKind:     runtime.ObservationKindNetworkFlow,
			wantProcess:  "curl",
			wantProtocol: "IPPROTO_TCP",
			wantDstIP:    "104.198.14.52",
			wantDstPort:  80,
		},
		{
			name:         "dns kprobe",
			fixture:      "dns_ip_output.golden.json",
			wantKind:     runtime.ObservationKindDNSQuery,
			wantProcess:  "dig",
			wantProtocol: "dns",
			wantDstIP:    "10.96.0.10",
			wantDstPort:  53,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw := mustReadFixture(t, tt.fixture)
			observations, err := (Adapter{}).Normalize(context.Background(), raw)
			if err != nil {
				t.Fatalf("Normalize(%s): %v", tt.fixture, err)
			}
			if len(observations) != 1 {
				t.Fatalf("len(observations) = %d, want 1", len(observations))
			}

			observation := observations[0]
			if observation.Kind != tt.wantKind {
				t.Fatalf("kind = %s, want %s", observation.Kind, tt.wantKind)
			}
			if observation.Process == nil || observation.Process.Name != tt.wantProcess {
				t.Fatalf("process = %#v, want %q", observation.Process, tt.wantProcess)
			}
			if tt.wantPath != "" {
				if observation.File == nil {
					t.Fatal("expected file context")
				}
				if observation.File.Path != tt.wantPath {
					t.Fatalf("file.path = %q, want %q", observation.File.Path, tt.wantPath)
				}
				if observation.File.Operation != tt.wantOperation {
					t.Fatalf("file.operation = %q, want %q", observation.File.Operation, tt.wantOperation)
				}
			}
			if tt.wantProtocol != "" {
				if observation.Network == nil {
					t.Fatal("expected network context")
				}
				if observation.Network.Protocol != tt.wantProtocol {
					t.Fatalf("network.protocol = %q, want %q", observation.Network.Protocol, tt.wantProtocol)
				}
				if observation.Network.DstIP != tt.wantDstIP {
					t.Fatalf("network.dst_ip = %q, want %q", observation.Network.DstIP, tt.wantDstIP)
				}
				if observation.Network.DstPort != tt.wantDstPort {
					t.Fatalf("network.dst_port = %d, want %d", observation.Network.DstPort, tt.wantDstPort)
				}
			}
		})
	}
}

func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return raw
}

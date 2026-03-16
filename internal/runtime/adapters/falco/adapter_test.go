package falco

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/runtime"
)

func TestAdapterSource(t *testing.T) {
	if got := (Adapter{}).Source(); got != sourceName {
		t.Fatalf("Source() = %q, want %q", got, sourceName)
	}
}

func TestAdapterNormalizeNetworkAlert(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T08:45:12.123456789Z",
		"rule": "Unexpected outbound connection destination",
		"priority": "Critical",
		"output": "Unexpected outbound connection to api.example.com",
		"hostname": "node-a",
		"source": "syscall",
		"tags": ["network", "mitre_command_and_control"],
		"output_fields": {
			"k8s.ns.name": "payments",
			"k8s.pod.name": "payments-api-7f5c9d",
			"k8s.pod.uid": "pod-123",
			"container.id": "abc123",
			"container.name": "payments-api",
			"container.image.repository": "ghcr.io/evalops/payments",
			"container.image.tag": "1.2.3",
			"container.image.digest": "sha256:deadbeef",
			"proc.pid": 173,
			"proc.ppid": 1,
			"proc.name": "curl",
			"proc.pname": "bash",
			"proc.exepath": "/usr/bin/curl",
			"proc.cmdline": "curl https://api.example.com",
			"user.name": "root",
			"user.uid": 0,
			"fd.l4proto": "tcp",
			"fd.cip": "10.1.2.3",
			"fd.cip.name": "api.example.com",
			"fd.cport": 49832,
			"fd.sip": "203.0.113.20",
			"fd.sport": 443,
			"evt.type": "connect",
			"evt.dir": "<"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	if observation.Kind != runtime.ObservationKindRuntimeAlert {
		t.Fatalf("Kind = %q, want %q", observation.Kind, runtime.ObservationKindRuntimeAlert)
	}
	wantTime := time.Date(2026, 3, 16, 8, 45, 12, 123456789, time.UTC)
	if !observation.ObservedAt.Equal(wantTime) {
		t.Fatalf("ObservedAt = %s, want %s", observation.ObservedAt, wantTime)
	}
	if observation.NodeName != "node-a" {
		t.Fatalf("NodeName = %q, want node-a", observation.NodeName)
	}
	if observation.Namespace != "payments" {
		t.Fatalf("Namespace = %q, want payments", observation.Namespace)
	}
	if observation.WorkloadRef != "pod:payments/payments-api-7f5c9d" {
		t.Fatalf("WorkloadRef = %q, want pod:payments/payments-api-7f5c9d", observation.WorkloadRef)
	}
	if observation.WorkloadUID != "pod-123" {
		t.Fatalf("WorkloadUID = %q, want pod-123", observation.WorkloadUID)
	}
	if observation.ContainerID != "abc123" {
		t.Fatalf("ContainerID = %q, want abc123", observation.ContainerID)
	}
	if observation.ImageRef != "ghcr.io/evalops/payments:1.2.3" {
		t.Fatalf("ImageRef = %q, want ghcr.io/evalops/payments:1.2.3", observation.ImageRef)
	}
	if observation.ImageID != "sha256:deadbeef" {
		t.Fatalf("ImageID = %q, want sha256:deadbeef", observation.ImageID)
	}
	if observation.PrincipalID != "root" {
		t.Fatalf("PrincipalID = %q, want root", observation.PrincipalID)
	}
	if observation.Process == nil {
		t.Fatal("expected process context")
	}
	if observation.Process.Name != "curl" || observation.Process.Path != "/usr/bin/curl" {
		t.Fatalf("Process = %#v, want curl /usr/bin/curl", observation.Process)
	}
	if observation.Network == nil {
		t.Fatal("expected network context")
	}
	if observation.Network.Direction != "outbound" {
		t.Fatalf("Network.Direction = %q, want outbound", observation.Network.Direction)
	}
	if observation.Network.SrcIP != "10.1.2.3" || observation.Network.DstIP != "203.0.113.20" {
		t.Fatalf("Network = %#v, want local->remote mapping", observation.Network)
	}
	if observation.Network.DstPort != 443 {
		t.Fatalf("Network.DstPort = %d, want 443", observation.Network.DstPort)
	}
	if observation.Network.Domain != "api.example.com" {
		t.Fatalf("Network.Domain = %q, want api.example.com", observation.Network.Domain)
	}
	if got := observation.Metadata["rule_name"]; got != "Unexpected outbound connection destination" {
		t.Fatalf("rule_name = %#v, want rule name", got)
	}
	if got := observation.Metadata["severity"]; got != "Critical" {
		t.Fatalf("severity = %#v, want Critical", got)
	}
	if !containsTag(observation.Tags, "network") || !containsTag(observation.Tags, "critical") {
		t.Fatalf("Tags = %#v, want Falco tags plus priority", observation.Tags)
	}
}

func TestAdapterNormalizeFileAlertWithOutputFieldTimestampFallback(t *testing.T) {
	raw := []byte(`{
		"rule": "Write below etc",
		"priority": "Warning",
		"output": "File below /etc opened for writing",
		"hostname": "node-b",
		"source": "syscall",
		"output_fields": {
			"evt.time": "not-a-timestamp",
			"evt.rawtime": "1773620000000000000",
			"evt.type": "openat",
			"evt.arg.flags": "O_WRONLY|O_CREAT|O_TRUNC",
			"fd.name": "/etc/shadow",
			"proc.name": "vi",
			"proc.exepath": "/usr/bin/vi",
			"proc.pid": "921",
			"user.name": "alice"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	observation := observations[0]
	wantTime := time.Unix(0, 1773620000000000000).UTC()
	if !observation.ObservedAt.Equal(wantTime) {
		t.Fatalf("ObservedAt = %s, want %s", observation.ObservedAt, wantTime)
	}
	if observation.File == nil {
		t.Fatal("expected file context")
	}
	if observation.File.Operation != "modify" {
		t.Fatalf("File.Operation = %q, want modify", observation.File.Operation)
	}
	if observation.File.Path != "/etc/shadow" {
		t.Fatalf("File.Path = %q, want /etc/shadow", observation.File.Path)
	}
	if observation.Process == nil || observation.Process.PID != 921 {
		t.Fatalf("Process = %#v, want pid 921", observation.Process)
	}
	if observation.PrincipalID != "alice" {
		t.Fatalf("PrincipalID = %q, want alice", observation.PrincipalID)
	}
	if observation.Network != nil {
		t.Fatalf("Network = %#v, want nil for file-only Falco alert", observation.Network)
	}
	if rawFields, ok := observation.Raw["output_fields"].(map[string]any); !ok || rawFields["fd.name"] != "/etc/shadow" {
		t.Fatalf("Raw output_fields = %#v, want fd.name preserved", observation.Raw["output_fields"])
	}
}

func TestAdapterNormalizeCreatWithoutFlagsIsModify(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T09:00:12.123456789Z",
		"rule": "Create suspicious file",
		"priority": "Warning",
		"output": "creat on suspicious file",
		"hostname": "node-c",
		"source": "syscall",
		"output_fields": {
			"evt.type": "creat",
			"fd.name": "/tmp/dropper",
			"proc.name": "python"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].File == nil {
		t.Fatal("expected file context")
	}
	if observations[0].File.Operation != "modify" {
		t.Fatalf("File.Operation = %q, want modify", observations[0].File.Operation)
	}
}

func TestAdapterNormalizeDoesNotUseCWDAsFilePathFallback(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T09:01:12.123456789Z",
		"rule": "Directory context only",
		"priority": "Info",
		"output": "cwd present without file path",
		"hostname": "node-c",
		"source": "syscall",
		"output_fields": {
			"evt.type": "unlink",
			"proc.cwd": "/workspace/app",
			"proc.name": "rm"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].File != nil {
		t.Fatalf("File = %#v, want nil when only proc.cwd is present", observations[0].File)
	}
}

func TestAdapterNormalizeUnixSocketAlertDoesNotCreateFileContext(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T09:02:12.123456789Z",
		"rule": "Unix socket activity",
		"priority": "Notice",
		"output": "sendmsg on docker socket",
		"hostname": "node-d",
		"source": "syscall",
		"output_fields": {
			"evt.type": "sendmsg",
			"fd.type": "unix",
			"fd.name": "/var/run/docker.sock",
			"proc.name": "docker"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].Network == nil {
		t.Fatal("expected network context for unix socket alert")
	}
	if observations[0].File != nil {
		t.Fatalf("File = %#v, want nil for unix socket alert", observations[0].File)
	}
}

func TestAdapterNormalizeIPv4SocketWriteDoesNotCreateFileContext(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T09:03:12.123456789Z",
		"rule": "Socket write activity",
		"priority": "Notice",
		"output": "write on remote socket",
		"hostname": "node-e",
		"source": "syscall",
		"output_fields": {
			"evt.type": "write",
			"fd.type": "ipv4",
			"fd.name": "10.1.2.3:49832->203.0.113.20:443",
			"fd.cip": "10.1.2.3",
			"fd.cport": 49832,
			"fd.sip": "203.0.113.20",
			"fd.sport": 443,
			"proc.name": "curl"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].Network == nil {
		t.Fatal("expected network context for ipv4 socket alert")
	}
	if observations[0].File != nil {
		t.Fatalf("File = %#v, want nil for ipv4 socket alert", observations[0].File)
	}
}

func TestAdapterNormalizeInboundNetworkAlertUsesServerClientFallbacks(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T08:50:12.123456789Z",
		"rule": "Unexpected inbound listener activity",
		"priority": "Error",
		"output": "Accepted inbound connection on 8443",
		"hostname": "node-b",
		"source": "syscall",
		"output_fields": {
			"evt.type": "accept",
			"evt.dir": "<",
			"fd.type": "ipv4",
			"fd.cip": "198.51.100.7",
			"fd.cport": 55221,
			"fd.sip": "10.1.2.4",
			"fd.sport": 8443
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	network := observations[0].Network
	if network == nil {
		t.Fatal("expected network context")
	}
	if network.Direction != "inbound" {
		t.Fatalf("Network.Direction = %q, want inbound", network.Direction)
	}
	if network.SrcIP != "198.51.100.7" || network.SrcPort != 55221 {
		t.Fatalf("Network source = %#v, want remote client", network)
	}
	if network.DstIP != "10.1.2.4" || network.DstPort != 8443 {
		t.Fatalf("Network destination = %#v, want local server", network)
	}
}

func TestAdapterNormalizeNetworkAlertWithNumericPortsOnly(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T08:55:12.123456789Z",
		"rule": "Port-only socket activity",
		"priority": "Info",
		"output": "Connect with numeric ports only",
		"hostname": "node-f",
		"source": "syscall",
		"output_fields": {
			"evt.type": "connect",
			"fd.cport": 49832,
			"fd.sport": 443,
			"proc.name": "curl"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	network := observations[0].Network
	if network == nil {
		t.Fatal("expected network context")
	}
	if network.Direction != "outbound" {
		t.Fatalf("Network.Direction = %q, want outbound", network.Direction)
	}
	if network.SrcPort != 49832 || network.DstPort != 443 {
		t.Fatalf("Network ports = %#v, want 49832 -> 443", network)
	}
}

func TestAdapterNormalizeSocketTupleWithoutFDTypeDoesNotCreateFileContext(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T08:56:12.123456789Z",
		"rule": "Socket tuple write",
		"priority": "Notice",
		"output": "write on socket tuple without fd.type",
		"hostname": "node-g",
		"source": "syscall",
		"output_fields": {
			"evt.type": "write",
			"fd.name": "10.1.2.3:49832->203.0.113.20:443",
			"fd.cip": "10.1.2.3",
			"fd.cport": 49832,
			"fd.sip": "203.0.113.20",
			"fd.sport": 443,
			"proc.name": "curl"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}
	if observations[0].Network == nil {
		t.Fatal("expected network context")
	}
	if observations[0].File != nil {
		t.Fatalf("File = %#v, want nil for socket tuple without fd.type", observations[0].File)
	}
}

func TestAdapterNormalizeUnknownDirectionDoesNotSynthesizeSelfLoopEndpoints(t *testing.T) {
	raw := []byte(`{
		"time": "2026-03-16T08:57:12.123456789Z",
		"rule": "Unknown direction socket metadata",
		"priority": "Info",
		"output": "socket tuple with only client endpoint fields",
		"hostname": "node-h",
		"source": "syscall",
		"output_fields": {
			"evt.type": "getsockopt",
			"fd.cip": "10.1.2.3",
			"fd.cport": 49832,
			"proc.name": "curl"
		}
	}`)

	observations, err := (Adapter{}).Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("len(observations) = %d, want 1", len(observations))
	}

	network := observations[0].Network
	if network == nil {
		t.Fatal("expected network context")
	}
	if network.Direction != "" {
		t.Fatalf("Network.Direction = %q, want empty for unknown direction", network.Direction)
	}
	if network.SrcIP != "10.1.2.3" || network.SrcPort != 49832 {
		t.Fatalf("Network source = %#v, want client endpoint preserved", network)
	}
	if network.DstIP != "" || network.DstPort != 0 {
		t.Fatalf("Network destination = %#v, want empty destination instead of self-loop", network)
	}
}

func TestAdapterNormalizeRejectsUnsupportedPayload(t *testing.T) {
	_, err := (Adapter{}).Normalize(context.Background(), []byte(`{"priority":"Critical"}`))
	if err == nil {
		t.Fatal("expected unsupported payload error")
	}
	if !strings.Contains(err.Error(), "unsupported event") {
		t.Fatalf("error = %v, want unsupported event", err)
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

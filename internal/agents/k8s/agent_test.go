package k8s

import (
	"strings"
	"testing"
	"time"
)

func TestNewAgentDefaults(t *testing.T) {
	agent := NewAgent(AgentConfig{})
	if agent.config.CollectInterval != 10*time.Second {
		t.Fatalf("expected default collect interval 10s, got %v", agent.config.CollectInterval)
	}
	if agent.config.BatchSize != 100 {
		t.Fatalf("expected default batch size 100, got %d", agent.config.BatchSize)
	}
}

func TestBytesReaderRead(t *testing.T) {
	reader := &bytesReader{data: []byte("abc")}
	buf := make([]byte, 2)

	count, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:count]) != "ab" {
		t.Fatalf("expected \"ab\", got %q", string(buf[:count]))
	}

	count, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:count]) != "c" {
		t.Fatalf("expected \"c\", got %q", string(buf[:count]))
	}

	_, err = reader.Read(buf)
	if err == nil {
		t.Fatalf("expected EOF error")
	}
}

func TestDaemonSetManifest(t *testing.T) {
	manifest := DaemonSetManifest("default", "https://cerebro.local", "token")
	checks := []string{
		"namespace: default",
		"value: \"https://cerebro.local\"",
		"token: \"token\"",
	}

	for _, check := range checks {
		if !strings.Contains(manifest, check) {
			t.Fatalf("expected manifest to contain %q", check)
		}
	}
}

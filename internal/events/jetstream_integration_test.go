package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/evalops/cerebro/internal/webhooks"
)

func TestJetStreamPublisherIntegration_DedupAndCloudEventContract(t *testing.T) {
	natsURL := startJetStreamServer(t)

	publisher, err := NewJetStreamPublisher(JetStreamConfig{
		URLs:          []string{natsURL},
		Stream:        "TEST_EVENTS",
		SubjectPrefix: "cerebro.events.itest",
		OutboxPath:    t.TempDir() + "/outbox.jsonl",
	}, nil)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	defer func() { _ = publisher.Close() }()

	event := webhooks.Event{
		ID:        "evt-dedupe-1",
		Type:      webhooks.EventScanCompleted,
		Timestamp: time.Now().UTC(),
		Data: map[string]interface{}{
			"scan_id": "scan-1",
		},
	}

	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatalf("publish #1: %v", err)
	}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatalf("publish #2: %v", err)
	}

	streamInfo, err := publisher.js.StreamInfo("TEST_EVENTS")
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if streamInfo.State.Msgs != 1 {
		t.Fatalf("expected 1 deduplicated message, got %d", streamInfo.State.Msgs)
	}

	rawMessage, err := publisher.js.GetMsg("TEST_EVENTS", 1)
	if err != nil {
		t.Fatalf("get stream message: %v", err)
	}

	var ce CloudEvent
	if err := json.Unmarshal(rawMessage.Data, &ce); err != nil {
		t.Fatalf("decode cloud event: %v", err)
	}
	if ce.SchemaVersion != cloudEventSchemaV1 {
		t.Fatalf("expected schema version %s, got %s", cloudEventSchemaV1, ce.SchemaVersion)
	}
	if ce.DataSchema == "" {
		t.Fatal("expected dataschema to be set")
	}
	if ce.TenantID != "unknown" {
		t.Fatalf("expected default tenant_id unknown, got %s", ce.TenantID)
	}
	if matched := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`).MatchString(ce.TraceParent); !matched {
		t.Fatalf("invalid traceparent format: %s", ce.TraceParent)
	}
}

func startJetStreamServer(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("nats-server"); err != nil {
		t.Skip("nats-server binary not found; skipping JetStream integration test")
	}

	port, err := reserveFreePort()
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}

	storeDir := t.TempDir()
	args := []string{"-js", "-a", "127.0.0.1", "-p", strconv.Itoa(port), "-sd", storeDir}
	cmd := exec.Command("nats-server", args...)

	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	err = cmd.Start()
	if err != nil {
		t.Fatalf("start nats-server: %v", err)
	}

	natsURL := fmt.Sprintf("nats://127.0.0.1:%d", port)
	if err := waitForNATSReady(natsURL, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("nats-server did not become ready: %v\nlogs:\n%s", err, logs.String())
	}

	t.Cleanup(func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)

		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	return natsURL
}

func reserveFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = listener.Close() }()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address type %T", listener.Addr())
	}

	return addr.Port, nil
}

func waitForNATSReady(natsURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		nc, err := nats.Connect(natsURL, nats.Timeout(250*time.Millisecond))
		if err == nil {
			nc.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for %s", natsURL)
}

package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/writer/cerebro/internal/testutil/integration"
)

func TestNATSQueue_EnsureStreamRespectsCreateStreamFlag(t *testing.T) {
	natsURL := integration.StartJetStreamServer(t)
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}

	queue := NewNATSQueue(js, NATSQueueConfig{
		Stream:       "JOBS_TEST",
		Subject:      "jobs.test",
		Consumer:     "worker",
		CreateStream: false,
	})
	if err := queue.EnsureStream(context.Background()); err == nil {
		t.Fatal("expected EnsureStream to fail when the stream is missing and CreateStream=false")
	}

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      "JOBS_TEST",
		Subjects:  []string{"jobs.test"},
		Retention: nats.WorkQueuePolicy,
	}); err != nil {
		t.Fatalf("AddStream: %v", err)
	}

	if err := queue.EnsureStream(context.Background()); err != nil {
		t.Fatalf("EnsureStream after provisioning: %v", err)
	}
}

func TestNATSQueue_ReceiveConfiguresConsumerAckWait(t *testing.T) {
	natsURL := integration.StartJetStreamServer(t)
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      "JOBS_ACK_TEST",
		Subjects:  []string{"jobs.ack"},
		Retention: nats.WorkQueuePolicy,
	}); err != nil {
		t.Fatalf("AddStream: %v", err)
	}

	queue := NewNATSQueue(js, NATSQueueConfig{
		Stream:       "JOBS_ACK_TEST",
		Subject:      "jobs.ack",
		Consumer:     "worker",
		CreateStream: false,
	})
	if err := queue.EnsureStream(context.Background()); err != nil {
		t.Fatalf("EnsureStream: %v", err)
	}

	publish := func(jobID string) {
		t.Helper()
		body, err := json.Marshal(JobMessage{JobID: jobID})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := js.Publish("jobs.ack", body); err != nil {
			t.Fatalf("Publish(%s): %v", jobID, err)
		}
	}

	publish("job-1")
	msgs, err := queue.Receive(context.Background(), 1, time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("Receive first: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected one message, got %d", len(msgs))
	}

	info, err := js.ConsumerInfo("JOBS_ACK_TEST", "worker")
	if err != nil {
		t.Fatalf("ConsumerInfo first: %v", err)
	}
	if info.Config.AckWait != 2*time.Second {
		t.Fatalf("expected first AckWait=2s, got %s", info.Config.AckWait)
	}
	if err := queue.Delete(context.Background(), msgs[0].ReceiptHandle); err != nil {
		t.Fatalf("Delete first: %v", err)
	}

	publish("job-2")
	msgs, err = queue.Receive(context.Background(), 1, time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("Receive second: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected one second message, got %d", len(msgs))
	}

	info, err = js.ConsumerInfo("JOBS_ACK_TEST", "worker")
	if err != nil {
		t.Fatalf("ConsumerInfo second: %v", err)
	}
	if info.Config.AckWait != 5*time.Second {
		t.Fatalf("expected second AckWait=5s, got %s", info.Config.AckWait)
	}
	if err := queue.Delete(context.Background(), msgs[0].ReceiptHandle); err != nil {
		t.Fatalf("Delete second: %v", err)
	}
}

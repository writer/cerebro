package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestConsumerConfigWithDefaults(t *testing.T) {
	cfg := (ConsumerConfig{}).withDefaults()
	if len(cfg.URLs) == 0 {
		t.Fatal("expected default URL")
	}
	if cfg.Stream == "" || cfg.Subject == "" || cfg.Durable == "" {
		t.Fatal("expected default stream/subject/durable")
	}
	if cfg.BatchSize <= 0 || cfg.AckWait <= 0 || cfg.FetchTimeout <= 0 {
		t.Fatal("expected positive default batch/ack/fetch settings")
	}
}

func TestConsumerConfigValidate(t *testing.T) {
	valid := (ConsumerConfig{
		URLs:         []string{"nats://127.0.0.1:4222"},
		Stream:       "ENSEMBLE_TAP",
		Subject:      "ensemble.tap.>",
		Durable:      "cerebro_graph_builder",
		BatchSize:    10,
		AckWait:      5,
		FetchTimeout: 5,
	}).withDefaults()
	if err := valid.validate(); err != nil {
		t.Fatalf("expected config to validate: %v", err)
	}

	invalid := ConsumerConfig{
		URLs:      []string{"nats://127.0.0.1:4222"},
		Stream:    "ENSEMBLE_TAP",
		Subject:   "ensemble.tap.>",
		Durable:   "cerebro_graph_builder",
		BatchSize: 0,
	}
	if err := invalid.validate(); err == nil {
		t.Fatal("expected validation error for invalid batch size")
	}
}

func TestJetStreamConsumer_CloseCancelsHandlerContext(t *testing.T) {
	natsURL := startJetStreamServer(t)

	handlerStarted := make(chan struct{})
	handlerCanceled := make(chan struct{})
	var startedOnce sync.Once
	var canceledOnce sync.Once

	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:         []string{natsURL},
		Stream:       "ENSEMBLE_TAP_CLOSE_TEST",
		Subject:      "ensemble.tap.close-test.>",
		Durable:      "cerebro_close_cancel_test",
		BatchSize:    1,
		AckWait:      5 * time.Second,
		FetchTimeout: 100 * time.Millisecond,
	}, nil, func(ctx context.Context, _ CloudEvent) error {
		startedOnce.Do(func() { close(handlerStarted) })
		<-ctx.Done()
		canceledOnce.Do(func() { close(handlerCanceled) })
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		_ = consumer.Close()
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	js, err := nc.JetStream()
	if err != nil {
		_ = consumer.Close()
		t.Fatalf("jetstream context: %v", err)
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-close-cancel-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
	}
	data, err := json.Marshal(event)
	if err != nil {
		_ = consumer.Close()
		t.Fatalf("marshal cloud event: %v", err)
	}
	if _, err := js.Publish("ensemble.tap.close-test.event", data); err != nil {
		_ = consumer.Close()
		t.Fatalf("publish cloud event: %v", err)
	}

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		_ = consumer.Close()
		t.Fatal("handler did not start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- consumer.Close()
	}()

	select {
	case <-handlerCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("handler context was not canceled on close")
	}

	select {
	case err := <-closeDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("close returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("consumer close did not complete")
	}
}

package events

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/nats-io/nats.go"
	dto "github.com/prometheus/client_model/go"
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

func TestConsumerConfigWithDefaultsPreservesZeroDropHealthThreshold(t *testing.T) {
	cfg := (ConsumerConfig{
		DropHealthThreshold: 0,
	}).withDefaults()
	if cfg.DropHealthThreshold != 0 {
		t.Fatalf("expected zero drop health threshold to remain zero, got %d", cfg.DropHealthThreshold)
	}
}

func TestConsumerConfigValidate(t *testing.T) {
	valid := (ConsumerConfig{
		URLs:           []string{"nats://127.0.0.1:4222"},
		Stream:         "ENSEMBLE_TAP",
		Subject:        "ensemble.tap.>",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      10,
		AckWait:        5,
		FetchTimeout:   5,
	}).withDefaults()
	if err := valid.validate(); err != nil {
		t.Fatalf("expected config to validate: %v", err)
	}

	invalid := ConsumerConfig{
		URLs:           []string{"nats://127.0.0.1:4222"},
		Stream:         "ENSEMBLE_TAP",
		Subject:        "ensemble.tap.>",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      0,
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
		URLs:           []string{natsURL},
		Stream:         "ENSEMBLE_TAP_CLOSE_TEST",
		Subject:        "ensemble.tap.close-test.>",
		Durable:        "cerebro_close_cancel_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      1,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
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

func TestConsumerHandleMessageDeadLettersMalformedPayload(t *testing.T) {
	cfg := (ConsumerConfig{
		URLs:                []string{"nats://127.0.0.1:4222"},
		Stream:              "ENSEMBLE_TAP_TEST",
		Subject:             "ensemble.tap.test.>",
		Durable:             "cerebro_graph_builder_test",
		DeadLetterPath:      t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:           1,
		AckWait:             time.Second,
		FetchTimeout:        time.Second,
		DropHealthLookback:  time.Minute,
		DropHealthThreshold: 1,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}
	consumer := &Consumer{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: cfg,
		handler: func(context.Context, CloudEvent) error {
			t.Fatal("handler should not be called for malformed payload")
			return nil
		},
		dlq: dlq,
	}

	before := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "malformed"))
	acked := 0
	nacked := 0
	consumer.handleMessage(context.Background(), "ensemble.tap.test.event", []byte("{bad json"), func() error {
		acked++
		return nil
	}, func() error {
		nacked++
		return nil
	})

	if acked != 1 {
		t.Fatalf("expected malformed payload to be acked after dead-letter, got %d", acked)
	}
	if nacked != 0 {
		t.Fatalf("expected malformed payload not to be nacked after dead-letter, got %d", nacked)
	}

	payload, err := os.ReadFile(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("read consumer dead-letter file: %v", err)
	}
	if got := string(payload); !containsAll(got, "\"reason\":\"malformed\"", "\"subject\":\"ensemble.tap.test.event\"", "{bad json") {
		t.Fatalf("expected malformed payload to be written to dead-letter file, got %s", got)
	}

	snapshot := consumer.HealthSnapshot(time.Now().UTC())
	if snapshot.RecentDropped != 1 {
		t.Fatalf("expected one recent dropped event, got %d", snapshot.RecentDropped)
	}
	if snapshot.LastDropReason != "malformed" {
		t.Fatalf("expected last drop reason malformed, got %q", snapshot.LastDropReason)
	}

	after := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "malformed"))
	if after-before != 1 {
		t.Fatalf("expected dropped metric to increase by 1, delta=%v", after-before)
	}
}

func TestConsumerHandleMessageRequeuesMalformedPayloadWhenDeadLetterFails(t *testing.T) {
	cfg := (ConsumerConfig{
		URLs:                []string{"nats://127.0.0.1:4222"},
		Stream:              "ENSEMBLE_TAP_TEST",
		Subject:             "ensemble.tap.test.>",
		Durable:             "cerebro_graph_builder_test_retry",
		DeadLetterPath:      t.TempDir(),
		BatchSize:           1,
		AckWait:             time.Second,
		FetchTimeout:        time.Second,
		DropHealthLookback:  time.Minute,
		DropHealthThreshold: 1,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}
	consumer := &Consumer{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: cfg,
		handler: func(context.Context, CloudEvent) error {
			t.Fatal("handler should not be called for malformed payload")
			return nil
		},
		dlq: dlq,
	}

	before := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "malformed"))
	acked := 0
	nacked := 0
	consumer.handleMessage(context.Background(), "ensemble.tap.test.event", []byte("{bad json"), func() error {
		acked++
		return nil
	}, func() error {
		nacked++
		return nil
	})

	if acked != 0 {
		t.Fatalf("expected malformed payload not to be acked when dead-letter write fails, got %d", acked)
	}
	if nacked != 1 {
		t.Fatalf("expected malformed payload to be nacked when dead-letter write fails, got %d", nacked)
	}
	if snapshot := consumer.HealthSnapshot(time.Now().UTC()); snapshot.RecentDropped != 0 {
		t.Fatalf("expected no recorded dropped events when dead-letter write fails, got %d", snapshot.RecentDropped)
	}
	after := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "malformed"))
	if after != before {
		t.Fatalf("expected dropped metric to remain unchanged, before=%v after=%v", before, after)
	}
}

func counterValue(t *testing.T, metric interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	snapshot := &dto.Metric{}
	if err := metric.Write(snapshot); err != nil {
		t.Fatalf("write metric snapshot: %v", err)
	}
	if snapshot.Counter == nil {
		t.Fatal("expected counter metric")
	}
	return snapshot.Counter.GetValue()
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

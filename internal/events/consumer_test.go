package events

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	dto "github.com/prometheus/client_model/go"
	"github.com/writer/cerebro/internal/metrics"
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

func TestConsumerConfigWithDefaultsSetsDedupDefaults(t *testing.T) {
	cfg := (ConsumerConfig{DedupEnabled: true}).withDefaults()
	if cfg.DedupTTL <= 0 {
		t.Fatalf("expected positive dedupe ttl, got %s", cfg.DedupTTL)
	}
	if cfg.DedupMaxRecords <= 0 {
		t.Fatalf("expected positive dedupe max records, got %d", cfg.DedupMaxRecords)
	}
}

func TestConsumerConfigValidate(t *testing.T) {
	valid := (ConsumerConfig{
		URLs:           []string{"nats://127.0.0.1:4222"},
		Stream:         "ENSEMBLE_TAP",
		Subject:        "ensemble.tap.>",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		DedupStateFile: t.TempDir() + "/executions.db",
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

func TestJetStreamConsumer_DrainWaitsForHandlerWithoutCancel(t *testing.T) {
	natsURL := startJetStreamServer(t)

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})

	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:                []string{natsURL},
		Stream:              "ENSEMBLE_TAP_DRAIN_TEST",
		Subject:             "ensemble.tap.drain-test.>",
		Durable:             "cerebro_drain_test",
		DeadLetterPath:      t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:           1,
		AckWait:             5 * time.Second,
		FetchTimeout:        100 * time.Millisecond,
		InProgressInterval:  10 * time.Millisecond,
		DropHealthLookback:  time.Minute,
		DropHealthThreshold: 1,
	}, nil, func(ctx context.Context, _ CloudEvent) error {
		close(handlerStarted)
		select {
		case <-releaseHandler:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-drain-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}
	if _, err := js.Publish("ensemble.tap.drain-test.event", data); err != nil {
		t.Fatalf("publish cloud event: %v", err)
	}

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}

	drainDone := make(chan error, 1)
	go func() {
		drainDone <- consumer.Drain(context.Background())
	}()

	select {
	case err := <-drainDone:
		t.Fatalf("drain returned before handler completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseHandler)

	select {
	case err := <-drainDone:
		if err != nil {
			t.Fatalf("drain returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not complete after handler release")
	}
}

func TestConsumerStartBatchInProgressHeartbeatSkipsDeactivatedEntries(t *testing.T) {
	consumer := &Consumer{
		config: ConsumerConfig{
			InProgressInterval: 10 * time.Millisecond,
			Stream:             "test",
			Durable:            "durable",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	var firstCount atomic.Int32
	var secondCount atomic.Int32
	deactivate, stop := consumer.startBatchInProgressHeartbeat(context.Background(), []func() error{
		func() error {
			firstCount.Add(1)
			return nil
		},
		func() error {
			secondCount.Add(1)
			return nil
		},
	})
	defer stop()

	time.Sleep(25 * time.Millisecond)
	deactivate(0)

	firstBefore := firstCount.Load()
	secondBefore := secondCount.Load()
	time.Sleep(30 * time.Millisecond)

	if secondCount.Load() <= secondBefore {
		t.Fatalf("expected active batch heartbeat to keep extending second message, got before=%d after=%d", secondBefore, secondCount.Load())
	}
	if firstCount.Load() != firstBefore {
		t.Fatalf("expected deactivated batch heartbeat to stop extending first message, got before=%d after=%d", firstBefore, firstCount.Load())
	}
}

func TestConsumerHandleMessageSkipsAlreadyProcessedCloudEvent(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		DedupStateFile: t.TempDir() + "/executions.db",
	}).withDefaults()
	deduper, err := newConsumerProcessedEventDeduper(cfg.DedupStateFile, cfg.Stream, cfg.Durable, cfg.DedupTTL, cfg.DedupMaxRecords)
	if err != nil {
		t.Fatalf("new deduper: %v", err)
	}
	defer func() { _ = deduper.Close() }()

	consumer := &Consumer{
		config:  cfg,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:     &consumerDeadLetterSink{},
		deduper: deduper,
	}

	evt := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-dedup-1",
		Source:      "urn:cerebro:test",
		Type:        "ensemble.tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		Data:        map[string]any{"id": "1"},
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var handlerCalls int
	consumer.handler = func(context.Context, CloudEvent) error {
		handlerCalls++
		return nil
	}
	var ackCalls int
	ack := func() error {
		ackCalls++
		return nil
	}

	first := consumer.handleMessage(context.Background(), "ensemble.tap.test", payload, ack, func() error { return nil }, func() error { return nil })
	if !first.Processed {
		t.Fatalf("expected first event to be processed, got %+v", first)
	}
	if handlerCalls != 1 {
		t.Fatalf("expected handler call count 1, got %d", handlerCalls)
	}

	before := counterValue(t, metrics.NATSConsumerDeduplicatedTotal.WithLabelValues(cfg.Stream, cfg.Durable))
	second := consumer.handleMessage(context.Background(), "ensemble.tap.test", payload, ack, func() error { return nil }, func() error { return nil })
	if second.Processed {
		t.Fatalf("expected duplicate event to be skipped, got %+v", second)
	}
	after := counterValue(t, metrics.NATSConsumerDeduplicatedTotal.WithLabelValues(cfg.Stream, cfg.Durable))
	if after != before+1 {
		t.Fatalf("expected deduplicated counter to increment from %v to %v", before, after)
	}
	if handlerCalls != 1 {
		t.Fatalf("expected duplicate event to avoid handler, got %d calls", handlerCalls)
	}
	if ackCalls != 2 {
		t.Fatalf("expected both events to ack, got %d", ackCalls)
	}
}

func TestConsumerHandleMessageDeadLettersDuplicateKeyPayloadMismatch(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		DedupStateFile: t.TempDir() + "/executions.db",
	}).withDefaults()
	deduper, err := newConsumerProcessedEventDeduper(cfg.DedupStateFile, cfg.Stream, cfg.Durable, cfg.DedupTTL, cfg.DedupMaxRecords)
	if err != nil {
		t.Fatalf("new deduper: %v", err)
	}
	defer func() { _ = deduper.Close() }()

	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	consumer := &Consumer{
		config:  cfg,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:     dlq,
		deduper: deduper,
	}

	firstEvent := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-dedup-collision-1",
		Source:      "urn:cerebro:test",
		Type:        "ensemble.tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		Data:        map[string]any{"id": "1", "value": "first"},
	}
	firstPayload, err := json.Marshal(firstEvent)
	if err != nil {
		t.Fatalf("marshal first event: %v", err)
	}

	secondEvent := firstEvent
	secondEvent.Type = "ensemble.tap.test.updated"
	secondEvent.Data = map[string]any{"id": "1", "value": "second"}
	secondPayload, err := json.Marshal(secondEvent)
	if err != nil {
		t.Fatalf("marshal second event: %v", err)
	}

	var handlerCalls int
	consumer.handler = func(context.Context, CloudEvent) error {
		handlerCalls++
		return nil
	}
	var ackCalls int
	var nakCalls int
	ack := func() error {
		ackCalls++
		return nil
	}
	nak := func() error {
		nakCalls++
		return nil
	}

	first := consumer.handleMessage(context.Background(), "ensemble.tap.test", firstPayload, ack, nak, func() error { return nil })
	if !first.Processed {
		t.Fatalf("expected first event to be processed, got %+v", first)
	}

	beforeDedup := counterValue(t, metrics.NATSConsumerDeduplicatedTotal.WithLabelValues(cfg.Stream, cfg.Durable))
	beforeDropped := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "dedupe_hash_mismatch"))
	second := consumer.handleMessage(context.Background(), "ensemble.tap.test", secondPayload, ack, nak, func() error { return nil })
	if second.Processed {
		t.Fatalf("expected hash-mismatch duplicate to avoid normal processing, got %+v", second)
	}

	afterDedup := counterValue(t, metrics.NATSConsumerDeduplicatedTotal.WithLabelValues(cfg.Stream, cfg.Durable))
	if afterDedup != beforeDedup {
		t.Fatalf("expected deduplicated counter unchanged on hash mismatch, before=%v after=%v", beforeDedup, afterDedup)
	}
	afterDropped := counterValue(t, metrics.NATSConsumerDroppedTotal.WithLabelValues(cfg.Stream, cfg.Durable, "dedupe_hash_mismatch"))
	if afterDropped != beforeDropped {
		t.Fatalf("expected hash mismatch to requeue instead of drop, before=%v after=%v", beforeDropped, afterDropped)
	}
	if handlerCalls != 1 {
		t.Fatalf("expected handler to run only for first event, got %d calls", handlerCalls)
	}
	if ackCalls != 1 {
		t.Fatalf("expected only the first event to ack before requeue, got %d", ackCalls)
	}
	if nakCalls != 1 {
		t.Fatalf("expected hash mismatch to requeue once, got %d nacks", nakCalls)
	}

	payload, err := os.ReadFile(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("read consumer dead-letter file: %v", err)
	}
	if got := string(payload); !containsAll(got, "\"reason\":\"dedupe_hash_mismatch\"", "\"subject\":\"ensemble.tap.test\"", "ensemble.tap.test.updated", "\\\"value\\\":\\\"second\\\"") {
		t.Fatalf("expected hash mismatch payload to be written to dead-letter file, got %s", got)
	}

	snapshot := consumer.HealthSnapshot(time.Now().UTC())
	if snapshot.LastDropReason != "" {
		t.Fatalf("expected hash mismatch requeue not to mark a drop, got %q", snapshot.LastDropReason)
	}

	eventKey, ok := consumerProcessedEventKey(firstEvent)
	if !ok {
		t.Fatal("expected event key for first event")
	}
	record, err := deduper.store.LookupProcessedEvent(context.Background(), deduper.namespace, eventKey, time.Now().UTC())
	if err != nil {
		t.Fatalf("LookupProcessedEvent after hash mismatch: %v", err)
	}
	if record != nil {
		t.Fatalf("expected hash mismatch to clear processed event record, got %#v", record)
	}

	third := consumer.handleMessage(context.Background(), "ensemble.tap.test", secondPayload, ack, nak, func() error { return nil })
	if !third.Processed {
		t.Fatalf("expected replayed hash-mismatch event to process after dedupe reset, got %+v", third)
	}
	if handlerCalls != 2 {
		t.Fatalf("expected handler to run again after hash-mismatch reset, got %d calls", handlerCalls)
	}
	if ackCalls != 2 {
		t.Fatalf("expected replayed event to ack after processing, got %d", ackCalls)
	}
	if nakCalls != 1 {
		t.Fatalf("expected only one hash-mismatch requeue, got %d", nakCalls)
	}

	record, err = deduper.store.LookupProcessedEvent(context.Background(), deduper.namespace, eventKey, time.Now().UTC())
	if err != nil {
		t.Fatalf("LookupProcessedEvent after replayed hash mismatch: %v", err)
	}
	if record == nil {
		t.Fatal("expected replayed hash-mismatch event to persist a new processed event record")
	}
	if record.DuplicateCount != 0 {
		t.Fatalf("expected replayed hash-mismatch event to persist without duplicate count, got %#v", record)
	}
}

func TestConsumerProcessedEventKeyIsUnambiguous(t *testing.T) {
	first, ok := consumerProcessedEventKey(CloudEvent{
		ID:       "d",
		Source:   "c",
		TenantID: "a|b",
	})
	if !ok {
		t.Fatal("expected first dedupe key")
	}
	second, ok := consumerProcessedEventKey(CloudEvent{
		ID:       "d",
		Source:   "b|c",
		TenantID: "a",
	})
	if !ok {
		t.Fatal("expected second dedupe key")
	}
	if first == second {
		t.Fatalf("expected canonical dedupe keys to differ, both were %q", first)
	}
	if !strings.HasPrefix(first, "sha256:") || !strings.HasPrefix(second, "sha256:") {
		t.Fatalf("expected canonical hashed dedupe keys, got %q and %q", first, second)
	}
}

func TestSaturatingUint64ToInt(t *testing.T) {
	if got := saturatingUint64ToInt(uint64(math.MaxInt) + 1); got != math.MaxInt {
		t.Fatalf("expected saturation to MaxInt, got %d", got)
	}
	if got := saturatingUint64ToInt(42); got != 42 {
		t.Fatalf("expected exact conversion for small values, got %d", got)
	}
}

func TestClampNegativeIntToUint64(t *testing.T) {
	if got := clampNegativeIntToUint64(-1); got != 0 {
		t.Fatalf("expected negative value to clamp to 0, got %d", got)
	}
	if got := clampNegativeIntToUint64(0); got != 0 {
		t.Fatalf("expected zero value to remain 0, got %d", got)
	}
	if got := clampNegativeIntToUint64(42); got != 42 {
		t.Fatalf("expected positive value to convert exactly, got %d", got)
	}
}

func TestGraphStalenessAt(t *testing.T) {
	now := time.Now().UTC()
	if got, ok := graphStalenessAt(now, time.Time{}); ok || got != 0 {
		t.Fatalf("expected zero/false for missing last processed time, got %s %t", got, ok)
	}

	lastProcessedAt := now.Add(-2 * time.Minute)
	got, ok := graphStalenessAt(now, lastProcessedAt)
	if !ok {
		t.Fatal("expected graph staleness to be available")
	}
	if got != 2*time.Minute {
		t.Fatalf("expected 2m graph staleness, got %s", got)
	}
}

func TestRefreshLagMetricsDoesNotResetGraphStalenessWithoutProcessedEvents(t *testing.T) {
	natsURL := startJetStreamServer(t)

	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:           []string{natsURL},
		Stream:         "ENSEMBLE_TAP_STALENESS_TEST",
		Subject:        "ensemble.tap.staleness-test.>",
		Durable:        "cerebro_staleness_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      1,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
	}, nil, func(context.Context, CloudEvent) error { return nil })
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	lastUpdate := time.Now().UTC().Add(-2 * time.Minute)
	metrics.SetGraphLastUpdate(lastUpdate)
	before := gaugeValue(t, metrics.GraphStalenessSeconds)

	consumer.refreshLagMetrics(time.Now().UTC())
	after := gaugeValue(t, metrics.GraphStalenessSeconds)

	if after != before {
		t.Fatalf("expected lag refresh without processed events to preserve graph staleness, before=%v after=%v", before, after)
	}
}

func TestRecordProcessedPreservesLastEventTimeWhenMissing(t *testing.T) {
	consumer := &Consumer{}
	firstEvent := time.Now().UTC().Add(-time.Minute)
	consumer.recordProcessed(time.Now().UTC().Add(-30*time.Second), firstEvent)
	consumer.recordProcessed(time.Now().UTC(), time.Time{})

	consumer.statusMu.RLock()
	defer consumer.statusMu.RUnlock()
	if !consumer.lastEventTime.Equal(firstEvent) {
		t.Fatalf("expected last event time %s to be preserved, got %s", firstEvent, consumer.lastEventTime)
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
	}, nil)

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
	}, nil)

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

func TestConsumerHandleMessageExtendsAckWaitWhileProcessing(t *testing.T) {
	cfg := (ConsumerConfig{
		URLs:                []string{"nats://127.0.0.1:4222"},
		Stream:              "ENSEMBLE_TAP_TEST",
		Subject:             "ensemble.tap.test.>",
		Durable:             "cerebro_graph_builder_test_progress",
		DeadLetterPath:      t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:           1,
		AckWait:             time.Second,
		FetchTimeout:        time.Second,
		InProgressInterval:  10 * time.Millisecond,
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
			time.Sleep(35 * time.Millisecond)
			return nil
		},
		dlq: dlq,
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-progress-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	var acked atomic.Int64
	var inProgressCalls atomic.Int64
	result := consumer.handleMessage(context.Background(), "ensemble.tap.test.event", payload, func() error {
		acked.Add(1)
		return nil
	}, func() error {
		t.Fatal("expected message to be acked, not nacked")
		return nil
	}, func() error {
		inProgressCalls.Add(1)
		return nil
	})

	if !result.Processed {
		t.Fatal("expected message to be processed successfully")
	}
	if acked.Load() != 1 {
		t.Fatalf("expected one ack, got %d", acked.Load())
	}
	if inProgressCalls.Load() == 0 {
		t.Fatal("expected at least one in-progress heartbeat")
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

func gaugeValue(t *testing.T, metric interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	snapshot := &dto.Metric{}
	if err := metric.Write(snapshot); err != nil {
		t.Fatalf("write gauge snapshot: %v", err)
	}
	if snapshot.Gauge == nil {
		t.Fatal("expected gauge metric")
	}
	return snapshot.Gauge.GetValue()
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

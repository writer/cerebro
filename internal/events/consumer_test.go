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
	if cfg.Stream != "CEREBRO_EVENTS" || cfg.Subject != "cerebro.events.>" {
		t.Fatalf("unexpected default stream/subject: %q %q", cfg.Stream, cfg.Subject)
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
		Stream:         "CEREBRO_EVENTS",
		Subject:        "cerebro.events.>",
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
		Stream:         "CEREBRO_EVENTS",
		Subject:        "cerebro.events.>",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      0,
	}
	if err := invalid.validate(); err == nil {
		t.Fatal("expected validation error for invalid batch size")
	}
}

func TestConsumerConfigWithDefaultsNormalizesSubjectFilters(t *testing.T) {
	cfg := (ConsumerConfig{
		Subject:  "cerebro.events.primary.>",
		Subjects: []string{"", "cerebro.events.secondary.>", "cerebro.events.primary.>"},
	}).withDefaults()

	if cfg.Subject != "cerebro.events.primary.>" {
		t.Fatalf("expected first normalized subject to become primary, got %q", cfg.Subject)
	}
	if len(cfg.Subjects) != 2 {
		t.Fatalf("expected 2 unique normalized subjects, got %v", cfg.Subjects)
	}
	if cfg.Subjects[0] != "cerebro.events.primary.>" || cfg.Subjects[1] != "cerebro.events.secondary.>" {
		t.Fatalf("unexpected normalized subjects: %v", cfg.Subjects)
	}
}

func TestSubjectPatternCoversPattern(t *testing.T) {
	tests := []struct {
		name     string
		stream   string
		consumer string
		want     bool
	}{
		{name: "global wildcard covers ensemble tap", stream: ">", consumer: "ensemble.tap.>", want: true},
		{name: "prefix wildcard covers specific subtree", stream: "cerebro.events.>", consumer: "cerebro.events.github.*", want: true},
		{name: "specific subtree does not cover broader prefix", stream: "cerebro.events.github.*", consumer: "cerebro.events.>", want: false},
		{name: "mixed wildcard covers nested wildcard", stream: "foo.*.>", consumer: "foo.bar.>", want: true},
		{name: "literal token does not cover wildcard token", stream: "foo.bar.>", consumer: "foo.*.>", want: false},
		{name: "tail wildcard does not cover shorter subject", stream: "foo.>", consumer: "foo", want: false},
		{name: "single token wildcard covers literal", stream: "foo.*", consumer: "foo.bar", want: true},
		{name: "literal does not cover single token wildcard", stream: "foo.bar", consumer: "foo.*", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subjectPatternCoversPattern(tt.stream, tt.consumer); got != tt.want {
				t.Fatalf("subjectPatternCoversPattern(%q, %q) = %t, want %t", tt.stream, tt.consumer, got, tt.want)
			}
		})
	}
}

func TestJetStreamConsumer_ConsumesConfiguredSubjects(t *testing.T) {
	natsURL := startJetStreamServer(t)
	received := make(chan string, 2)

	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:           []string{natsURL},
		Stream:         "CEREBRO_EVENTS_MULTI_SUBJECT_TEST",
		Subjects:       []string{"cerebro.events.repo.>", "cerebro.events.chat.>"},
		Durable:        "cerebro_multi_subject_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      1,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
	}, nil, func(_ context.Context, evt CloudEvent) error {
		received <- evt.Type
		return nil
	})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	if info, err := consumer.sub.ConsumerInfo(); err != nil {
		t.Fatalf("consumer info: %v", err)
	} else if len(info.Config.FilterSubjects) != 2 {
		t.Fatalf("expected 2 consumer filter subjects, got %#v", info.Config.FilterSubjects)
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}

	eventsBySubject := map[string]string{
		"cerebro.events.repo.synced":         "repo.synced",
		"cerebro.events.chat.message_posted": "chat.message_posted",
	}
	for subject, eventType := range eventsBySubject {
		event := CloudEvent{
			SpecVersion: cloudEventSpecVersion,
			ID:          "evt-" + strings.ReplaceAll(eventType, ".", "-"),
			Source:      "cerebro.events.test",
			Type:        eventType,
			Time:        time.Now().UTC(),
			DataSchema:  "urn:cerebro:events:test",
		}
		payload, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal cloud event %s: %v", eventType, err)
		}
		if _, err := js.Publish(subject, payload); err != nil {
			t.Fatalf("publish %s: %v", subject, err)
		}
	}

	seen := make(map[string]bool, len(eventsBySubject))
	deadline := time.After(5 * time.Second)
	for len(seen) < len(eventsBySubject) {
		select {
		case eventType := <-received:
			seen[eventType] = true
		case <-deadline:
			t.Fatalf("timed out waiting for events, saw %v", seen)
		}
	}

	for _, eventType := range eventsBySubject {
		if !seen[eventType] {
			t.Fatalf("expected event type %q to be consumed, saw %v", eventType, seen)
		}
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

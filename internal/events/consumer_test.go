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
	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestConsumerConfigWithDefaults(t *testing.T) {
	cfg := (ConsumerConfig{}).withDefaults()
	if len(cfg.URLs) == 0 {
		t.Fatal("expected default URL")
	}
	if cfg.Stream == "" || cfg.Subject == "" || cfg.Durable == "" {
		t.Fatal("expected default stream/subject/durable")
	}
	if cfg.BatchSize <= 0 || cfg.HandlerWorkers <= 0 || cfg.AckWait <= 0 || cfg.FetchTimeout <= 0 {
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

func TestJetStreamConsumerProcessesMultipleFilterSubjects(t *testing.T) {
	natsURL := startJetStreamServer(t)

	received := make(chan string, 4)
	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:           []string{natsURL},
		Stream:         "ENSEMBLE_GRAPH_MULTI_SUBJECT_TEST",
		Subjects:       []string{"ensemble.tap.>", "aws.cloudtrail.>"},
		Durable:        "cerebro_multi_subject_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      2,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
	}, nil, func(_ context.Context, evt CloudEvent) error {
		received <- evt.ID
		return nil
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

	for _, tc := range []struct {
		subject string
		id      string
		typ     string
	}{
		{subject: "ensemble.tap.github.pull_request.merged", id: "evt-tap-1", typ: "ensemble.tap.github.pull_request.merged"},
		{subject: "aws.cloudtrail.asset.changed", id: "evt-audit-1", typ: "aws.cloudtrail.asset.changed"},
	} {
		payload, err := json.Marshal(CloudEvent{
			SpecVersion: cloudEventSpecVersion,
			ID:          tc.id,
			Source:      "urn:test",
			Type:        tc.typ,
			Time:        time.Now().UTC(),
			DataSchema:  "urn:test:schema",
		})
		if err != nil {
			t.Fatalf("marshal cloud event: %v", err)
		}
		if _, err := js.Publish(tc.subject, payload); err != nil {
			t.Fatalf("publish cloud event %s: %v", tc.id, err)
		}
	}

	want := map[string]bool{"evt-tap-1": false, "evt-audit-1": false}
	deadline := time.After(5 * time.Second)
	for range want {
		select {
		case id := <-received:
			want[id] = true
		case <-deadline:
			t.Fatalf("timed out waiting for multi-subject deliveries: %#v", want)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("expected event %s to be delivered, got %#v", id, want)
		}
	}
}

func TestJetStreamConsumerUpgradesExistingDurableToMultipleFilterSubjects(t *testing.T) {
	natsURL := startJetStreamServer(t)

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "ENSEMBLE_GRAPH_UPGRADE_TEST",
		Subjects: []string{"ensemble.tap.>", "aws.cloudtrail.>"},
		Storage:  nats.FileStorage,
	})
	if err != nil {
		t.Fatalf("add stream: %v", err)
	}
	_, err = js.AddConsumer("ENSEMBLE_GRAPH_UPGRADE_TEST", &nats.ConsumerConfig{
		Durable:       "cerebro_upgrade_multi_subject_test",
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: "ensemble.tap.>",
	})
	if err != nil {
		t.Fatalf("add legacy consumer: %v", err)
	}

	received := make(chan string, 4)
	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:           []string{natsURL},
		Stream:         "ENSEMBLE_GRAPH_UPGRADE_TEST",
		Subjects:       []string{"ensemble.tap.>", "aws.cloudtrail.>"},
		Durable:        "cerebro_upgrade_multi_subject_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      2,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
	}, nil, func(_ context.Context, evt CloudEvent) error {
		received <- evt.ID
		return nil
	})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	for _, tc := range []struct {
		subject string
		id      string
		typ     string
	}{
		{subject: "ensemble.tap.github.pull_request.merged", id: "evt-tap-upgrade-1", typ: "ensemble.tap.github.pull_request.merged"},
		{subject: "aws.cloudtrail.asset.changed", id: "evt-audit-upgrade-1", typ: "aws.cloudtrail.asset.changed"},
	} {
		payload, err := json.Marshal(CloudEvent{
			SpecVersion: cloudEventSpecVersion,
			ID:          tc.id,
			Source:      "urn:test",
			Type:        tc.typ,
			Time:        time.Now().UTC(),
			DataSchema:  "urn:test:schema",
		})
		if err != nil {
			t.Fatalf("marshal cloud event: %v", err)
		}
		if _, err := js.Publish(tc.subject, payload); err != nil {
			t.Fatalf("publish cloud event %s: %v", tc.id, err)
		}
	}

	want := map[string]bool{"evt-tap-upgrade-1": false, "evt-audit-upgrade-1": false}
	deadline := time.After(5 * time.Second)
	for range want {
		select {
		case id := <-received:
			want[id] = true
		case <-deadline:
			t.Fatalf("timed out waiting for upgraded durable deliveries: %#v", want)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("expected event %s to be delivered after durable upgrade, got %#v", id, want)
		}
	}
}

func TestJetStreamConsumerUpdatesExistingStreamSubjectsForAuditSources(t *testing.T) {
	natsURL := startJetStreamServer(t)

	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "ENSEMBLE_GRAPH_STREAM_UPGRADE_TEST",
		Subjects: []string{"ensemble.tap.>"},
		Storage:  nats.FileStorage,
	})
	if err != nil {
		t.Fatalf("add stream: %v", err)
	}

	received := make(chan string, 2)
	consumer, err := NewJetStreamConsumer(ConsumerConfig{
		URLs:           []string{natsURL},
		Stream:         "ENSEMBLE_GRAPH_STREAM_UPGRADE_TEST",
		Subjects:       []string{"ensemble.tap.>", "aws.cloudtrail.>"},
		Durable:        "cerebro_stream_upgrade_test",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      1,
		AckWait:        5 * time.Second,
		FetchTimeout:   100 * time.Millisecond,
	}, nil, func(_ context.Context, evt CloudEvent) error {
		received <- evt.ID
		return nil
	})
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	streamInfo, err := js.StreamInfo("ENSEMBLE_GRAPH_STREAM_UPGRADE_TEST")
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if !streamHasSubject(streamInfo.Config.Subjects, "aws.cloudtrail.>") {
		t.Fatalf("expected stream subjects to be updated, got %v", streamInfo.Config.Subjects)
	}

	payload, err := json.Marshal(CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-audit-stream-upgrade-1",
		Source:      "urn:test",
		Type:        "aws.cloudtrail.asset.changed",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:test:schema",
	})
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}
	if _, err := js.Publish("aws.cloudtrail.asset.changed", payload); err != nil {
		t.Fatalf("publish audit cloud event: %v", err)
	}

	select {
	case id := <-received:
		if id != "evt-audit-stream-upgrade-1" {
			t.Fatalf("unexpected delivered event %q", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for audit delivery after stream subject upgrade")
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

func TestConsumerStartInProgressHeartbeatContinuesAfterContextCancelUntilStopped(t *testing.T) {
	consumer := &Consumer{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: (ConsumerConfig{
			InProgressInterval: 10 * time.Millisecond,
		}).withDefaults(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	var beats atomic.Int64
	stop := consumer.startInProgressHeartbeat(ctx, func() error {
		beats.Add(1)
		return nil
	})

	cancel()
	time.Sleep(35 * time.Millisecond)
	if beats.Load() == 0 {
		stop()
		t.Fatal("expected in-progress heartbeat to continue after context cancellation")
	}

	beforeStop := beats.Load()
	stop()
	time.Sleep(20 * time.Millisecond)
	if beats.Load() != beforeStop {
		t.Fatalf("expected in-progress heartbeat to stop after stop(), got before=%d after=%d", beforeStop, beats.Load())
	}
}

func TestConsumerStartBatchInProgressHeartbeatContinuesAfterContextCancelUntilStopped(t *testing.T) {
	consumer := &Consumer{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: (ConsumerConfig{
			InProgressInterval: 10 * time.Millisecond,
		}).withDefaults(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	var first atomic.Int64
	var second atomic.Int64
	deactivate, stop := consumer.startBatchInProgressHeartbeat(ctx, []func() error{
		func() error {
			first.Add(1)
			return nil
		},
		func() error {
			second.Add(1)
			return nil
		},
	})

	cancel()
	time.Sleep(35 * time.Millisecond)
	if first.Load() == 0 || second.Load() == 0 {
		stop()
		t.Fatalf("expected batch heartbeats to continue after context cancellation, got first=%d second=%d", first.Load(), second.Load())
	}

	deactivate(0)
	firstBefore := first.Load()
	secondBefore := second.Load()
	time.Sleep(20 * time.Millisecond)
	stop()
	if first.Load() != firstBefore {
		t.Fatalf("expected deactivated batch heartbeat to stop after cancellation, got before=%d after=%d", firstBefore, first.Load())
	}
	if second.Load() <= secondBefore {
		t.Fatalf("expected active batch heartbeat to continue after cancellation, got before=%d after=%d", secondBefore, second.Load())
	}
}

func TestConsumerProcessBatchPreservesPerEntityOrderingAcrossWorkers(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      8,
		HandlerWorkers: 4,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	entityA := "customer:a"
	entityB := ""
	for _, candidate := range []string{"customer:b", "customer:c", "customer:d", "customer:e"} {
		if consumerShardIndex(testConsumerEvent(candidate, 1, true), cfg.HandlerWorkers) != consumerShardIndex(testConsumerEvent(entityA, 1, true), cfg.HandlerWorkers) {
			entityB = candidate
			break
		}
	}
	if entityB == "" {
		t.Fatal("expected distinct shard candidate for concurrent worker test")
	}

	var (
		mu      sync.Mutex
		started = make(map[string][]int)
		aOnce   sync.Once
		bOnce   sync.Once
	)
	aStarted := make(chan struct{})
	bStarted := make(chan struct{})
	releaseA := make(chan struct{})

	consumer := &Consumer{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:    dlq,
		handler: func(ctx context.Context, evt CloudEvent) error {
			entityID := extractEntityID(evt.Data)
			seq := int(evt.Data["seq"].(float64))
			mu.Lock()
			started[entityID] = append(started[entityID], seq)
			mu.Unlock()
			if entityID == entityA && seq == 1 {
				aOnce.Do(func() { close(aStarted) })
				<-releaseA
			}
			if entityID == entityB {
				bOnce.Do(func() { close(bStarted) })
			}
			return nil
		},
	}

	messages := []consumerPipelineMessage{
		testConsumerPipelineMessage(t, 0, testConsumerEvent(entityA, 1, true), nil),
		testConsumerPipelineMessage(t, 1, testConsumerEvent(entityB, 1, true), nil),
		testConsumerPipelineMessage(t, 2, testConsumerEvent(entityA, 2, true), nil),
		testConsumerPipelineMessage(t, 3, testConsumerEvent(entityA, 3, true), nil),
		testConsumerPipelineMessage(t, 4, testConsumerEvent(entityA, 4, true), nil),
	}

	done := make(chan bool, 1)
	go func() {
		done <- consumer.processBatch(context.Background(), messages)
	}()

	select {
	case <-aStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first entity-a handler start")
	}
	select {
	case <-bStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for concurrent entity-b handler start")
	}

	mu.Lock()
	gotWhileBlocked := append([]int(nil), started[entityA]...)
	mu.Unlock()
	if !equalIntSlices(gotWhileBlocked, []int{1}) {
		t.Fatalf("expected only the first entity-a event to start before release, got %v", gotWhileBlocked)
	}

	close(releaseA)
	backpressured := false
	select {
	case backpressured = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for batch pipeline to finish")
	}
	if backpressured {
		t.Fatal("expected one hot shard to preserve throughput without reporting global backpressure")
	}

	mu.Lock()
	gotA := append([]int(nil), started[entityA]...)
	gotB := append([]int(nil), started[entityB]...)
	mu.Unlock()
	if !equalIntSlices(gotA, []int{1, 2, 3, 4}) {
		t.Fatalf("expected entity-a processing order [1 2 3 4], got %v", gotA)
	}
	if !equalIntSlices(gotB, []int{1}) {
		t.Fatalf("expected entity-b processing order [1], got %v", gotB)
	}
}

func TestConsumerProcessBatchSkipsDuplicateEventsWithinSameBatch(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		DedupStateFile: t.TempDir() + "/executions.db",
		DedupEnabled:   true,
		BatchSize:      4,
		HandlerWorkers: 4,
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

	var handlerCalls atomic.Int32
	var ackCalls atomic.Int32
	consumer := &Consumer{
		config:  cfg,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:     dlq,
		deduper: deduper,
		handler: func(context.Context, CloudEvent) error {
			handlerCalls.Add(1)
			time.Sleep(20 * time.Millisecond)
			return nil
		},
	}

	event := testConsumerEvent("", 1, false)
	event.ID = "evt-duplicate-batch"
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal duplicate event: %v", err)
	}
	messages := []consumerPipelineMessage{
		{
			index:   0,
			subject: "ensemble.tap.test",
			payload: payload,
			ack: func() error {
				ackCalls.Add(1)
				return nil
			},
			nak: func() error { return nil },
		},
		{
			index:   1,
			subject: "ensemble.tap.test",
			payload: payload,
			ack: func() error {
				ackCalls.Add(1)
				return nil
			},
			nak: func() error { return nil },
		},
	}

	consumer.processBatch(context.Background(), messages)
	if handlerCalls.Load() != 1 {
		t.Fatalf("expected one handler call for duplicate batch events, got %d", handlerCalls.Load())
	}
	if ackCalls.Load() != 2 {
		t.Fatalf("expected both duplicate batch events to ack, got %d", ackCalls.Load())
	}
}

func TestConsumerProcessBatchStopsDispatchOnContextCancel(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      4,
		HandlerWorkers: 4,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	var handlerCalls atomic.Int32
	firstStarted := make(chan struct{})
	consumer := &Consumer{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:    dlq,
		handler: func(ctx context.Context, evt CloudEvent) error {
			if extractEntityID(evt.Data) != "customer:a" {
				t.Fatalf("unexpected entity routed to blocked shard: %#v", evt.Data)
			}
			if handlerCalls.Add(1) == 1 {
				close(firstStarted)
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	messages := []consumerPipelineMessage{
		testConsumerPipelineMessage(t, 0, testConsumerEvent("customer:a", 1, true), nil),
		testConsumerPipelineMessage(t, 1, testConsumerEvent("customer:a", 2, true), nil),
		testConsumerPipelineMessage(t, 2, testConsumerEvent("customer:a", 3, true), nil),
	}

	done := make(chan bool, 1)
	go func() {
		done <- consumer.processBatch(ctx, messages)
	}()

	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first shard handler to start")
	}

	cancel()

	select {
	case backpressured := <-done:
		if backpressured {
			t.Fatal("expected context cancellation to stop dispatch without reporting global backpressure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("processBatch did not stop after context cancellation")
	}
}

func TestConsumerProcessBatchReportsBackpressureWhenPipelineSaturates(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      2,
		HandlerWorkers: 1,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	consumer := &Consumer{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:    dlq,
		handler: func(context.Context, CloudEvent) error {
			once.Do(func() { close(started) })
			<-release
			return nil
		},
	}

	messages := []consumerPipelineMessage{
		testConsumerPipelineMessage(t, 0, testConsumerEvent("customer:a", 1, true), nil),
		testConsumerPipelineMessage(t, 1, testConsumerEvent("customer:b", 1, true), nil),
		testConsumerPipelineMessage(t, 2, testConsumerEvent("customer:c", 1, true), nil),
		testConsumerPipelineMessage(t, 3, testConsumerEvent("customer:d", 1, true), nil),
	}

	done := make(chan bool, 1)
	go func() {
		done <- consumer.processBatch(context.Background(), messages)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pipeline handler to start")
	}

	time.Sleep(25 * time.Millisecond)
	close(release)

	select {
	case backpressured := <-done:
		if !backpressured {
			t.Fatal("expected saturated pipeline to report backpressure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for saturated pipeline batch to finish")
	}
}

func TestConsumerProcessBatchPreservesBackpressureSignalOnContextCancel(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      2,
		HandlerWorkers: 1,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	consumer := &Consumer{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:    dlq,
		handler: func(context.Context, CloudEvent) error {
			once.Do(func() { close(started) })
			<-release
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	messages := []consumerPipelineMessage{
		testConsumerPipelineMessage(t, 0, testConsumerEvent("customer:a", 1, true), nil),
		testConsumerPipelineMessage(t, 1, testConsumerEvent("customer:b", 1, true), nil),
		testConsumerPipelineMessage(t, 2, testConsumerEvent("customer:c", 1, true), nil),
		testConsumerPipelineMessage(t, 3, testConsumerEvent("customer:d", 1, true), nil),
	}

	done := make(chan bool, 1)
	go func() {
		done <- consumer.processBatch(ctx, messages)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pipeline handler to start")
	}

	time.Sleep(25 * time.Millisecond)
	cancel()
	close(release)

	select {
	case backpressured := <-done:
		if !backpressured {
			t.Fatal("expected context cancellation to preserve prior backpressure signal")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for cancelled saturated pipeline batch to finish")
	}
}

func TestConsumerProcessBatchReportsIntakeBackpressureForHotShard(t *testing.T) {
	cfg := (ConsumerConfig{
		Stream:         "ENSEMBLE_TAP",
		Durable:        "cerebro_graph_builder",
		DeadLetterPath: t.TempDir() + "/consumer.dlq.jsonl",
		BatchSize:      4,
		HandlerWorkers: 2,
	}).withDefaults()
	dlq, err := newConsumerDeadLetterSink(cfg.DeadLetterPath)
	if err != nil {
		t.Fatalf("new consumer dead-letter sink: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	consumer := &Consumer{
		config: cfg,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dlq:    dlq,
		handler: func(context.Context, CloudEvent) error {
			once.Do(func() { close(started) })
			<-release
			return nil
		},
	}

	messages := make([]consumerPipelineMessage, 10)
	for i := range messages {
		messages[i] = testConsumerPipelineMessage(t, i, testConsumerEvent("customer:a", i+1, true), nil)
	}

	done := make(chan bool, 1)
	go func() {
		done <- consumer.processBatch(context.Background(), messages)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hot shard handler to start")
	}

	time.Sleep(25 * time.Millisecond)
	close(release)

	select {
	case backpressured := <-done:
		if !backpressured {
			t.Fatal("expected intake saturation behind a hot shard to report backpressure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hot shard batch to finish")
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

func TestAdaptiveConsumerBatchSize(t *testing.T) {
	if got := initialAdaptiveConsumerBatchSize(1); got != 1 {
		t.Fatalf("initialAdaptiveConsumerBatchSize(1) = %d, want 1", got)
	}
	if got := initialAdaptiveConsumerBatchSize(50); got != 8 {
		t.Fatalf("initialAdaptiveConsumerBatchSize(50) = %d, want 8", got)
	}
	if got := nextAdaptiveConsumerBatchSize(8, 50, 8, false); got != 16 {
		t.Fatalf("nextAdaptiveConsumerBatchSize(8, 50, 8, false) = %d, want 16", got)
	}
	if got := nextAdaptiveConsumerBatchSize(16, 50, 4, false); got != 16 {
		t.Fatalf("nextAdaptiveConsumerBatchSize(16, 50, 4, false) = %d, want 16", got)
	}
	if got := nextAdaptiveConsumerBatchSize(16, 50, 16, true); got != 8 {
		t.Fatalf("nextAdaptiveConsumerBatchSize(16, 50, 16, true) = %d, want 8", got)
	}
}

func TestConsumerShardIndexStaysWithinWorkerRange(t *testing.T) {
	evt := CloudEvent{
		ID:       "evt-1",
		TenantID: "tenant-a",
		Subject:  "ensemble.tap.test",
		Type:     "tap.test",
	}
	workers := 1 << 20
	got := consumerShardIndex(evt, workers)
	if got < 0 || got >= workers {
		t.Fatalf("consumerShardIndex() = %d, want range [0,%d)", got, workers)
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

func TestConsumerHandleMessagePropagatesTraceparentIntoHandlerSpans(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(traceContextPropagator())
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
		_ = tp.Shutdown(t.Context())
	})

	var handlerTraceID trace.TraceID
	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:  "ENSEMBLE_TAP_TEST",
			Durable: "cerebro_trace_test",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(ctx context.Context, evt CloudEvent) error {
			handlerTraceID = trace.SpanFromContext(ctx).SpanContext().TraceID()
			if evt.ID != "evt-trace-1" {
				t.Fatalf("unexpected event %q", evt.ID)
			}
			return nil
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-trace-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	var acked atomic.Int64
	result := consumer.handleMessage(context.Background(), "ensemble.tap.trace.event", payload, func() error {
		acked.Add(1)
		return nil
	}, func() error {
		t.Fatal("expected message to be acked, not nacked")
		return nil
	}, func() error { return nil })

	if !result.Processed {
		t.Fatal("expected traced message to be processed successfully")
	}
	if acked.Load() != 1 {
		t.Fatalf("expected one ack, got %d", acked.Load())
	}
	expectedTraceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("trace id parse: %v", err)
	}
	if handlerTraceID != expectedTraceID {
		t.Fatalf("handler trace id = %s, want %s", handlerTraceID.String(), expectedTraceID.String())
	}

	spans := exporter.GetSpans()
	for _, name := range []string{"cerebro.event.decode", "cerebro.event.ingest", "cerebro.event.dedup", "cerebro.event.handle", "cerebro.event.ack"} {
		span := testConsumerSpanByName(t, spans, name)
		if span.SpanContext.TraceID() != expectedTraceID {
			t.Fatalf("%s trace id = %s, want %s", name, span.SpanContext.TraceID().String(), expectedTraceID.String())
		}
	}

	ingestSpan := testConsumerSpanByName(t, spans, "cerebro.event.ingest")
	if ingestSpan.Parent.SpanID() != testConsumerSpanByName(t, spans, "cerebro.event.decode").SpanContext.SpanID() {
		t.Fatalf("ingest span parent = %s, want decode span", ingestSpan.Parent.SpanID().String())
	}
	handleSpan := testConsumerSpanByName(t, spans, "cerebro.event.handle")
	if handleSpan.Parent.SpanID() != ingestSpan.SpanContext.SpanID() {
		t.Fatalf("handle span parent = %s, want ingest span", handleSpan.Parent.SpanID().String())
	}
	if got, ok := testConsumerSpanAttribute(handleSpan, "cerebro.event.id"); !ok || got != "evt-trace-1" {
		t.Fatalf("handle span event id = %q, ok=%t", got, ok)
	}
}

func TestConsumerHandleMessageTracesNakOnHandlerFailure(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(traceContextPropagator())
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
		_ = tp.Shutdown(t.Context())
	})

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:  "ENSEMBLE_TAP_TEST",
			Durable: "cerebro_trace_test",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(context.Context, CloudEvent) error {
			return errors.New("boom")
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-trace-fail-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-01",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	var nacked atomic.Int64
	result := consumer.handleMessage(context.Background(), "ensemble.tap.trace.event", payload, func() error {
		t.Fatal("expected failed handler to nack, not ack")
		return nil
	}, func() error {
		nacked.Add(1)
		return nil
	}, func() error { return nil })

	if result.Processed {
		t.Fatal("expected failed handler result to remain unprocessed")
	}
	if nacked.Load() != 1 {
		t.Fatalf("expected one nak, got %d", nacked.Load())
	}

	spans := exporter.GetSpans()
	handleSpan := testConsumerSpanByName(t, spans, "cerebro.event.handle")
	if handleSpan.Status.Code != codes.Error {
		t.Fatalf("handler span status = %v, want error", handleSpan.Status.Code)
	}
	ackSpan := testConsumerSpanByName(t, spans, "cerebro.event.ack")
	if got, ok := testConsumerSpanAttribute(ackSpan, "cerebro.event.ack_operation"); !ok || got != "nak" {
		t.Fatalf("ack span operation = %q, ok=%t", got, ok)
	}
}

func TestConsumerHandleDecodedMessageTracesDelayedNakForRetryWithDelayErrors(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(traceContextPropagator())
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
		_ = tp.Shutdown(t.Context())
	})

	const retryDelay = 5 * time.Second

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:  "ENSEMBLE_TAP_TEST",
			Durable: "cerebro_retry_delay_trace_test",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(context.Context, CloudEvent) error {
			return RetryWithDelay(errors.New("deferred"), retryDelay)
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-retry-delay-trace-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-01",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	var delayedNaks atomic.Int64
	decoded := consumer.decodePipelineMessage(context.Background(), consumerPipelineMessage{
		subject: "ensemble.tap.retry.event",
		payload: payload,
		ack: func() error {
			t.Fatal("expected deferred handler failure not to ack")
			return nil
		},
		nak: func() error {
			t.Fatal("expected deferred handler failure not to use immediate nak")
			return nil
		},
		nakWithDelay: func(delay time.Duration) error {
			if delay != retryDelay {
				t.Fatalf("delayed nak used delay %s, want %s", delay, retryDelay)
			}
			delayedNaks.Add(1)
			return nil
		},
		inProgress: func() error { return nil },
	})

	result := consumer.handleDecodedMessage(decoded)
	if result.Processed {
		t.Fatal("expected deferred handler result to remain unprocessed")
	}
	if delayedNaks.Load() != 1 {
		t.Fatalf("expected one delayed nak, got %d", delayedNaks.Load())
	}

	spans := exporter.GetSpans()
	handleSpan := testConsumerSpanByName(t, spans, "cerebro.event.handle")
	if handleSpan.Status.Code != codes.Error {
		t.Fatalf("handler span status = %v, want error", handleSpan.Status.Code)
	}
	ackSpan := testConsumerSpanByName(t, spans, "cerebro.event.ack")
	if got, ok := testConsumerSpanAttribute(ackSpan, "cerebro.event.ack_operation"); !ok || got != "nak_with_delay" {
		t.Fatalf("ack span operation = %q, ok=%t", got, ok)
	}
}

func TestConsumerHandleDecodedMessageUsesDelayedNakForRetryWithDelayErrors(t *testing.T) {
	const retryDelay = 5 * time.Second

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:  "ENSEMBLE_TAP_TEST",
			Durable: "cerebro_retry_delay_test",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(context.Context, CloudEvent) error {
			return RetryWithDelay(errors.New("deferred"), retryDelay)
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-retry-delay-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	var immediateNaks atomic.Int64
	var delayedNaks atomic.Int64
	gotDelay := time.Duration(0)
	decoded := consumer.decodePipelineMessage(context.Background(), consumerPipelineMessage{
		subject: "ensemble.tap.retry.event",
		payload: payload,
		ack: func() error {
			t.Fatal("expected deferred handler failure not to ack")
			return nil
		},
		nak: func() error {
			immediateNaks.Add(1)
			return nil
		},
		nakWithDelay: func(delay time.Duration) error {
			delayedNaks.Add(1)
			gotDelay = delay
			return nil
		},
		inProgress: func() error { return nil },
	})

	result := consumer.handleDecodedMessage(decoded)
	if result.Processed {
		t.Fatal("expected deferred handler result to remain unprocessed")
	}
	if immediateNaks.Load() != 0 {
		t.Fatalf("expected no immediate naks, got %d", immediateNaks.Load())
	}
	if delayedNaks.Load() != 1 {
		t.Fatalf("expected one delayed nak, got %d", delayedNaks.Load())
	}
	if gotDelay != retryDelay {
		t.Fatalf("delayed nak used delay %s, want %s", gotDelay, retryDelay)
	}
}

func TestConsumerProcessBatchUsesDelayedNakForRetryWithDelayErrors(t *testing.T) {
	const retryDelay = 5 * time.Second

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:         "ENSEMBLE_TAP_TEST",
			Durable:        "cerebro_retry_delay_batch_test",
			BatchSize:      1,
			HandlerWorkers: 1,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(context.Context, CloudEvent) error {
			return RetryWithDelay(errors.New("deferred"), retryDelay)
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-retry-delay-batch-1",
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
	var immediateNaks atomic.Int64
	var delayedNaks atomic.Int64
	var gotDelay atomic.Int64
	consumer.processBatch(context.Background(), []consumerPipelineMessage{
		{
			index:   0,
			subject: "ensemble.tap.retry.event",
			payload: payload,
			ack: func() error {
				acked.Add(1)
				return nil
			},
			nak: func() error {
				immediateNaks.Add(1)
				return nil
			},
			nakWithDelay: func(delay time.Duration) error {
				delayedNaks.Add(1)
				gotDelay.Store(int64(delay))
				return nil
			},
		},
	})

	if acked.Load() != 0 {
		t.Fatalf("expected deferred handler failure not to ack, got %d", acked.Load())
	}
	if immediateNaks.Load() != 0 {
		t.Fatalf("expected no immediate naks, got %d", immediateNaks.Load())
	}
	if delayedNaks.Load() != 1 {
		t.Fatalf("expected one delayed nak, got %d", delayedNaks.Load())
	}
	if time.Duration(gotDelay.Load()) != retryDelay {
		t.Fatalf("delayed nak used delay %s, want %s", time.Duration(gotDelay.Load()), retryDelay)
	}
}

func TestConsumerHandleMessagePropagatesEventAttributesIntoHandlerChildSpans(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(traceContextPropagator())
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
		_ = tp.Shutdown(t.Context())
	})

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:  "ENSEMBLE_TAP_TEST",
			Durable: "cerebro_trace_test",
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(ctx context.Context, evt CloudEvent) error {
			_, span := telemetry.StartSpan(ctx, "cerebro.test", "cerebro.test.child")
			span.End()
			return nil
		},
	}

	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-trace-attrs-1",
		Source:      "cerebro.events.test",
		Type:        "tap.test",
		Subject:     "workload-a",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal cloud event: %v", err)
	}

	result := consumer.handleMessage(context.Background(), "ensemble.tap.trace.event", payload, func() error {
		return nil
	}, func() error {
		t.Fatal("expected message to be acked, not nacked")
		return nil
	}, func() error { return nil })
	if !result.Processed {
		t.Fatal("expected message to be processed successfully")
	}

	childSpan := testConsumerSpanByName(t, exporter.GetSpans(), "cerebro.test.child")
	for key, want := range map[string]string{
		"cerebro.event.id":      "evt-trace-attrs-1",
		"cerebro.event.source":  "cerebro.events.test",
		"cerebro.event.type":    "tap.test",
		"cerebro.event.subject": "workload-a",
		"cerebro.tenant_id":     "tenant-a",
	} {
		if got, ok := testConsumerSpanAttribute(childSpan, key); !ok || got != want {
			t.Fatalf("child span attribute %s = %q, ok=%t, want %q", key, got, ok, want)
		}
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

func traceContextPropagator() propagation.TextMapPropagator {
	return propagation.TraceContext{}
}

func TestConsumerProcessBatchWithoutTraceparentUsesRunSpanAsParent(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prevProvider := otel.GetTracerProvider()
	prevPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(traceContextPropagator())
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		otel.SetTextMapPropagator(prevPropagator)
		_ = tp.Shutdown(t.Context())
	})

	consumer := &Consumer{
		config: ConsumerConfig{
			Stream:         "ENSEMBLE_TAP_TEST",
			Durable:        "cerebro_trace_test",
			HandlerWorkers: 1,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		handler: func(context.Context, CloudEvent) error {
			return nil
		},
	}

	event := testConsumerEvent("customer:a", 1, true)
	event.TraceParent = ""
	runCtx, runSpan := otel.Tracer("cerebro.events").Start(context.Background(), "cerebro.event.run")
	consumer.processBatch(runCtx, []consumerPipelineMessage{
		testConsumerPipelineMessage(t, 0, event, nil),
	})
	runSpan.End()

	spans := exporter.GetSpans()
	run := testConsumerSpanByName(t, spans, "cerebro.event.run")
	decode := testConsumerSpanByName(t, spans, "cerebro.event.decode")
	ingest := testConsumerSpanByName(t, spans, "cerebro.event.ingest")
	if decode.Parent.SpanID() != run.SpanContext.SpanID() {
		t.Fatalf("decode span parent = %s, want run span %s", decode.Parent.SpanID().String(), run.SpanContext.SpanID().String())
	}
	if ingest.Parent.SpanID() != decode.SpanContext.SpanID() {
		t.Fatalf("ingest span parent = %s, want decode span %s", ingest.Parent.SpanID().String(), decode.SpanContext.SpanID().String())
	}
}

func testConsumerSpanByName(t *testing.T, spans []tracetest.SpanStub, name string) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if span.Name == name {
			return span
		}
	}
	t.Fatalf("span %q not found in %#v", name, spans)
	return tracetest.SpanStub{}
}

func testConsumerSpanAttribute(span tracetest.SpanStub, key string) (string, bool) {
	for _, attr := range span.Attributes {
		if string(attr.Key) == key {
			return attr.Value.AsString(), true
		}
	}
	return "", false
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

func equalIntSlices(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func testConsumerEvent(entityID string, seq int, includeEntity bool) CloudEvent {
	event := CloudEvent{
		SpecVersion: cloudEventSpecVersion,
		ID:          "evt-" + strings.ReplaceAll(entityID, ":", "-") + "-" + strings.TrimSpace(time.Unix(int64(seq), 0).UTC().Format("150405")),
		Source:      "urn:cerebro:test",
		Type:        "ensemble.tap.test",
		Time:        time.Now().UTC(),
		DataSchema:  "urn:cerebro:events:test",
		TenantID:    "tenant-a",
		Data: map[string]any{
			"seq": seq,
		},
	}
	if includeEntity {
		event.Data["entity_id"] = entityID
	}
	return event
}

func testConsumerPipelineMessage(t *testing.T, index int, event CloudEvent, ack func() error) consumerPipelineMessage {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal pipeline event: %v", err)
	}
	if ack == nil {
		ack = func() error { return nil }
	}
	return consumerPipelineMessage{
		index:   index,
		subject: "ensemble.tap.test",
		payload: payload,
		ack:     ack,
		nak:     func() error { return nil },
	}
}

package events

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestReplayJetStreamHistoryFromSequenceIntegration(t *testing.T) {
	natsURL := startJetStreamServer(t)
	js := mustJetStreamContext(t, natsURL)
	mustAddReplayStream(t, js, "REPLAY_TEST_SEQ", "ensemble.tap.replay.seq.>")

	mustPublishReplayEvent(t, js, "ensemble.tap.replay.seq.event", CloudEvent{ID: "evt-1", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})
	mustPublishReplayEvent(t, js, "ensemble.tap.replay.seq.event", CloudEvent{ID: "evt-2", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})
	mustPublishReplayEvent(t, js, "ensemble.tap.replay.seq.event", CloudEvent{ID: "evt-3", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})

	var ids []string
	report, err := ReplayJetStreamHistory(context.Background(), ReplayConfig{
		URLs:         []string{natsURL},
		Stream:       "REPLAY_TEST_SEQ",
		Subject:      "ensemble.tap.replay.seq.>",
		FromSequence: 2,
		BatchSize:    2,
		FetchTimeout: 100 * time.Millisecond,
	}, func(_ context.Context, evt ReplayEvent) error {
		ids = append(ids, evt.CloudEvent.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("ReplayJetStreamHistory failed: %v", err)
	}

	if got := len(ids); got != 2 {
		t.Fatalf("expected 2 replayed ids, got %d (%v)", got, ids)
	}
	if ids[0] != "evt-2" || ids[1] != "evt-3" {
		t.Fatalf("unexpected replay order: %v", ids)
	}
	if report.StartSequence != 2 {
		t.Fatalf("expected start sequence 2, got %d", report.StartSequence)
	}
	if report.UpperBoundSequence != 3 {
		t.Fatalf("expected upper bound sequence 3, got %d", report.UpperBoundSequence)
	}
	if report.EventsHandled != 2 {
		t.Fatalf("expected 2 handled events, got %d", report.EventsHandled)
	}
}

func TestReplayJetStreamHistoryFromTimeIntegration(t *testing.T) {
	natsURL := startJetStreamServer(t)
	js := mustJetStreamContext(t, natsURL)
	mustAddReplayStream(t, js, "REPLAY_TEST_TIME", "ensemble.tap.replay.time.>")

	mustPublishReplayEvent(t, js, "ensemble.tap.replay.time.event", CloudEvent{ID: "evt-before", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})
	time.Sleep(25 * time.Millisecond)
	startAt := time.Now().UTC()
	time.Sleep(25 * time.Millisecond)
	mustPublishReplayEvent(t, js, "ensemble.tap.replay.time.event", CloudEvent{ID: "evt-after", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})

	var ids []string
	report, err := ReplayJetStreamHistory(context.Background(), ReplayConfig{
		URLs:         []string{natsURL},
		Stream:       "REPLAY_TEST_TIME",
		Subject:      "ensemble.tap.replay.time.>",
		FromTime:     &startAt,
		BatchSize:    1,
		FetchTimeout: 100 * time.Millisecond,
	}, func(_ context.Context, evt ReplayEvent) error {
		ids = append(ids, evt.CloudEvent.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("ReplayJetStreamHistory failed: %v", err)
	}
	if got := len(ids); got != 1 || ids[0] != "evt-after" {
		t.Fatalf("expected only post-time event, got %v", ids)
	}
	if report.EventsHandled != 1 {
		t.Fatalf("expected 1 handled event, got %d", report.EventsHandled)
	}
}

func TestReplayJetStreamHistoryStopsAtInitialUpperBound(t *testing.T) {
	natsURL := startJetStreamServer(t)
	js := mustJetStreamContext(t, natsURL)
	mustAddReplayStream(t, js, "REPLAY_TEST_BOUND", "ensemble.tap.replay.bound.>")

	mustPublishReplayEvent(t, js, "ensemble.tap.replay.bound.event", CloudEvent{ID: "evt-1", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})
	mustPublishReplayEvent(t, js, "ensemble.tap.replay.bound.event", CloudEvent{ID: "evt-2", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})

	var ids []string
	report, err := ReplayJetStreamHistory(context.Background(), ReplayConfig{
		URLs:         []string{natsURL},
		Stream:       "REPLAY_TEST_BOUND",
		Subject:      "ensemble.tap.replay.bound.>",
		FromSequence: 1,
		BatchSize:    1,
		FetchTimeout: 100 * time.Millisecond,
	}, func(_ context.Context, evt ReplayEvent) error {
		ids = append(ids, evt.CloudEvent.ID)
		if evt.CloudEvent.ID == "evt-1" {
			mustPublishReplayEvent(t, js, "ensemble.tap.replay.bound.event", CloudEvent{ID: "evt-3", Type: "ensemble.tap.replay.test", Source: "urn:test", Time: time.Now().UTC(), DataSchema: "urn:test:schema"})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ReplayJetStreamHistory failed: %v", err)
	}
	if got := len(ids); got != 2 {
		t.Fatalf("expected 2 bounded replay events, got %d (%v)", got, ids)
	}
	if ids[0] != "evt-1" || ids[1] != "evt-2" {
		t.Fatalf("unexpected replay order: %v", ids)
	}
	if !report.StoppedByUpperBound {
		t.Fatalf("expected replay to stop at initial upper bound, got %#v", report)
	}
	if report.UpperBoundSequence != 2 {
		t.Fatalf("expected initial upper bound 2, got %d", report.UpperBoundSequence)
	}
}

func mustJetStreamContext(t *testing.T, natsURL string) nats.JetStreamContext {
	t.Helper()
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	return js
}

func mustAddReplayStream(t *testing.T, js nats.JetStreamContext, stream, subject string) {
	t.Helper()
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      stream,
		Subjects:  []string{subject},
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		Replicas:  1,
	}); err != nil {
		t.Fatalf("add replay stream %s: %v", stream, err)
	}
}

func mustPublishReplayEvent(t *testing.T, js nats.JetStreamContext, subject string, evt CloudEvent) {
	t.Helper()
	evt.SpecVersion = cloudEventSpecVersion
	if evt.DataSchema == "" {
		evt.DataSchema = "urn:test:schema"
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal replay event: %v", err)
	}
	if _, err := js.Publish(subject, payload); err != nil {
		t.Fatalf("publish replay event: %v", err)
	}
}

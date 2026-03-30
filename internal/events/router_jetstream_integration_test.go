package events

import (
	"bytes"
	"context"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestNATSAlertNotifierIntegrationUpdatesExistingStreamSubjects(t *testing.T) {
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
	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST_ALERTS",
		Subjects:  []string{"cerebro.events.>"},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
	}); err != nil {
		t.Fatalf("add stream: %v", err)
	}

	notifier, err := NewNATSAlertNotifier(AlertNotifierConfig{
		URLs:          []string{natsURL},
		Stream:        "TEST_ALERTS",
		SubjectPrefix: "ensemble.notify",
	}, nil)
	if err != nil {
		t.Fatalf("new notifier: %v", err)
	}
	defer func() { _ = notifier.Close() }()

	info, err := js.StreamInfo("TEST_ALERTS")
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if !streamHasSubject(info.Config.Subjects, "cerebro.events.>") {
		t.Fatalf("expected original stream subject to be preserved, got %v", info.Config.Subjects)
	}
	if !streamHasSubject(info.Config.Subjects, "ensemble.notify.>") {
		t.Fatalf("expected alert stream subject to be added, got %v", info.Config.Subjects)
	}
}

func TestNATSAlertNotifierIntegrationPublishesAlertsToJetStream(t *testing.T) {
	natsURL := startJetStreamServer(t)

	notifier, err := NewNATSAlertNotifier(AlertNotifierConfig{
		URLs:          []string{natsURL},
		Stream:        "TEST_ALERTS",
		SubjectPrefix: "ensemble.notify",
	}, nil)
	if err != nil {
		t.Fatalf("new notifier: %v", err)
	}
	defer func() { _ = notifier.Close() }()

	payload := []byte(`{"alert":"test"}`)
	if err := notifier.Send(context.Background(), "ensemble.notify.dm", payload); err != nil {
		t.Fatalf("send: %v", err)
	}

	info, err := notifier.js.StreamInfo("TEST_ALERTS")
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("expected 1 alert message, got %d", info.State.Msgs)
	}

	rawMessage, err := notifier.js.GetMsg("TEST_ALERTS", 1)
	if err != nil {
		t.Fatalf("get stream message: %v", err)
	}
	if rawMessage.Subject != "ensemble.notify.dm" {
		t.Fatalf("expected alert subject ensemble.notify.dm, got %s", rawMessage.Subject)
	}
	if !bytes.Equal(rawMessage.Data, payload) {
		t.Fatalf("expected alert payload %q, got %q", payload, rawMessage.Data)
	}
}

func TestNATSAlertNotifierIntegrationNormalizesSubjectPrefix(t *testing.T) {
	natsURL := startJetStreamServer(t)

	notifier, err := NewNATSAlertNotifier(AlertNotifierConfig{
		URLs:          []string{natsURL},
		Stream:        "TEST_ALERTS",
		SubjectPrefix: ".ensemble.notify.",
	}, nil)
	if err != nil {
		t.Fatalf("new notifier: %v", err)
	}
	defer func() { _ = notifier.Close() }()

	if notifier.subjectPrefix != "ensemble.notify" {
		t.Fatalf("expected normalized subject prefix, got %q", notifier.subjectPrefix)
	}

	info, err := notifier.js.StreamInfo("TEST_ALERTS")
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if !streamHasSubject(info.Config.Subjects, "ensemble.notify.>") {
		t.Fatalf("expected normalized stream subject, got %v", info.Config.Subjects)
	}
	if streamHasSubject(info.Config.Subjects, ".ensemble.notify.>") || streamHasSubject(info.Config.Subjects, "ensemble.notify..>") {
		t.Fatalf("expected only normalized stream subjects, got %v", info.Config.Subjects)
	}
}

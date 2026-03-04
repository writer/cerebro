package events

import (
	"testing"
	"time"

	"github.com/writerinternal/cerebro/internal/webhooks"
)

func TestCloudEventFromWebhook(t *testing.T) {
	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventFindingCreated,
		Timestamp: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"finding_id": "f-1",
		},
	}

	ce := cloudEventFromWebhook("cerebro", event)

	if ce.SpecVersion != "1.0" {
		t.Fatalf("expected specversion 1.0, got %s", ce.SpecVersion)
	}
	if ce.ID != "evt-1" {
		t.Fatalf("expected id evt-1, got %s", ce.ID)
	}
	if ce.Type != string(webhooks.EventFindingCreated) {
		t.Fatalf("expected type %s, got %s", webhooks.EventFindingCreated, ce.Type)
	}
	if ce.Source != "cerebro" {
		t.Fatalf("expected source cerebro, got %s", ce.Source)
	}
	if ce.Data["finding_id"] != "f-1" {
		t.Fatalf("expected finding_id f-1, got %#v", ce.Data["finding_id"])
	}
}

func TestSubjectFor(t *testing.T) {
	publisher := &Publisher{config: JetStreamConfig{SubjectPrefix: "cerebro.events"}}

	subject := publisher.subjectFor(webhooks.EventScanCompleted)
	if subject != "cerebro.events.scan.completed" {
		t.Fatalf("unexpected subject: %s", subject)
	}
}

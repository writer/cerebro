package events

import (
	"regexp"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/writerinternal/cerebro/internal/webhooks"
)

func TestCloudEventFromWebhook(t *testing.T) {
	event := webhooks.Event{
		ID:        "evt-1",
		Type:      webhooks.EventFindingCreated,
		Timestamp: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
		Data: map[string]interface{}{
			"finding_id":  "f-1",
			"tenant_id":   "tenant-1",
			"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
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
	if ce.SchemaVersion != cloudEventSchemaV1 {
		t.Fatalf("expected schema version %s, got %s", cloudEventSchemaV1, ce.SchemaVersion)
	}
	if ce.DataSchema == "" {
		t.Fatal("expected dataschema to be set")
	}
	if ce.TenantID != "tenant-1" {
		t.Fatalf("expected tenant id tenant-1, got %s", ce.TenantID)
	}
	if ce.TraceParent != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("unexpected traceparent: %s", ce.TraceParent)
	}
	if ce.Data["finding_id"] != "f-1" {
		t.Fatalf("expected finding_id f-1, got %#v", ce.Data["finding_id"])
	}
}

func TestCloudEventFromWebhook_DefaultExtensions(t *testing.T) {
	event := webhooks.Event{
		Type:      webhooks.EventScanCompleted,
		Timestamp: time.Now().UTC(),
	}

	ce := cloudEventFromWebhook("", event)
	if ce.Source != defaultJetStreamSource {
		t.Fatalf("expected default source %s, got %s", defaultJetStreamSource, ce.Source)
	}
	if ce.TenantID != "unknown" {
		t.Fatalf("expected tenant_id unknown, got %s", ce.TenantID)
	}
	if ce.TraceParent == "" {
		t.Fatal("expected generated traceparent")
	}
	if matched := regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`).MatchString(ce.TraceParent); !matched {
		t.Fatalf("invalid traceparent format: %s", ce.TraceParent)
	}
}

func TestSubjectFor(t *testing.T) {
	publisher := &Publisher{config: JetStreamConfig{SubjectPrefix: "cerebro.events"}}

	subject := publisher.subjectFor(webhooks.EventScanCompleted)
	if subject != "cerebro.events.scan.completed" {
		t.Fatalf("unexpected subject: %s", subject)
	}
}

func TestJetStreamConfigValidateTLSPair(t *testing.T) {
	cfg := JetStreamConfig{
		URLs:        []string{"nats://127.0.0.1:4222"},
		TLSCertFile: "/tmp/client.crt",
	}
	cfg = cfg.withDefaults()

	if err := cfg.validate(); err == nil {
		t.Fatal("expected tls validation error")
	}
}

func TestJetStreamConfigNKeyAuthOption(t *testing.T) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create user nkey: %v", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := JetStreamConfig{
		URLs:     []string{"nats://127.0.0.1:4222"},
		AuthMode: authModeNKey,
		NKeySeed: string(seed),
	}
	cfg = cfg.withDefaults()

	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := cfg.natsOptions(); err != nil {
		t.Fatalf("nats options: %v", err)
	}

	cfg.NKeySeed = "invalid-seed"
	if _, err := cfg.natsOptions(); err == nil {
		t.Fatal("expected nats options error for invalid nkey seed")
	}
}

func TestJetStreamConfigValidateBackpressureThresholds(t *testing.T) {
	cfg := JetStreamConfig{
		URLs:                  []string{"nats://127.0.0.1:4222"},
		OutboxWarnPercent:     95,
		OutboxCriticalPercent: 90,
	}
	cfg = cfg.withDefaults()

	if err := cfg.validate(); err == nil {
		t.Fatal("expected validate to fail when warn percent exceeds critical percent")
	}
}

func TestJetStreamConfigEvaluateOutboxBackpressure(t *testing.T) {
	cfg := JetStreamConfig{
		OutboxMaxRecords:      100,
		OutboxWarnPercent:     70,
		OutboxCriticalPercent: 90,
		OutboxWarnAge:         time.Minute,
		OutboxCriticalAge:     2 * time.Minute,
	}.withDefaults()

	state := cfg.evaluateOutboxBackpressure(outboxStats{Depth: 20, OldestAge: 10 * time.Second})
	if state.Level != backpressureLevelNormal {
		t.Fatalf("expected normal backpressure, got %s", state.Level)
	}

	state = cfg.evaluateOutboxBackpressure(outboxStats{Depth: 75, OldestAge: 10 * time.Second})
	if state.Level != backpressureLevelWarning {
		t.Fatalf("expected warning backpressure, got %s", state.Level)
	}
	if state.Reason == "" {
		t.Fatal("expected warning reason")
	}

	state = cfg.evaluateOutboxBackpressure(outboxStats{Depth: 20, OldestAge: 3 * time.Minute})
	if state.Level != backpressureLevelCritical {
		t.Fatalf("expected critical backpressure from age, got %s", state.Level)
	}
	if state.Reason == "" {
		t.Fatal("expected critical reason")
	}
}

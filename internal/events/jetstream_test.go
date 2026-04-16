package events

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"go.opentelemetry.io/otel/trace"

	"github.com/writer/cerebro/internal/webhooks"
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

	ce := cloudEventFromWebhook(context.Background(), "cerebro", event)

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

	ce := cloudEventFromWebhook(context.Background(), "", event)
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

func TestCloudEventFromWebhook_UsesTraceparentFromContext(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("parse trace id: %v", err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatalf("parse span id: %v", err)
	}
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), spanCtx)

	ce := cloudEventFromWebhook(ctx, "cerebro", webhooks.Event{
		ID:        "evt-ctx",
		Type:      webhooks.EventFindingCreated,
		Timestamp: time.Now().UTC(),
		Data:      map[string]interface{}{"finding_id": "f-ctx"},
	})

	if ce.TraceParent == "" {
		t.Fatal("expected traceparent to be populated from context")
	}
	if !strings.Contains(ce.TraceParent, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Fatalf("expected context trace id in traceparent, got %s", ce.TraceParent)
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
		return
	}
}

func TestJetStreamConfigRejectsInsecureTLSWithoutOverride(t *testing.T) {
	cfg := JetStreamConfig{
		URLs:                  []string{"tls://127.0.0.1:4222"},
		TLSEnabled:            true,
		TLSInsecureSkipVerify: true,
	}.withDefaults()

	if _, err := cfg.NATSOptions(); err == nil {
		t.Fatal("expected insecure TLS override error")
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
		return
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
		return
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

func TestPublishQueuesImmediatelyWhenDisconnected(t *testing.T) {
	outboxPath := filepath.Join(t.TempDir(), "outbox.jsonl")
	cfg := JetStreamConfig{
		Stream:                "TEST_EVENTS",
		SubjectPrefix:         "cerebro.events",
		OutboxPath:            outboxPath,
		OutboxDLQPath:         outboxPath + ".dlq.jsonl",
		OutboxMaxRecords:      10,
		OutboxWarnPercent:     70,
		OutboxCriticalPercent: 90,
		OutboxWarnAge:         time.Minute,
		OutboxCriticalAge:     2 * time.Minute,
	}.withDefaults()

	publisher := &Publisher{
		logger: slog.Default(),
		config: cfg,
		outbox: newFileOutbox(cfg.OutboxPath, outboxConfig{
			MaxRecords:  cfg.OutboxMaxRecords,
			MaxAge:      cfg.OutboxMaxAge,
			MaxAttempts: cfg.OutboxMaxAttempts,
			DLQPath:     cfg.OutboxDLQPath,
		}),
	}

	start := time.Now()
	err := publisher.Publish(context.Background(), webhooks.Event{
		Type:      webhooks.EventRuntimeIngested,
		Timestamp: time.Now().UTC(),
		Data: map[string]interface{}{
			"source": "dogfood",
		},
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if duration > time.Second {
		t.Fatalf("expected fast outbox fallback when disconnected, took %s", duration)
	}

	stats, err := publisher.outbox.stats()
	if err != nil {
		t.Fatalf("outbox stats: %v", err)
	}
	if stats.Depth != 1 {
		t.Fatalf("expected outbox depth 1, got %d", stats.Depth)
	}

	status := publisher.Status(context.Background())
	if ready, ok := status["ready"].(bool); !ok || ready {
		t.Fatalf("expected publisher ready=false while disconnected, got %#v", status["ready"])
	}
}

func TestShouldEnsureJetStreamStream(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "no stream response", err: nats.ErrNoStreamResponse, want: true},
		{name: "stream not found", err: nats.ErrStreamNotFound, want: true},
		{name: "no responders", err: nats.ErrNoResponders, want: true},
		{name: "generic error", err: errors.New("boom"), want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldEnsureJetStreamStream(tt.err); got != tt.want {
				t.Fatalf("shouldEnsureJetStreamStream(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

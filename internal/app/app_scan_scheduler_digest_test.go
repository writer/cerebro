package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/findings"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/policy"
)

func TestInitScheduler_AddsSecurityDigestJob(t *testing.T) {
	app := &App{
		Config: &Config{
			SecurityDigestInterval: "24h",
		},
		Logger: schedulerDigestTestLogger(),
	}

	app.initScheduler(context.Background())

	job, ok := app.Scheduler.GetJob("security-digest")
	if !ok {
		t.Fatal("expected security-digest job to be registered")
	}
	if job.Interval != 24*time.Hour {
		t.Fatalf("expected security-digest interval 24h, got %v", job.Interval)
	}
	if _, ok := app.Scheduler.GetJob("graph-rebuild"); !ok {
		t.Fatal("expected graph-rebuild job to remain registered")
	}
}

func TestInitScheduler_InvalidSecurityDigestIntervalSkipsJob(t *testing.T) {
	app := &App{
		Config: &Config{
			SecurityDigestInterval: "not-a-duration",
		},
		Logger: schedulerDigestTestLogger(),
	}

	app.initScheduler(context.Background())

	if _, ok := app.Scheduler.GetJob("security-digest"); ok {
		t.Fatal("expected security-digest job to be skipped for invalid interval")
	}
}

func TestSendSecurityDigest_SendsSummary(t *testing.T) {
	ctx := context.Background()
	store := findings.NewStore()
	upsert := func(f policy.Finding) {
		store.Upsert(ctx, f)
	}

	upsert(policy.Finding{
		ID:          "finding-critical-1",
		PolicyID:    "policy-critical",
		PolicyName:  "Critical Policy",
		Description: "Critical issue",
		Severity:    "critical",
		Resource:    map[string]interface{}{"id": "resource-critical-1"},
	})
	upsert(policy.Finding{
		ID:          "finding-high-1",
		PolicyID:    "policy-high",
		PolicyName:  "High Policy",
		Description: "High issue",
		Severity:    "high",
		Resource:    map[string]interface{}{"id": "resource-high-1"},
	})
	upsert(policy.Finding{
		ID:          "finding-medium-1",
		PolicyID:    "policy-medium",
		PolicyName:  "Medium Policy",
		Description: "Medium issue",
		Severity:    "medium",
		Resource:    map[string]interface{}{"id": "resource-medium-1"},
	})
	upsert(policy.Finding{
		ID:          "finding-low-1",
		PolicyID:    "policy-low",
		PolicyName:  "Low Policy",
		Description: "Low issue",
		Severity:    "low",
		Resource:    map[string]interface{}{"id": "resource-low-1"},
	})
	upsert(policy.Finding{
		ID:          "finding-resolved-high",
		PolicyID:    "policy-resolved",
		PolicyName:  "Resolved High Policy",
		Description: "Resolved high issue",
		Severity:    "high",
		Resource:    map[string]interface{}{"id": "resource-resolved-high"},
	})
	if !store.Resolve("finding-resolved-high") {
		t.Fatal("expected resolved test finding to be resolvable")
	}

	capture := &captureNotifier{}
	manager := notifications.NewManager()
	manager.AddNotifier(capture)

	app := &App{
		Findings:      store,
		Notifications: manager,
	}

	if err := app.sendSecurityDigest(ctx); err != nil {
		t.Fatalf("sendSecurityDigest returned error: %v", err)
	}

	if len(capture.events) != 1 {
		t.Fatalf("expected 1 notification event, got %d", len(capture.events))
	}

	event := capture.events[0]
	if event.Type != notifications.EventSecurityDigest {
		t.Fatalf("expected event type %q, got %q", notifications.EventSecurityDigest, event.Type)
	}
	if event.Severity != "info" {
		t.Fatalf("expected severity info, got %q", event.Severity)
	}
	if event.Title != "Scheduled Security Digest" {
		t.Fatalf("expected digest title, got %q", event.Title)
	}
	for _, want := range []string{
		"Open findings: 4",
		"critical: 1",
		"high: 1",
		"medium: 1",
		"low: 1",
		"Top priorities:",
	} {
		if !strings.Contains(event.Message, want) {
			t.Fatalf("expected digest message to contain %q, got %q", want, event.Message)
		}
	}

	openTotal, ok := event.Data["open_total"].(int)
	if !ok || openTotal != 4 {
		t.Fatalf("expected open_total=4, got %#v", event.Data["open_total"])
	}

	highlights, ok := event.Data["highlights"].([]string)
	if !ok {
		t.Fatalf("expected highlights to be []string, got %#v", event.Data["highlights"])
	}
	if len(highlights) != 2 {
		t.Fatalf("expected 2 highlights (critical + high), got %d", len(highlights))
	}
}

func schedulerDigestTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type captureNotifier struct {
	events []notifications.Event
}

func (c *captureNotifier) Send(_ context.Context, event notifications.Event) error {
	c.events = append(c.events, event)
	return nil
}

func (c *captureNotifier) Name() string {
	return "capture"
}

func (c *captureNotifier) Test(_ context.Context) error {
	return nil
}

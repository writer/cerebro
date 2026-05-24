package github

import (
	"context"
	"strings"
	"testing"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	findingrules "github.com/writer/cerebro/internal/findings"
)

func TestAuditAttributesSurfaceM3DurableStateFields(t *testing.T) {
	t.Run("integration installation prefers app id", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "integration_installation.create", map[string]any{
			"installation": map[string]any{
				"app_id": 4242,
				"id":     1111,
			},
		})

		if got := attributes["github_app_id"]; got != "4242" {
			t.Fatalf("github_app_id = %q, want app_id 4242", got)
		}
	})

	t.Run("integration installation falls back to installation id", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "integration_installation.create", map[string]any{
			"installation": map[string]any{
				"id": 1111,
			},
		})

		if got := attributes["github_app_id"]; got != "1111" {
			t.Fatalf("github_app_id = %q, want installation id fallback 1111", got)
		}
	})

	t.Run("secret scanning alert forwards resolution state and comment", func(t *testing.T) {
		attributes := auditEventAttributesForTest(t, "secret_scanning_alert.resolve", map[string]any{
			"secret_scanning_alert": map[string]any{
				"resolution":         "revoked",
				"resolution_comment": "rotated exposed token",
				"state":              "resolved",
			},
		})

		for key, want := range map[string]string{
			"secret_scanning_alert.resolution":         "revoked",
			"secret_scanning_alert.resolution_comment": "rotated exposed token",
			"secret_scanning_alert.state":              "resolved",
		} {
			if got := attributes[key]; got != want {
				t.Fatalf("%s = %q, want %q", key, got, want)
			}
		}
	})
}

func TestSecretScanningAuditEventFeedsFindingRule(t *testing.T) {
	rule, ok := findingrules.Builtin().Get("github-secret-scanning-alert-created")
	if !ok {
		t.Fatal("github-secret-scanning-alert-created rule is not registered")
	}
	counterRule, ok := rule.(findingrules.CounterEventRule)
	if !ok {
		t.Fatal("github-secret-scanning-alert-created rule does not implement CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{
		Id:       "example-github-secret-scanning-audit",
		SourceId: "github",
		TenantId: "writer",
		Config:   map[string]string{"family": "audit"},
	}

	openEvent := secretScanningAuditEventForRuleTest(t, "secret_scanning_alert.create", "open")
	if got := strings.TrimSpace(openEvent.Attributes["state"]); got != "" {
		t.Fatalf("source adapter emitted flat state = %q, want empty", got)
	}
	if got := openEvent.Attributes["secret_scanning_alert.state"]; got != "open" {
		t.Fatalf("source adapter emitted secret_scanning_alert.state = %q, want open", got)
	}
	records, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(source adapter open event) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(source adapter open event) returned %d findings, want 1", len(records))
	}
	openAnchor := counterRule.OpenAnchor(records[0].Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want repo/number anchor", records[0].Attributes)
	}

	for _, tc := range []struct {
		name   string
		action string
		state  string
	}{
		{name: "resolved", action: "secret_scanning_alert.resolve", state: "resolved"},
		{name: "revoked", action: "secret_scanning_alert.revoke", state: "revoked"},
		{name: "false_positive", action: "secret_scanning_alert.false_positive", state: "false_positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closeEvent := secretScanningAuditEventForRuleTest(t, tc.action, tc.state)
			records, err := rule.Evaluate(context.Background(), runtime, closeEvent)
			if err != nil {
				t.Fatalf("Evaluate(source adapter close event) error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(source adapter close event) returned %d findings, want 0", len(records))
			}
			closeAnchor, closes := counterRule.CloseOnEvent(closeEvent)
			if !closes || closeAnchor != openAnchor {
				t.Fatalf("CloseOnEvent(source adapter %s) = (%q, %v), want (%q, true)", tc.name, closeAnchor, closes, openAnchor)
			}
		})
	}
}

func auditEventAttributesForTest(t *testing.T, action string, additionalFields map[string]any) map[string]string {
	t.Helper()

	event, err := auditEvent(settings{owner: "writer"}, &gogithub.AuditEntry{
		Action:           gogithub.String(action),
		DocumentID:       gogithub.String("audit-doc-" + action),
		Timestamp:        &gogithub.Timestamp{Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)},
		AdditionalFields: additionalFields,
	}, auditActorResolution{})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if event.Kind != "github.audit" {
		t.Fatalf("event.Kind = %q, want github.audit", event.Kind)
	}
	return event.Attributes
}

func secretScanningAuditEventForRuleTest(t *testing.T, action string, state string) *cerebrov1.EventEnvelope {
	t.Helper()

	event, err := auditEvent(settings{owner: "writer"}, &gogithub.AuditEntry{
		Action:     gogithub.String(action),
		DocumentID: gogithub.String("audit-doc-" + action + "-" + state),
		Timestamp:  &gogithub.Timestamp{Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)},
		AdditionalFields: map[string]any{
			"number":      12,
			"repo":        "writer/cerebro",
			"secret_type": "github_personal_access_token",
			"secret_scanning_alert": map[string]any{
				"state": state,
			},
		},
	}, auditActorResolution{})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if event.Kind != "github.audit" {
		t.Fatalf("event.Kind = %q, want github.audit", event.Kind)
	}
	return event
}

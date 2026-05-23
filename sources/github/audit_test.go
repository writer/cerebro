package github

import (
	"testing"
	"time"

	gogithub "github.com/google/go-github/v66/github"
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

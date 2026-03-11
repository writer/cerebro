package identity

import (
	"context"
	"testing"
	"time"
)

func TestDetectUnusedAccessKeys_ParsesStringValues(t *testing.T) {
	detector := NewStaleAccessDetector(DefaultThresholds())

	credentials := []map[string]interface{}{
		{
			"arn":                         "arn:aws:iam::123456789012:user/alice",
			"account_id":                  "123456789012",
			"access_key_1_active":         "TRUE",
			"access_key_1_last_used_date": "2000-01-01T00:00:00Z",
		},
	}

	findings := detector.DetectUnusedAccessKeys(context.Background(), credentials)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Type != StaleAccessUnusedAccessKey {
		t.Fatalf("expected type %q, got %q", StaleAccessUnusedAccessKey, findings[0].Type)
	}
	if findings[0].Metadata["key_number"] != 1 {
		t.Fatalf("expected key_number=1, got %#v", findings[0].Metadata["key_number"])
	}
}

func TestDetectUnusedAccessKeys_IgnoresInactiveKey(t *testing.T) {
	detector := NewStaleAccessDetector(DefaultThresholds())

	credentials := []map[string]interface{}{
		{
			"arn":                         "arn:aws:iam::123456789012:user/bob",
			"account_id":                  "123456789012",
			"access_key_1_active":         "false",
			"access_key_1_last_used_date": "2000-01-01T00:00:00Z",
		},
	}

	findings := detector.DetectUnusedAccessKeys(context.Background(), credentials)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestStaleAccessFinding_ToPolicyFinding(t *testing.T) {
	lastSeen := time.Now().Add(-120 * 24 * time.Hour).UTC()
	finding := StaleAccessFinding{
		ID:       "stale-user-arn:aws:iam::123456789012:user/alice",
		Type:     StaleAccessInactiveUser,
		Severity: "HIGH",
		Principal: Principal{
			ID:    "arn:aws:iam::123456789012:user/alice",
			Type:  "user",
			Name:  "alice",
			Email: "alice@example.com",
		},
		Provider:     "aws",
		Account:      "123456789012",
		LastActivity: &lastSeen,
		DaysSince:    120,
		Details:      "User has not logged in for 120 days",
		Remediation:  "Disable account",
		Metadata: map[string]interface{}{
			"key_number": 1,
		},
	}

	policyFinding := finding.ToPolicyFinding()
	if policyFinding.ID != "identity-"+finding.ID {
		t.Fatalf("unexpected finding ID: %s", policyFinding.ID)
	}
	if policyFinding.PolicyID != "identity-stale-inactive-user" {
		t.Fatalf("unexpected policy ID: %s", policyFinding.PolicyID)
	}
	if policyFinding.Severity != "high" {
		t.Fatalf("expected normalized severity high, got %s", policyFinding.Severity)
	}
	if policyFinding.ResourceType != "identity/user" {
		t.Fatalf("expected resource type identity/user, got %s", policyFinding.ResourceType)
	}
	if got := policyFinding.Resource["days_since"]; got != 120 {
		t.Fatalf("expected days_since=120, got %#v", got)
	}
	if got := policyFinding.Resource["last_activity"]; got == "" {
		t.Fatal("expected last_activity to be populated")
	}
}

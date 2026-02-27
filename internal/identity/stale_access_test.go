package identity

import (
	"context"
	"testing"
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

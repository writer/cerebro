package sync

import (
	"testing"
	"time"
)

func TestParseCredentialReportValue(t *testing.T) {
	active, ok := parseCredentialReportValue("access_key_1_active", "true")
	if !ok {
		t.Fatal("expected active value to parse")
	}
	if v, ok := active.(bool); !ok || !v {
		t.Fatalf("expected bool true, got %#v", active)
	}

	timestamp, ok := parseCredentialReportValue("access_key_1_last_used_date", "2025-01-02T03:04:05+00:00")
	if !ok {
		t.Fatal("expected timestamp value to parse")
	}
	if _, ok := timestamp.(time.Time); !ok {
		t.Fatalf("expected time.Time, got %#v", timestamp)
	}

	if _, ok := parseCredentialReportValue("password_last_used", "N/A"); ok {
		t.Fatal("expected N/A value to be ignored")
	}
}

func TestAddCredentialReportDerivedFields(t *testing.T) {
	now := time.Date(2026, time.February, 27, 0, 0, 0, 0, time.UTC)
	lastUsed := now.AddDate(0, 0, -91)

	row := map[string]interface{}{
		"password_last_used":          lastUsed,
		"access_key_1_last_used_date": now.AddDate(0, 0, -15).Format(time.RFC3339),
	}

	addCredentialReportDerivedFields(row, now)

	if row["password_last_used_days"] != 91 {
		t.Fatalf("expected password_last_used_days=91, got %#v", row["password_last_used_days"])
	}
	if row["access_key_1_last_used_days"] != 15 {
		t.Fatalf("expected access_key_1_last_used_days=15, got %#v", row["access_key_1_last_used_days"])
	}
	if _, exists := row["access_key_2_last_used_days"]; exists {
		t.Fatalf("expected access_key_2_last_used_days to be absent, got %#v", row["access_key_2_last_used_days"])
	}
}

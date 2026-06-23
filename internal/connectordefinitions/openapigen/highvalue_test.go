package openapigen

import (
	"strings"
	"testing"
)

func TestSummarizeDescriptionStripsExamples(t *testing.T) {
	raw := "Acme widgets API for managing things.\n\n" +
		"## Auth\nUse a key like this:\n\n```\ncurl -H \"Authorization: Bearer sk_live_0123456789abcdef0123\" https://api.acme.com\n```\n"
	got := summarizeDescription(raw)
	if got != "Acme widgets API for managing things." {
		t.Fatalf("summarizeDescription = %q, want first paragraph only", got)
	}
	if strings.Contains(got, "curl") || strings.Contains(got, "Authorization") || strings.Contains(got, "sk_live") {
		t.Fatalf("summarizeDescription leaked example auth content: %q", got)
	}
}

func TestSummarizeDescriptionCapsLength(t *testing.T) {
	raw := strings.Repeat("word ", 200)
	got := summarizeDescription(raw)
	if len(got) > 405 {
		t.Fatalf("summarizeDescription length = %d, want capped near 400", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
}

func TestIsHighValueSecurityVocabulary(t *testing.T) {
	highValue := []struct{ family, path string }{
		{"credentials", "/v1/credentials"},
		{"audit_logs", "/v1/audit/logs"},
		{"sessions", "/api/sessions"},
		{"certificates", "/v1/certificates"},
	}
	for _, c := range highValue {
		if !isHighValue("", c.family, c.path) {
			t.Errorf("isHighValue(%q,%q) = false, want true (security/GRC vocabulary)", c.family, c.path)
		}
	}
	// Generic business objects must stay low-value so the catalog proof gate is
	// not gamed into accepting connectors with no security/GRC coverage.
	lowValue := []struct{ family, path string }{
		{"invoices", "/v1/invoices"},
		{"payments", "/v1/payments"},
		{"products", "/v1/products"},
	}
	for _, c := range lowValue {
		if isHighValue("", c.family, c.path) {
			t.Errorf("isHighValue(%q,%q) = true, want false (generic business object)", c.family, c.path)
		}
	}
}

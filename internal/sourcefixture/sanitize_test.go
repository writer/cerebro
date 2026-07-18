package sourcefixture

import (
	"strings"
	"testing"
)

func TestSanitizeImportedJSONPreservesShape(t *testing.T) {
	tenantID := "00u" + "1234567890ABCDEFG"
	payload, changed, err := SanitizeImportedJSONWithKeys([]byte(`{"data":[{"email":"person@company.com","firstName":"Alice","name":"Alice's Token","secret":"redacted-value","active":true,"userId":"`+tenantID+`"}]}`), []string{"name"})
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	if strings.Contains(text, "person@company.com") || strings.Contains(text, "Alice") || strings.Contains(text, "redacted-value") || strings.Contains(text, tenantID) || !strings.Contains(text, `"secret": ""`) || !strings.Contains(text, `"active": true`) || !strings.Contains(text, `"userId": "example-`) {
		t.Fatalf("sanitized payload = %s", payload)
	}
	if len(changed) != 5 || changed[0] != "$.data[0].email" || changed[1] != "$.data[0].firstName" || changed[2] != "$.data[0].name" || changed[3] != "$.data[0].secret" || changed[4] != "$.data[0].userId" {
		t.Fatalf("changed fields = %#v", changed)
	}
}

func TestSanitizeImportedJSONReplacesTokenShapedProviderIdentifiers(t *testing.T) {
	payload, changed, err := SanitizeImportedJSON([]byte(`[
		{"id":"00T3kinb0wOUpDUdV5d7","_links":{"self":{"href":"https://example.okta.com/api/v1/api-tokens/00T3kinb0wOUpDUdV5d7"}}},
		{"id":"autl0by7reTh1KIzB5d6"}
	]`))
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	for _, identifier := range []string{"00T3kinb0wOUpDUdV5d7", "autl0by7reTh1KIzB5d6"} {
		if strings.Contains(text, identifier) {
			t.Fatalf("sanitized payload retained provider identifier %q: %s", identifier, payload)
		}
	}
	if len(changed) != 3 {
		t.Fatalf("changed fields = %#v, want 3 provider identifier locations", changed)
	}
}

func TestSanitizeImportedJSONClearsNestedCredentialValues(t *testing.T) {
	payload, changed, err := SanitizeImportedJSON([]byte(`{
		"tokens":["ghp_realtoken123"],
		"secret":{"access_key":"AKIAIOSFODNN7EXAMPLE"},
		"credentials":{"provider":{"type":"oauth2"}}
	}`))
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	for _, secret := range []string{"ghp_realtoken123", "AKIAIOSFODNN7EXAMPLE", "oauth2"} {
		if strings.Contains(text, secret) {
			t.Fatalf("sanitized payload retained credential %q: %s", secret, payload)
		}
	}
	want := []string{"$.credentials.provider.type", "$.secret.access_key", "$.tokens[0]"}
	if len(changed) != len(want) {
		t.Fatalf("changed fields = %#v, want %#v", changed, want)
	}
	for index := range want {
		if changed[index] != want[index] {
			t.Fatalf("changed fields = %#v, want %#v", changed, want)
		}
	}
}

func TestSanitizeImportedJSONRejectsNonStringCredentialLeaves(t *testing.T) {
	if _, _, err := SanitizeImportedJSON([]byte(`{"tokens":[123]}`)); err == nil {
		t.Fatal("SanitizeImportedJSON() error = nil, want manual-sanitization error")
	}
}

func TestSanitizeImportedTextPreservesCommitSHAs(t *testing.T) {
	commit := "00a1234567890abcdef0123456789abcdef01234567"
	if got := SanitizeImportedText(commit); got != commit {
		t.Fatalf("SanitizeImportedText(%q) = %q", commit, got)
	}
	identifier := "00u1234567890ABCDEFG"
	if got := SanitizeImportedText(identifier); got == identifier {
		t.Fatalf("SanitizeImportedText(%q) retained provider identifier", identifier)
	}
}

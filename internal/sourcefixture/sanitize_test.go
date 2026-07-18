package sourcefixture

import (
	"fmt"
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
		{"id":"autl0by7reTh1KIzB5d6"},
		{"user_id":"auth0|6581a1f11c2a8abf544cc91c","url":"https://example.auth0.com/api/v2/users/auth0%7C6581a1f11c2a8abf544cc91c"},
		{"id":"org_5GOvOhO924a08wZJ","url":"https://example.auth0.com/api/v2/organizations/org_5GOvOhO924a08wZJ"}
	]`))
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	for _, identifier := range []string{"00T3kinb0wOUpDUdV5d7", "autl0by7reTh1KIzB5d6", "auth0|6581a1f11c2a8abf544cc91c", "auth0%7C6581a1f11c2a8abf544cc91c", "org_5GOvOhO924a08wZJ"} {
		if strings.Contains(text, identifier) {
			t.Fatalf("sanitized payload retained provider identifier %q: %s", identifier, payload)
		}
	}
	if len(changed) != 7 {
		t.Fatalf("changed fields = %#v, want 7 provider identifier locations", changed)
	}
}

func TestSanitizeImportedJSONClearsNestedCredentialValues(t *testing.T) {
	accessKey := "AKIA" + "IOSFODNN7EXAMPLE"
	payload, changed, err := SanitizeImportedJSON([]byte(fmt.Sprintf(`{
		"tokens":["ghp_realtoken123"],
		"secret":{"access_key":%q},
		"credentials":{"provider":{"type":"oauth2"}}
	}`, accessKey)))
	if err != nil {
		t.Fatalf("SanitizeImportedJSON() error = %v", err)
	}
	text := string(payload)
	for _, secret := range []string{"ghp_realtoken123", accessKey, "oauth2"} {
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
	if _, _, err := SanitizeImportedJSON([]byte(`{"issue_token":0,"secret":false}`)); err != nil {
		t.Fatalf("SanitizeImportedJSON() sanitized typed credentials error = %v", err)
	}
}

func TestSanitizeImportedJSONExplicitKeysPreserveJSONTypes(t *testing.T) {
	payload, changed, err := SanitizeImportedJSONWithKeys([]byte(`{
		"issue_token":73062,
		"target_ids":["34205503"],
		"sensitive":true
	}`), []string{"issue_token", "target_ids", "sensitive"})
	if err != nil {
		t.Fatalf("SanitizeImportedJSONWithKeys() error = %v", err)
	}
	text := string(payload)
	if !strings.Contains(text, `"issue_token": 0`) || !strings.Contains(text, `"target_ids": [`) || !strings.Contains(text, `"example-`) || !strings.Contains(text, `"sensitive": false`) {
		t.Fatalf("sanitized payload = %s", payload)
	}
	want := []string{"$.issue_token", "$.sensitive", "$.target_ids[0]"}
	if len(changed) != len(want) {
		t.Fatalf("changed fields = %#v, want %#v", changed, want)
	}
	for index := range want {
		if changed[index] != want[index] {
			t.Fatalf("changed fields = %#v, want %#v", changed, want)
		}
	}
}

func TestSanitizeImportedTextValuesIsIdempotentForPersonalFields(t *testing.T) {
	payload, changed, err := SanitizeImportedTextValues([]byte(`{
		"email":"user-3a5ab2b2@example.test",
		"ip":"162.159.129.83",
		"url":"https://uat.tf.terraform-provider-auth0.com/client-grant/example"
	}`))
	if err != nil {
		t.Fatalf("SanitizeImportedTextValues() error = %v", err)
	}
	text := string(payload)
	if !strings.Contains(text, `"email": "user-3a5ab2b2@example.test"`) || !strings.Contains(text, `"ip": "203.0.113.`) || !strings.Contains(text, `"url": "https://auth0.example.test/client-grant/example"`) {
		t.Fatalf("sanitized payload = %s", payload)
	}
	want := []string{"$.ip", "$.url"}
	if len(changed) != len(want) || changed[0] != want[0] || changed[1] != want[1] {
		t.Fatalf("changed fields = %#v, want %#v", changed, want)
	}
}

func TestSanitizeImportedTextPreservesCommitSHAs(t *testing.T) {
	commit := "00a" + strings.Repeat("1", 37)
	if got := SanitizeImportedText(commit); got != commit {
		t.Fatalf("SanitizeImportedText(%q) = %q", commit, got)
	}
	identifier := "00u" + "1234567890ABCDEFG"
	if got := SanitizeImportedText(identifier); got == identifier {
		t.Fatalf("SanitizeImportedText(%q) retained provider identifier", identifier)
	}
	tenantURL := "https://tenant-name.zendesk.com/api/v2/users.json"
	if got := SanitizeImportedText(tenantURL); got != "https://zendesk.example.test/api/v2/users.json" {
		t.Fatalf("SanitizeImportedText(%q) = %q", tenantURL, got)
	}
	audienceURL := "https://uat.tf.terraform-provider-auth0.com/client-grant/example"
	if got := SanitizeImportedText(audienceURL); got != "https://auth0.example.test/client-grant/example" {
		t.Fatalf("SanitizeImportedText(%q) = %q", audienceURL, got)
	}
	publicIP := "162.159.129.83"
	if got := SanitizeImportedText(publicIP); got == publicIP || !strings.HasPrefix(got, "203.0.113.") {
		t.Fatalf("SanitizeImportedText(%q) = %q", publicIP, got)
	}
	for _, safeIP := range []string{"10.0.0.1", "127.0.0.1", "192.0.2.25", "198.51.100.25", "203.0.113.25"} {
		if got := SanitizeImportedText(safeIP); got != safeIP {
			t.Fatalf("SanitizeImportedText(%q) = %q", safeIP, got)
		}
	}
}

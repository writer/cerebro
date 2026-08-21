package main

import (
	"os"
	"strings"
	"testing"
)

func TestValidateSanitizedRequestURL(t *testing.T) {
	tests := []struct {
		name      string
		recorded  string
		sanitized string
		wantError bool
	}{
		{
			name:      "query values may change",
			recorded:  "https://api.provider.test/v1/items?account=real",
			sanitized: "https://api.provider.test/v1/items?account=tenant-example",
		},
		{
			name:      "recording host may become an HTTPS example host",
			recorded:  "http://localhost:3000/api/v1/instance/activity",
			sanitized: "https://mastodon.example.test/api/v1/instance/activity",
		},
		{
			name:      "provider identifiers in path segments may become example values",
			recorded:  "https://api.provider.test/v1/accounts/acct-123/items",
			sanitized: "https://api.provider.test/v1/accounts/example-account/items",
		},
		{
			name:      "static route segments must not change",
			recorded:  "http://localhost:3000/api/v1/instance/activity",
			sanitized: "https://mastodon.example.test/api/v2/instance/activity",
			wantError: true,
		},
		{
			name:      "path segment count must not change",
			recorded:  "https://api.provider.test/v1/accounts/acct-123/items",
			sanitized: "https://api.provider.test/v1/accounts/example-account/items/current",
			wantError: true,
		},
		{
			name:      "replacement host must be reserved",
			recorded:  "http://localhost:3000/api/v1/instance/activity",
			sanitized: "https://unrelated.example.com/api/v1/instance/activity",
			wantError: true,
		},
		{
			name:      "replacement scheme must be HTTPS",
			recorded:  "https://api.provider.test/v1/items",
			sanitized: "http://provider.example.test/v1/items",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSanitizedRequestURL(test.recorded, test.sanitized)
			if (err != nil) != test.wantError {
				t.Fatalf("validateSanitizedRequestURL() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestSanitizedCapturePayloadAcceptsStdinWithoutReturningRawValues(t *testing.T) {
	const rawEmail = "operator@company.invalid"
	const rawSecret = "provider-secret-value"
	const rawTenant = "tenant-confidential-name"
	payload, changed, err := sanitizedCapturePayload(strings.NewReader(`{
		"email":"`+rawEmail+`",
		"api_key":"`+rawSecret+`",
		"tenant_name":"`+rawTenant+`",
		"active":true
	}`), []string{"tenant_name"}, nil)
	if err != nil {
		t.Fatalf("sanitizedCapturePayload() error = %v", err)
	}
	for _, raw := range []string{rawEmail, rawSecret, rawTenant} {
		if strings.Contains(string(payload), raw) {
			t.Fatalf("sanitized payload retained raw value %q: %s", raw, payload)
		}
	}
	if !strings.Contains(string(payload), `"active": true`) {
		t.Fatalf("sanitized payload changed response shape: %s", payload)
	}
	if len(changed) != 3 {
		t.Fatalf("changed fields = %#v, want three in-memory redactions", changed)
	}
}

func TestCanonicalRequestDigestAcceptsStdinWithoutEchoingBody(t *testing.T) {
	first, err := canonicalRequestDigest(strings.NewReader(`{"limit":1,"select":["id"]}`))
	if err != nil {
		t.Fatalf("canonicalRequestDigest() error = %v", err)
	}
	second, err := canonicalRequestDigest(strings.NewReader("{\n\"select\":[\"id\"],\"limit\":1\n}"))
	if err != nil {
		t.Fatalf("canonicalRequestDigest() error = %v", err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("digests = %q and %q, want stable SHA-256", first, second)
	}
	if strings.Contains(first, "select") || strings.Contains(first, "limit") {
		t.Fatalf("digest output exposed request body: %q", first)
	}
}

func TestCanonicalRequestDigestFileBindsExactClientBody(t *testing.T) {
	path := t.TempDir() + "/request.json"
	if err := os.WriteFile(path, []byte(`{"limit":100,"select":["id"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := canonicalRequestDigestFile(path)
	if err != nil {
		t.Fatalf("canonicalRequestDigestFile() error = %v", err)
	}
	fromReader, err := canonicalRequestDigest(strings.NewReader(`{"select":["id"],"limit":100}`))
	if err != nil {
		t.Fatalf("canonicalRequestDigest() error = %v", err)
	}
	if fromFile != fromReader {
		t.Fatalf("file digest = %q, want exact client body digest %q", fromFile, fromReader)
	}
}

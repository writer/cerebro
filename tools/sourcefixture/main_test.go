package main

import "testing"

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
			name:      "path must not change",
			recorded:  "http://localhost:3000/api/v1/instance/activity",
			sanitized: "https://mastodon.example.test/api/v2/instance/activity",
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

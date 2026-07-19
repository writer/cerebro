package sourcefixture

import (
	"strings"
	"testing"
)

func TestExtractVCRRecordings(t *testing.T) {
	tests := []struct {
		name       string
		artifact   string
		wantURL    string
		wantTime   string
		wantBasis  string
		wantRecord string
	}{
		{
			name: "go vcr yaml",
			artifact: `interactions:
- request:
    method: GET
    url: https://api.example.test/v2/items
  response:
    body: '{"data":[{"id":"item-1"}]}'
    code: 200
    headers:
      Content-Type: [application/json]
      Date: ['Sat, 18 Jul 2026 12:00:00 GMT']
    status: 200 OK
version: 2
`,
			wantURL:    "https://api.example.test/v2/items",
			wantTime:   "2026-07-18T12:00:00Z",
			wantBasis:  "response_header",
			wantRecord: "item-1",
		},
		{
			name:       "ruby vcr json",
			artifact:   `{"http_interactions":[{"request":{"method":"get","uri":"https://api.example.test/v1/events"},"response":{"status":{"code":200},"headers":{"Content-Type":["application/json"]},"body":{"base64_string":"W3siaWQiOiJldmVudC0xIn1d"},"recorded_at":"Sat, 18 Jul 2026 13:00:00 GMT"}}]}`,
			wantURL:    "https://api.example.test/v1/events",
			wantTime:   "2026-07-18T13:00:00Z",
			wantBasis:  "recorded_at",
			wantRecord: "event-1",
		},
		{
			name: "pytest recording yaml",
			artifact: `interactions:
- request:
    method: GET
    uri: https://api.example.test/v1/models
  response:
    content: '{"results":[{"name":"model-1"}]}'
    headers:
      Content-Type: [application/json]
      Date: ['Sat, 18 Jul 2026 14:00:00 GMT']
    status_code: 200
version: 1
`,
			wantURL:    "https://api.example.test/v1/models",
			wantTime:   "2026-07-18T14:00:00Z",
			wantBasis:  "response_header",
			wantRecord: "model-1",
		},
		{
			name:       "exvcr json interaction array",
			artifact:   `[{"request":{"method":"get","url":"https://api.example.test/v1/lists"},"response":{"body":"{\"lists\":[{\"id\":\"list-1\"}]}","headers":{"Content-Type":"application/json","Date":"Sat, 18 Jul 2026 15:00:00 GMT"},"status_code":200}}]`,
			wantURL:    "https://api.example.test/v1/lists",
			wantTime:   "2026-07-18T15:00:00Z",
			wantBasis:  "response_header",
			wantRecord: "list-1",
		},
		{
			name: "ruby vcr yaml binary body",
			artifact: `http_interactions:
- request:
    method: GET
    uri: https://api.example.test/v1/binary-items
  response:
    status:
      code: 200
    headers:
      Content-Type: [application/json]
      Date: ['Sat, 18 Jul 2026 16:00:00 GMT']
    body:
      string: !!binary eyJpdGVtcyI6W3siaWQiOiJiaW5hcnktMSJ9XX0=
recorded_with: VCR
`,
			wantURL:    "https://api.example.test/v1/binary-items",
			wantTime:   "2026-07-18T16:00:00Z",
			wantBasis:  "response_header",
			wantRecord: "binary-1",
		},
		{
			name: "ruby vcr yaml custom binary body",
			artifact: `http_interactions:
- request:
    method: GET
    uri: https://api.example.test/v1/custom-binary-items
  response:
    status:
      code: 200
    headers:
      Content-Type: [application/json]
      Date: ['Sat, 18 Jul 2026 17:00:00 GMT']
    body:
      string: !binary eyJpdGVtcyI6W3siaWQiOiJjdXN0b20tYmluYXJ5LTEifV19
recorded_with: VCR
`,
			wantURL:    "https://api.example.test/v1/custom-binary-items",
			wantTime:   "2026-07-18T17:00:00Z",
			wantBasis:  "response_header",
			wantRecord: "custom-binary-1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interaction, err := ExtractRecording([]byte(test.artifact), RecordingFormatVCR, 0)
			if err != nil {
				t.Fatalf("ExtractRecording() error = %v", err)
			}
			if interaction.Request.Method != "GET" || interaction.Request.URL != test.wantURL || interaction.Status != 200 {
				t.Fatalf("interaction request/status = %#v/%d", interaction.Request, interaction.Status)
			}
			if interaction.CapturedAt != test.wantTime || interaction.CaptureTimeBasis != test.wantBasis {
				t.Fatalf("interaction capture = %q/%q", interaction.CapturedAt, interaction.CaptureTimeBasis)
			}
			if !strings.Contains(string(interaction.Payload), test.wantRecord) {
				t.Fatalf("interaction payload = %q", interaction.Payload)
			}
		})
	}
}

func TestExtractPyGitHubRecording(t *testing.T) {
	artifact := `https
GET
api.github.com
None
/orgs/example/secret-scanning/alerts
{'Authorization': 'token private_token_removed'}
None
200
[('Date', 'Sat, 18 Jul 2026 14:00:00 GMT'), ('Content-Type', 'application/json; charset=utf-8')]
[{"number":1,"state":"open"}]
`
	interaction, err := ExtractRecording([]byte(artifact), RecordingFormatPyGitHub, 0)
	if err != nil {
		t.Fatalf("ExtractRecording() error = %v", err)
	}
	if interaction.Request.URL != "https://api.github.com/orgs/example/secret-scanning/alerts" || interaction.Status != 200 {
		t.Fatalf("interaction = %#v", interaction)
	}
	if interaction.CapturedAt != "2026-07-18T14:00:00Z" || interaction.CaptureTimeBasis != "response_header" {
		t.Fatalf("interaction capture = %q/%q", interaction.CapturedAt, interaction.CaptureTimeBasis)
	}
}

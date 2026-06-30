package google_gemini

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

type geminiRuntimeFamily struct {
	family        string
	path          string
	listKey       string
	firstRecord   map[string]any
	secondRecord  map[string]any
	wantFirstID   string
	wantFirstName string
}

func TestSourceCheckAndReadRuntimeFamiliesUseGeminiShapes(t *testing.T) {
	for _, tc := range geminiRuntimeFamilies() {
		t.Run(tc.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			nextPageToken := "token-" + tc.family + "-page-2"
			continuationRequests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get(tokenHeader); got != "test-key" {
					t.Fatalf("%s = %q, want test-key", tokenHeader, got)
				}
				if r.URL.Path == defaultHealthPath && strings.TrimSpace(r.URL.Query().Get("pageSize")) == "" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{}})
					return
				}
				if r.URL.Path != tc.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tc.path)
				}
				if got := strings.TrimSpace(r.URL.Query().Get("pageSize")); got == "" {
					t.Fatalf("pageSize query param is empty for %s", tc.family)
				}
				w.Header().Set("Content-Type", "application/json")

				switch pageToken := r.URL.Query().Get("pageToken"); pageToken {
				case "":
					_ = json.NewEncoder(w).Encode(geminiListResponse(tc.listKey, []map[string]any{tc.firstRecord}, nextPageToken))
				case nextPageToken:
					continuationRequests++
					_ = json.NewEncoder(w).Encode(geminiListResponse(tc.listKey, []map[string]any{tc.secondRecord}, ""))
				default:
					t.Fatalf("pageToken = %q, want %q", pageToken, nextPageToken)
				}
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"family":    tc.family,
				"api_key":   "test-key",
				"per_page":  "2",
			})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			first, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read(first) error = %v", err)
			}
			assertGeminiEvent(t, first, tc, tc.wantFirstID, tc.wantFirstName)
			if first.NextCursor.GetOpaque() != nextPageToken {
				t.Fatalf("first NextCursor = %q, want %q", first.NextCursor.GetOpaque(), nextPageToken)
			}

			second, err := source.Read(context.Background(), cfg, first.NextCursor)
			if err != nil {
				t.Fatalf("Read(second) error = %v", err)
			}
			assertGeminiEvent(t, second, tc, valueStringForTest(tc.secondRecord["name"]), valueStringForTest(tc.secondRecord["displayName"]))
			if second.NextCursor != nil {
				t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
			}
			if continuationRequests != 1 {
				t.Fatalf("continuation requests = %d, want 1", continuationRequests)
			}
		})
	}
}

func TestSourceReadRequiresGeminiAPIKey(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"family":    defaultFamily,
	}), nil)
	if err == nil || !strings.Contains(err.Error(), "api_key is required") {
		t.Fatalf("Read() error = %v, want api_key required", err)
	}
}

func assertGeminiEvent(t *testing.T, pull sourcecdk.Pull, tc geminiRuntimeFamily, wantID string, wantName string) {
	t.Helper()
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "google_gemini."+tc.family {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got := valueStringForTest(payload["name"]); got != wantID {
		t.Fatalf("payload.name = %q, want %q", got, wantID)
	}
	switch tc.family {
	case familyModelCatalog, familyFiles, familyCachedContents:
		if got := event.Attributes["resource_id"]; got != wantID {
			t.Fatalf("resource_id = %q, want %q", got, wantID)
		}
		if got := event.Attributes["resource_type"]; got != tc.family {
			t.Fatalf("resource_type = %q, want %q", got, tc.family)
		}
	case familyTunedModels, familyBatchJobs:
		if got := event.Attributes["deployment_id"]; got != wantID {
			t.Fatalf("deployment_id = %q, want %q", got, wantID)
		}
		if got := event.Attributes["deployment_name"]; got == "" {
			t.Fatalf("deployment_name is empty for %s", tc.family)
		}
	}
	if wantName != "" && event.Attributes["resource_name"] == "" && event.Attributes["deployment_name"] == "" {
		t.Fatalf("resource or deployment name is empty; want record name %q", wantName)
	}
}

func geminiListResponse(listKey string, records []map[string]any, nextPageToken string) map[string]any {
	response := map[string]any{listKey: records}
	if nextPageToken != "" {
		response["nextPageToken"] = nextPageToken
	}
	return response
}

func geminiRuntimeFamilies() []geminiRuntimeFamily {
	return []geminiRuntimeFamily{
		{
			family:  familyModelCatalog,
			path:    "/v1beta/models",
			listKey: "models",
			firstRecord: map[string]any{
				"name":                       "models/gemini-2.5-pro",
				"version":                    "2.5",
				"displayName":                "Gemini 2.5 Pro",
				"description":                "Sanitized Gemini model catalog entry.",
				"inputTokenLimit":            float64(1048576),
				"outputTokenLimit":           float64(65536),
				"supportedGenerationMethods": []any{"generateContent", "countTokens"},
				"temperature":                float64(1),
				"topP":                       float64(0.95),
				"topK":                       float64(64),
			},
			secondRecord: map[string]any{
				"name":                       "models/gemini-2.5-flash",
				"version":                    "2.5",
				"displayName":                "Gemini 2.5 Flash",
				"description":                "Sanitized Gemini model catalog entry.",
				"inputTokenLimit":            float64(1048576),
				"outputTokenLimit":           float64(65536),
				"supportedGenerationMethods": []any{"generateContent", "countTokens"},
			},
			wantFirstID:   "models/gemini-2.5-pro",
			wantFirstName: "Gemini 2.5 Pro",
		},
		{
			family:  familyFiles,
			path:    "/v1beta/files",
			listKey: "files",
			firstRecord: map[string]any{
				"name":           "files/abc123",
				"displayName":    "prompt-context.pdf",
				"mimeType":       "application/pdf",
				"sizeBytes":      "12345",
				"createTime":     "2026-06-01T00:00:00Z",
				"updateTime":     "2026-06-01T00:05:00Z",
				"expirationTime": "2026-06-03T00:00:00Z",
				"sha256Hash":     "MDEyMzQ1Njc4OWFiY2RlZg==",
				"uri":            "https://generativelanguage.googleapis.com/v1beta/files/abc123",
				"state":          "ACTIVE",
				"source":         "UPLOADED",
			},
			secondRecord: map[string]any{
				"name":        "files/def456",
				"displayName": "training-notes.txt",
				"mimeType":    "text/plain",
				"sizeBytes":   "23456",
				"createTime":  "2026-06-01T01:00:00Z",
				"updateTime":  "2026-06-01T01:05:00Z",
				"state":       "ACTIVE",
				"source":      "UPLOADED",
			},
			wantFirstID:   "files/abc123",
			wantFirstName: "prompt-context.pdf",
		},
		{
			family:  familyCachedContents,
			path:    "/v1beta/cachedContents",
			listKey: "cachedContents",
			firstRecord: map[string]any{
				"name":              "cachedContents/cache-001",
				"model":             "models/gemini-2.5-pro",
				"displayName":       "support-policy-context",
				"createTime":        "2026-06-01T00:00:00Z",
				"updateTime":        "2026-06-01T00:05:00Z",
				"expireTime":        "2026-06-02T00:00:00Z",
				"usageMetadata":     map[string]any{"totalTokenCount": float64(1536)},
				"systemInstruction": map[string]any{"parts": []any{map[string]any{"text": "Use the current support policy."}}},
			},
			secondRecord: map[string]any{
				"name":          "cachedContents/cache-002",
				"model":         "models/gemini-2.5-flash",
				"displayName":   "release-notes-context",
				"createTime":    "2026-06-01T01:00:00Z",
				"updateTime":    "2026-06-01T01:05:00Z",
				"expireTime":    "2026-06-02T01:00:00Z",
				"usageMetadata": map[string]any{"totalTokenCount": float64(2048)},
			},
			wantFirstID:   "cachedContents/cache-001",
			wantFirstName: "support-policy-context",
		},
		{
			family:  familyTunedModels,
			path:    "/v1beta/tunedModels",
			listKey: "tunedModels",
			firstRecord: map[string]any{
				"name":        "tunedModels/support-classifier-001",
				"displayName": "support-classifier",
				"description": "Sanitized tuned model entry.",
				"baseModel":   "models/gemini-2.0-flash-001",
				"state":       "ACTIVE",
				"createTime":  "2026-06-01T00:00:00Z",
				"updateTime":  "2026-06-01T00:10:00Z",
				"tuningTask":  map[string]any{"completeTime": "2026-06-01T00:09:00Z", "snapshots": []any{map[string]any{"step": float64(1), "meanLoss": float64(0.42)}}},
			},
			secondRecord: map[string]any{
				"name":        "tunedModels/triage-router-002",
				"displayName": "triage-router",
				"baseModel":   "models/gemini-2.0-flash-001",
				"state":       "CREATING",
				"createTime":  "2026-06-01T01:00:00Z",
				"updateTime":  "2026-06-01T01:10:00Z",
			},
			wantFirstID:   "tunedModels/support-classifier-001",
			wantFirstName: "support-classifier",
		},
		{
			family:  familyBatchJobs,
			path:    "/v1beta/batches",
			listKey: "operations",
			firstRecord: map[string]any{
				"name": "batches/support-export-001",
				"metadata": map[string]any{
					"@type":       "type.googleapis.com/google.ai.generativelanguage.v1beta.BatchGenerateContentMetadata",
					"displayName": "support-export",
					"state":       "JOB_STATE_SUCCEEDED",
					"createTime":  "2026-06-01T00:00:00Z",
					"updateTime":  "2026-06-01T00:20:00Z",
				},
				"done": true,
				"response": map[string]any{
					"@type":       "type.googleapis.com/google.ai.generativelanguage.v1beta.BatchGenerateContentResponse",
					"displayName": "support-export",
					"state":       "JOB_STATE_SUCCEEDED",
				},
			},
			secondRecord: map[string]any{
				"name": "batches/nightly-eval-002",
				"metadata": map[string]any{
					"@type":       "type.googleapis.com/google.ai.generativelanguage.v1beta.BatchGenerateContentMetadata",
					"displayName": "nightly-eval",
					"state":       "JOB_STATE_RUNNING",
					"createTime":  "2026-06-01T01:00:00Z",
					"updateTime":  "2026-06-01T01:20:00Z",
				},
				"done": false,
			},
			wantFirstID:   "batches/support-export-001",
			wantFirstName: "support-export",
		},
	}
}

func valueStringForTest(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

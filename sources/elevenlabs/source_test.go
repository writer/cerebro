package elevenlabs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckUsesModelsHealthPath(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAPIKey(t, r)
		if r.URL.Path != "/v1/models" {
			t.Fatalf("path = %q, want /v1/models", r.URL.Path)
		}
		writeFixture(t, w, "api_model_catalog.json")
	}))
	defer server.Close()

	if err := source.Check(context.Background(), testConfig(server.URL, familyModelCatalog)); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestSourceReadsRuntimeFamiliesFromProviderShapedResponses(t *testing.T) {
	tests := []struct {
		name       string
		family     string
		path       string
		fixture    string
		kind       string
		attributes map[string]string
		payload    map[string]string
	}{
		{
			name:    "model catalog",
			family:  familyModelCatalog,
			path:    "/v1/models",
			fixture: "api_model_catalog.json",
			kind:    "elevenlabs.model_catalog",
			attributes: map[string]string{
				"source_event_id": "eleven_multilingual_v2",
				"resource_id":     "eleven_multilingual_v2",
				"resource_name":   "Eleven Multilingual v2",
				"resource_type":   "tts",
				"record_class":    "asset",
			},
			payload: map[string]string{"model_id": "eleven_multilingual_v2"},
		},
		{
			name:    "voices",
			family:  familyVoices,
			path:    "/v2/voices",
			fixture: "api_voices_page_2.json",
			kind:    "elevenlabs.voices",
			attributes: map[string]string{
				"source_event_id": "EXAVITQu4vr4xnSDxMaL",
				"resource_id":     "EXAVITQu4vr4xnSDxMaL",
				"resource_name":   "Bella",
				"record_class":    "asset",
			},
			payload: map[string]string{"voice_id": "EXAVITQu4vr4xnSDxMaL"},
		},
		{
			name:    "service accounts",
			family:  familyServiceAccounts,
			path:    "/v1/service-accounts",
			fixture: "api_service_accounts.json",
			kind:    "elevenlabs.service_accounts",
			attributes: map[string]string{
				"source_event_id": "svc_01J6Q9W9B6Q2M4XK0B8Z",
				"user_id":         "svc_01J6Q9W9B6Q2M4XK0B8Z",
				"resource_id":     "svc_01J6Q9W9B6Q2M4XK0B8Z",
				"resource_name":   "Production voice sync",
				"record_class":    "identity_user",
			},
			payload: map[string]string{"service_account_user_id": "svc_01J6Q9W9B6Q2M4XK0B8Z"},
		},
		{
			name:    "service account api keys",
			family:  familyServiceAccountApiKeys,
			path:    "/v1/service-accounts/svc-admin/api-keys",
			fixture: "api_service_account_api_keys.json",
			kind:    "elevenlabs.service_account_api_keys",
			attributes: map[string]string{
				"source_event_id": "fixture-service-account-key-1",
				"secret_id":       "fixture-service-account-key-1",
				"secret_name":     "prod-sync-key",
				"resource_id":     "fixture-service-account-key-1",
				"record_class":    "secret",
			},
			payload: map[string]string{"key_id": "fixture-service-account-key-1"},
		},
		{
			name:    "webhooks",
			family:  familyWebhooks,
			path:    "/v1/workspace/webhooks",
			fixture: "api_webhooks.json",
			kind:    "elevenlabs.webhooks",
			attributes: map[string]string{
				"source_event_id": "wh_01J6QBRZGW8QX94C1N6",
				"deployment_id":   "wh_01J6QBRZGW8QX94C1N6",
				"deployment_name": "Conversation complete",
				"deployment_url":  "https://hooks.example.test/elevenlabs/conversation",
				"record_class":    "deployment",
			},
			payload: map[string]string{"webhook_id": "wh_01J6QBRZGW8QX94C1N6"},
		},
		{
			name:    "auth connections",
			family:  familyAuthConnections,
			path:    "/v1/workspace/auth-connections",
			fixture: "api_auth_connections.json",
			kind:    "elevenlabs.auth_connections",
			attributes: map[string]string{
				"source_event_id": "authconn_01J6QBF9HY9C3ZJWQ2V",
				"secret_id":       "authconn_01J6QBF9HY9C3ZJWQ2V",
				"secret_name":     "convai-prod-oauth",
				"record_class":    "secret",
			},
			payload: map[string]string{"name": "convai-prod-oauth"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertAPIKey(t, r)
				if r.URL.Path != tc.path {
					t.Fatalf("path = %q, want %s", r.URL.Path, tc.path)
				}
				writeFixture(t, w, tc.fixture)
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), testConfig(server.URL, tc.family), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if pull.NextCursor != nil {
				t.Fatalf("NextCursor = %#v, want nil", pull.NextCursor)
			}
			if pull.Checkpoint == nil || strings.TrimSpace(pull.Checkpoint.GetCursorOpaque()) == "" {
				t.Fatalf("Checkpoint = %#v, want cursor checkpoint", pull.Checkpoint)
			}

			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tc.kind)
			}
			if event.TenantId != "tenant" {
				t.Fatalf("tenant = %q, want tenant", event.TenantId)
			}
			if strings.TrimSpace(event.Attributes["resource_urn"]) == "" {
				t.Fatalf("resource_urn is empty: %#v", event.Attributes)
			}
			urns, err := source.Discover(context.Background(), testConfig(server.URL, tc.family))
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != 1 {
				t.Fatalf("Discover() urns = %d, want 1", len(urns))
			}
			if got, want := urns[0].String(), event.Attributes["resource_urn"]; got != want {
				t.Fatalf("Discover() URN = %q, want read resource_urn %q", got, want)
			}
			for key, want := range tc.attributes {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
			payload := payloadObject(t, event.Payload)
			for key, want := range tc.payload {
				if got := stringValue(payload[key]); got != want {
					t.Fatalf("payload %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestSourceVoicesPaginationCheckpoint(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAPIKey(t, r)
		if r.URL.Path != "/v2/voices" {
			t.Fatalf("path = %q, want /v2/voices", r.URL.Path)
		}
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("next_page_token") {
		case "":
			if got := r.URL.Query().Get("page_size"); got != "1" {
				t.Fatalf("page_size = %q, want 1", got)
			}
			writeFixture(t, w, "api_voices_page_1.json")
		case "voice-page-2":
			writeFixture(t, w, "api_voices_page_2.json")
		default:
			t.Fatalf("unexpected next_page_token %q", r.URL.Query().Get("next_page_token"))
		}
	}))
	defer server.Close()

	cfg := testConfig(server.URL, familyVoices)
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := first.NextCursor.GetOpaque(); got != "voice-page-2" {
		t.Fatalf("first NextCursor = %q, want voice-page-2", got)
	}
	if got := first.Checkpoint.GetCursorOpaque(); got != "voice-page-2" {
		t.Fatalf("first checkpoint cursor = %q, want voice-page-2", got)
	}

	second, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: first.NextCursor.GetOpaque()})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := second.Events[0].Attributes["resource_id"]; got != "EXAVITQu4vr4xnSDxMaL" {
		t.Fatalf("second resource_id = %q, want EXAVITQu4vr4xnSDxMaL", got)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if got := requests[1].URL.Query().Get("next_page_token"); got != "voice-page-2" {
		t.Fatalf("second next_page_token = %q, want voice-page-2", got)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":{"message":"service unavailable"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), testConfig(server.URL, familyModelCatalog), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "elevenlabs API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func testConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"tenant_id":               "tenant",
		"base_url":                baseURL,
		"family":                  family,
		"api_token":               "test-token",
		"service_account_user_id": "svc-admin",
		"per_page":                "1",
	})
}

func assertAPIKey(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("xi-api-key"); got != "test-token" {
		t.Fatalf("xi-api-key = %q, want test-token", got)
	}
}

func writeFixture(t *testing.T, w http.ResponseWriter, name string) {
	t.Helper()
	body, err := fixtureFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}

func payloadObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	value := map[string]any{}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return value
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

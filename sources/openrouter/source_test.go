package openrouter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireOpenRouterAuth(t, r)
		switch r.URL.Path {
		case "/v1/models":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/v1/organization/members":
			writeJSON(t, w, map[string]any{
				"data": []map[string]any{{
					"email":      "jane.doe@example.com",
					"first_name": "Jane",
					"id":         "user_2dHFtVWx2n56w6HkM0000000000",
					"last_name":  "Doe",
					"role":       "org:admin",
				}},
				"total_count": 1,
			})
			return
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "openrouter.organization_members" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["email"]; got != "jane.doe@example.com" {
		t.Fatalf("email = %q", got)
	}
	if got := event.Attributes["role"]; got != "org:admin" {
		t.Fatalf("role = %q", got)
	}
	if got := event.Attributes["status"]; got != "" {
		t.Fatalf("status = %q, want empty when provider only returns role", got)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:openrouter_organization_members:user_2dHFtVWx2n56w6HkM0000000000" {
		t.Fatalf("resource_urn = %q", got)
	}
}

func TestSourceReadsProviderShapedFamilies(t *testing.T) {
	tests := []struct {
		family string
		path   string
		body   map[string]any
		kind   string
		attr   string
		want   string
		urn    string
	}{
		{
			family: familyApiKeys,
			path:   "/v1/keys",
			body: map[string]any{"data": []map[string]any{{
				"byok_usage":            17.38,
				"byok_usage_daily":      1.25,
				"byok_usage_monthly":    17.38,
				"byok_usage_weekly":     4.5,
				"created_at":            "2025-08-24T10:30:00Z",
				"creator_user_id":       "user_2dHFtVWx2n56w6HkM0000000000",
				"disabled":              false,
				"expires_at":            "2027-12-31T23:59:59Z",
				"hash":                  "fixture-openrouter-key-hash-1",
				"include_byok_in_limit": false,
				"label":                 "Production usage key",
				"limit":                 100,
				"limit_remaining":       74.5,
				"limit_reset":           "monthly",
				"name":                  "Production usage key",
				"updated_at":            "2025-08-24T15:45:00Z",
				"usage":                 25.5,
				"usage_daily":           2.5,
				"usage_monthly":         25.5,
				"usage_weekly":          8.5,
				"workspace_id":          "0df9e665-d932-5740-b2c7-b52af166bc11",
			}}},
			kind: "openrouter.api_keys",
			attr: "secret_id",
			want: "fixture-openrouter-key-hash-1",
			urn:  "urn:cerebro:tenant:openrouter_api_keys:fixture-openrouter-key-hash-1",
		},
		{
			family: familyProviderKeys,
			path:   "/v1/byok",
			body: map[string]any{
				"data": []map[string]any{{
					"allowed_api_key_hashes": []string{"fixture-openrouter-key-hash-1"},
					"allowed_models":         []string{"openai/gpt-4.1"},
					"allowed_user_ids":       []string{"user_2dHFtVWx2n56w6HkM0000000000"},
					"created_at":             "2025-08-24T10:30:00Z",
					"disabled":               false,
					"id":                     "11111111-2222-3333-4444-555555555555",
					"is_fallback":            false,
					"label":                  "masked-provider-credential",
					"name":                   "Production OpenAI credential",
					"provider":               "openai",
					"sort_order":             0,
					"workspace_id":           "550e8400-e29b-41d4-a716-446655440000",
				}},
				"total_count": 1,
			},
			kind: "openrouter.provider_keys",
			attr: "provider_key_provider",
			want: "openai",
			urn:  "urn:cerebro:tenant:openrouter_provider_keys:11111111-2222-3333-4444-555555555555",
		},
		{
			family: familyUsageReports,
			path:   "/v1/activity",
			body: map[string]any{"data": []map[string]any{{
				"byok_usage_inference": 0.012,
				"completion_tokens":    125,
				"date":                 "2025-08-24",
				"endpoint_id":          "550e8400-e29b-41d4-a716-446655440000",
				"model":                "openai/gpt-4.1",
				"model_permaslug":      "openai/gpt-4.1-2025-04-14",
				"prompt_tokens":        50,
				"provider_name":        "OpenAI",
				"reasoning_tokens":     25,
				"requests":             5,
				"usage":                0.015,
			}}},
			kind: "openrouter.usage_reports",
			attr: "resource_type",
			want: "openrouter_activity_endpoint",
			urn:  "urn:cerebro:tenant:openrouter_usage_reports:550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source := newTestSource(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireOpenRouterAuth(t, r)
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				writeJSON(t, w, tt.body)
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
			if got := event.Attributes["resource_urn"]; got != tt.urn {
				t.Fatalf("resource_urn = %q, want %q", got, tt.urn)
			}
			if tt.family == familyApiKeys || tt.family == familyProviderKeys {
				if got := event.Attributes["secret_status"]; got == "true" || got == "false" {
					t.Fatalf("secret_status = %q, want status text or empty value", got)
				}
			}
		})
	}
}

func TestUsageReportsPreserveEndpointDayRows(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireOpenRouterAuth(t, r)
		if r.URL.Path != "/v1/activity" {
			t.Fatalf("path = %q, want /v1/activity", r.URL.Path)
		}
		writeJSON(t, w, map[string]any{"data": []map[string]any{
			{
				"date":            "2025-08-24",
				"endpoint_id":     "550e8400-e29b-41d4-a716-446655440000",
				"model":           "openai/gpt-4.1",
				"model_permaslug": "openai/gpt-4.1-2025-04-14",
				"requests":        5,
				"usage":           0.015,
			},
			{
				"date":            "2025-08-25",
				"endpoint_id":     "550e8400-e29b-41d4-a716-446655440000",
				"model":           "openai/gpt-4.1",
				"model_permaslug": "openai/gpt-4.1-2025-04-14",
				"requests":        7,
				"usage":           0.025,
			},
		}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyUsageReports, "token": "test-token"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2 endpoint-day rows", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs collapsed for different usage dates: %q", pull.Events[0].Id)
	}
	if got := pull.Events[0].Attributes["resource_urn"]; got != pull.Events[1].Attributes["resource_urn"] {
		t.Fatalf("resource_urn changed across daily rows: %q vs %q", got, pull.Events[1].Attributes["resource_urn"])
	}
	if got := pull.Events[0].Attributes["date"]; got != "2025-08-24" {
		t.Fatalf("first date = %q", got)
	}
	if got := pull.Events[1].Attributes["date"]; got != "2025-08-25" {
		t.Fatalf("second date = %q", got)
	}
}

func TestSourceReadReturnsOpenRouterErrorBody(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireOpenRouterAuth(t, r)
		if r.URL.Path != "/v1/keys" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, w, map[string]any{"error": map[string]any{"code": 401, "message": "Missing Authentication header"}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyApiKeys, "token": "test-token"})
	_, err := source.Read(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want OpenRouter error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("Read() error = %v, want HTTP 401", err)
	}
}

func TestSourceReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireOpenRouterAuth(t, r)
		if r.URL.Path != "/v1/byok" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(t, w, map[string]any{"error": "provider temporarily unavailable"})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyProviderKeys, "token": "test-token"})
	_, err := source.Read(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider unavailable error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Read() error = %v, want HTTP 503", err)
	}
	if got := err.Error(); !strings.Contains(got, "openrouter API returned 503") || !strings.Contains(got, "provider temporarily unavailable") {
		t.Fatalf("Read() error = %q, want provider unavailable detail", got)
	}
}

func TestFixtureContractsLoad(t *testing.T) {
	fixture, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, family := range []string{familyOrganizationMembers, familyApiKeys, familyProviderKeys, familyUsageReports} {
		cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": family})
		pull, err := fixture.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("fixture Read(%s) error = %v", family, err)
		}
		if len(pull.Events) == 0 {
			t.Fatalf("fixture Read(%s) returned no events", family)
		}
	}
}

func newTestSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func requireOpenRouterAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want Bearer test-token", got)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

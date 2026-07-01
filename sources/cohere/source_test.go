package cohere

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

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		name             string
		family           string
		path             string
		kind             string
		listKey          string
		response         map[string]any
		wantNext         string
		wantPayloadKey   string
		wantResourceType string
	}{
		{
			name:    "model catalog",
			family:  familyModelCatalog,
			path:    "/v1/models",
			kind:    "cohere.model_catalog",
			listKey: "models",
			response: map[string]any{
				"models": []map[string]any{{
					"name":              "command-r-08-2024",
					"endpoints":         []string{"chat"},
					"context_length":    128000,
					"tokenizer_url":     "https://storage.googleapis.com/cohere-public/tokenizers/command-r.json",
					"default_endpoints": map[string]string{"chat": "command-r-08-2024"},
				}},
				"next_page_token": "model-page-2",
			},
			wantNext:         "model-page-2",
			wantPayloadKey:   "name",
			wantResourceType: "model_catalog",
		},
		{
			name:    "connectors",
			family:  familyConnectors,
			path:    "/v1/connectors",
			kind:    "cohere.connectors",
			listKey: "connectors",
			response: map[string]any{
				"connectors": []map[string]any{{
					"id":         "connector_01HX",
					"name":       "support_docs",
					"created_at": "2024-05-01T12:00:00Z",
					"updated_at": "2024-05-03T12:00:00Z",
				}},
				"total_count": 2,
			},
			wantNext:         "1",
			wantPayloadKey:   "id",
			wantResourceType: "connectors",
		},
		{
			name:    "datasets",
			family:  familyDatasets,
			path:    "/v1/datasets",
			kind:    "cohere.datasets",
			listKey: "datasets",
			response: map[string]any{
				"datasets": []map[string]any{{
					"id":                "dataset_01HY",
					"name":              "support-chat-eval",
					"created_at":        "2024-05-04T12:00:00Z",
					"updated_at":        "2024-05-05T12:00:00Z",
					"status":            "ready",
					"validation_status": "validated",
				}},
			},
			wantNext:         "1",
			wantPayloadKey:   "id",
			wantResourceType: "datasets",
		},
		{
			name:    "fine tuned models",
			family:  familyFineTunedModels,
			path:    "/v1/finetuning/finetuned-models",
			kind:    "cohere.fine_tuned_models",
			listKey: "finetuned_models",
			response: map[string]any{
				"finetuned_models": []map[string]any{{
					"id":         "ft_01HZ",
					"name":       "support-reranker",
					"status":     "READY",
					"created_at": "2024-05-06T12:00:00Z",
					"updated_at": "2024-05-07T12:00:00Z",
				}},
				"next_page_token": "fine-tuned-page-2",
			},
			wantNext:         "fine-tuned-page-2",
			wantPayloadKey:   "id",
			wantResourceType: "fine_tuned_models",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			familyRequests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Fatalf("Authorization = %q, want Bearer test-token", got)
				}
				if got := r.Header.Get("Accept"); got != "application/json" {
					t.Fatalf("Accept = %q, want application/json", got)
				}
				if r.URL.Path == "/v1/models" && r.URL.RawQuery == "" {
					writeJSON(t, w, modelCatalogResponse())
					return
				}
				if r.URL.Path != tc.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tc.path)
				}
				familyRequests++
				assertCohereListQuery(t, tc.family, r)
				writeJSON(t, w, tc.response)
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"family":    tc.family,
				"token":     "test-token",
				"per_page":  "1",
			})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if familyRequests != 2 {
				t.Fatalf("family requests = %d, want 2", familyRequests)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tc.kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if got := event.Attributes["resource_type"]; got != tc.wantResourceType {
				t.Fatalf("resource_type = %q, want %q", got, tc.wantResourceType)
			}
			if got := event.Attributes["source_event_id"]; strings.TrimSpace(got) == "" {
				t.Fatalf("source_event_id is empty: %#v", event.Attributes)
			}
			if got := event.Attributes["resource_urn"]; !strings.HasPrefix(got, "urn:cerebro:tenant:cohere_") {
				t.Fatalf("resource_urn = %q, want cohere tenant URN", got)
			}
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("unmarshal event payload: %v", err)
			}
			if _, ok := payload[tc.wantPayloadKey]; !ok {
				t.Fatalf("payload missing %q: %#v", tc.wantPayloadKey, payload)
			}
			if pull.NextCursor == nil || pull.NextCursor.Opaque != tc.wantNext {
				t.Fatalf("next cursor = %#v, want %q", pull.NextCursor, tc.wantNext)
			}
		})
	}
}

func TestSourceRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeJSON(t, w, modelCatalogResponse())
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyModelCatalog,
	})
	err = source.Check(context.Background(), cfg)
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
	if called {
		t.Fatalf("server was called without a token")
	}
}

func TestSourceRejectsMissingProviderListKey(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want Bearer test-token", got)
		}
		writeJSON(t, w, map[string]any{"objects": []map[string]any{{"id": "dataset_01HY"}}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyDatasets,
		"token":     "test-token",
	})
	_, err = source.Read(context.Background(), cfg, nil)
	if sourcecdk.SourceErrorKind(err) != sourcecdk.ErrorKindProvider {
		t.Fatalf("Read() error kind = %q, want provider; err=%v", sourcecdk.SourceErrorKind(err), err)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/datasets" {
			t.Fatalf("path = %q, want /v1/datasets", r.URL.Path)
		}
		http.Error(w, `{"message":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    familyDatasets,
		"token":     "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "cohere API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestFixtureSourceUsesProviderPayloads(t *testing.T) {
	fixture, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	tests := []struct {
		family         string
		wantURNPrefix  string
		wantPayloadKey string
	}{
		{family: familyModelCatalog, wantURNPrefix: "urn:cerebro:tenant:cohere_model_catalog:", wantPayloadKey: "endpoints"},
		{family: familyConnectors, wantURNPrefix: "urn:cerebro:tenant:cohere_connectors:", wantPayloadKey: "created_at"},
		{family: familyDatasets, wantURNPrefix: "urn:cerebro:tenant:cohere_datasets:", wantPayloadKey: "validation_status"},
		{family: familyFineTunedModels, wantURNPrefix: "urn:cerebro:tenant:cohere_fine_tuned_models:", wantPayloadKey: "status"},
	}
	for _, tc := range tests {
		t.Run(tc.family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": tc.family})
			if err := fixture.Check(context.Background(), cfg); err != nil {
				t.Fatalf("fixture Check() error = %v", err)
			}
			urns, err := fixture.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("fixture Discover() error = %v", err)
			}
			if len(urns) != 1 || !strings.HasPrefix(urns[0].String(), tc.wantURNPrefix) {
				t.Fatalf("fixture URNs = %#v, want prefix %q", urns, tc.wantURNPrefix)
			}
			pull, err := fixture.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("fixture Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("fixture events = %d, want 1", len(pull.Events))
			}
			var payload map[string]any
			if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
				t.Fatalf("unmarshal fixture payload: %v", err)
			}
			if _, ok := payload[tc.wantPayloadKey]; !ok {
				t.Fatalf("fixture payload missing %q: %#v", tc.wantPayloadKey, payload)
			}
			rawPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal fixture payload: %v", err)
			}
			if strings.Contains(string(rawPayload), "Record One") || strings.Contains(string(rawPayload), "source-cohere") {
				t.Fatalf("fixture payload still contains generated placeholder values: %s", rawPayload)
			}
		})
	}
}

func assertCohereListQuery(t *testing.T, family string, r *http.Request) {
	t.Helper()
	query := r.URL.Query()
	if got := query.Get("per_page"); got != "" {
		t.Fatalf("per_page = %q, want empty", got)
	}
	switch family {
	case familyModelCatalog, familyFineTunedModels:
		if got := query.Get("page_size"); got != "1" {
			t.Fatalf("page_size = %q, want 1", got)
		}
		if got := query.Get("page_token"); got != "" {
			t.Fatalf("page_token = %q, want empty on first page", got)
		}
		if got := query.Get("limit"); got != "" {
			t.Fatalf("limit = %q, want empty", got)
		}
		if got := query.Get("offset"); got != "" {
			t.Fatalf("offset = %q, want empty", got)
		}
	case familyConnectors, familyDatasets:
		if got := query.Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		if got := query.Get("offset"); got != "0" {
			t.Fatalf("offset = %q, want 0", got)
		}
		if got := query.Get("page_size"); got != "" {
			t.Fatalf("page_size = %q, want empty", got)
		}
		if got := query.Get("page_token"); got != "" {
			t.Fatalf("page_token = %q, want empty", got)
		}
	default:
		t.Fatalf("unhandled family %q", family)
	}
}

func modelCatalogResponse() map[string]any {
	return map[string]any{
		"models": []map[string]any{{
			"name":           "command-r-08-2024",
			"endpoints":      []string{"chat"},
			"context_length": 128000,
		}},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

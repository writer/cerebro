package langfuse

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/internal/sourcehttp"
)

func TestGenuineProviderResponsesReplayAcceptedRuntimeFamilies(t *testing.T) {
	bundles := map[string]sourcefixture.Bundle{}
	projectBundle, err := sourcefixture.FindBundle("../..", "langfuse", "project", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(project) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, projectBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "project", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/projects", RawQuery: ""})
	bundles["project"] = projectBundle
	traceBundle, err := sourcefixture.FindBundle("../..", "langfuse", "trace", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(trace) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, traceBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "trace", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/traces", RawQuery: "limit=1&page=1"})
	bundles["trace"] = traceBundle
	scoreBundle, err := sourcefixture.FindBundle("../..", "langfuse", "score", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(score) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, scoreBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "score", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/v2/scores", RawQuery: "limit=1&page=1"})
	bundles["score"] = scoreBundle
	promptBundle, err := sourcefixture.FindBundle("../..", "langfuse", "prompt", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(prompt) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, promptBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "prompt", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/v2/prompts", RawQuery: "limit=1&page=1"})
	bundles["prompt"] = promptBundle
	sessionBundle, err := sourcefixture.FindBundle("../..", "langfuse", "session", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(session) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, sessionBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "session", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/sessions", RawQuery: "limit=1&page=1"})
	bundles["session"] = sessionBundle
	annotationQueueBundle, err := sourcefixture.FindBundle("../..", "langfuse", "annotation_queue", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(annotation_queue) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, annotationQueueBundle, sourcefixture.ReplayContract{SourceID: "langfuse", Family: "annotation_queue", Case: "authorized_first_page", Method: http.MethodGet, Host: "langfuse.example.com", Path: "/api/public/annotation-queues", RawQuery: "limit=1&page=1"})
	bundles["annotation_queue"] = annotationQueueBundle

	tests := []struct {
		family       string
		wantPath     string
		runtimeQuery string
		wantKind     string
		wantAttr     string
		wantEvents   bool
	}{
		{family: "project", wantPath: "/api/public/projects", wantKind: "langfuse.project", wantAttr: "project_id", wantEvents: true},
		{family: "trace", wantPath: "/api/public/traces", runtimeQuery: "limit=100&page=1", wantKind: "langfuse.trace", wantAttr: "trace_id", wantEvents: true},
		{family: "score", wantPath: "/api/public/v2/scores", runtimeQuery: "limit=100&page=1", wantKind: "langfuse.score", wantAttr: "score_id"},
		{family: "prompt", wantPath: "/api/public/v2/prompts", runtimeQuery: "limit=100&page=1", wantKind: "langfuse.prompt", wantAttr: "prompt_id"},
		{family: "session", wantPath: "/api/public/sessions", runtimeQuery: "limit=100&page=1", wantKind: "langfuse.session", wantAttr: "session_id", wantEvents: true},
		{family: "annotation_queue", wantPath: "/api/public/annotation-queues", runtimeQuery: "limit=100&page=1", wantKind: "langfuse.annotation_queue", wantAttr: "annotation_queue_id"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := bundles[test.family]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := sourcehttp.ValidateReplayRequest(r, http.MethodGet, test.wantPath, test.runtimeQuery); err != nil {
					t.Fatalf("ValidateReplayRequest() error = %v", err)
				}
				if username, password, ok := r.BasicAuth(); !ok || username != "replay-public-key" || password != "replay-secret-key" {
					t.Fatalf("BasicAuth() = %q/%q/%t, want configured replay key pair", username, password, ok)
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
				"base_url":   server.URL,
				"family":     test.family,
				"public_key": "replay-public-key",
				"secret_key": "replay-secret-key",
				"tenant_id":  "writer",
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if !test.wantEvents {
				if len(pull.Events) != 0 {
					t.Fatalf("len(Events) = %d, want genuine empty provider page", len(pull.Events))
				}
				compareGenuineProviderOutputs(t, source, cfg, bundle, test.family, pull)
				return
			}
			if len(pull.Events) == 0 {
				t.Fatal("Read() emitted no events")
			}
			for _, event := range pull.Events {
				if event.Kind != test.wantKind || strings.TrimSpace(event.Attributes[test.wantAttr]) == "" {
					t.Fatalf("event kind/attributes = %q/%#v, want %q with %s", event.Kind, event.Attributes, test.wantKind, test.wantAttr)
				}
			}
			compareGenuineProviderOutputs(t, source, cfg, bundle, test.family, pull)
		})
	}
}

func compareGenuineProviderOutputs(t *testing.T, source *Source, cfg sourcecdk.Config, bundle sourcefixture.Bundle, family string, pull sourcecdk.Pull) {
	t.Helper()
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(%s) error = %v", family, err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
		t.Fatalf("StabilizeEvents(%s) error = %v", family, err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}

func TestGenuineProviderV1FallbackResponsesReplay(t *testing.T) {
	observationBundle, err := sourcefixture.FindBundle("../..", "langfuse", "observation", "authorized_v1_fallback_first_page")
	if err != nil {
		t.Fatalf("FindBundle(observation) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, observationBundle, sourcefixture.ReplayContract{
		SourceID: "langfuse",
		Family:   "observation",
		Case:     "authorized_v1_fallback_first_page",
		Method:   http.MethodGet,
		Host:     "langfuse.example.com",
		Path:     "/api/public/observations",
		RawQuery: "limit=1&page=1",
	})
	metricsQuery := `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z","config":{"row_limit":1}}`
	metricsRawQuery := url.Values{"query": []string{metricsQuery}}.Encode()
	metricBundle, err := sourcefixture.FindBundle("../..", "langfuse", "metric", "authorized_v1_fallback_first_page")
	if err != nil {
		t.Fatalf("FindBundle(metric) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, metricBundle, sourcefixture.ReplayContract{
		SourceID: "langfuse",
		Family:   "metric",
		Case:     "authorized_v1_fallback_first_page",
		Method:   http.MethodGet,
		Host:     "langfuse.example.com",
		Path:     "/api/public/metrics",
		RawQuery: "query=%7B%22view%22%3A%22observations%22%2C%22dimensions%22%3A%5B%7B%22field%22%3A%22name%22%7D%5D%2C%22metrics%22%3A%5B%7B%22measure%22%3A%22count%22%2C%22aggregation%22%3A%22count%22%7D%5D%2C%22fromTimestamp%22%3A%222026-08-19T12%3A00%3A00Z%22%2C%22toTimestamp%22%3A%222026-08-20T12%3A00%3A00Z%22%2C%22config%22%3A%7B%22row_limit%22%3A1%7D%7D",
	})

	t.Run("observation", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			wantPath := "/api/public/v2/observations"
			wantQuery := "limit=100"
			if requestCount == 2 {
				wantPath = "/api/public/observations"
				wantQuery = "limit=100&page=1"
			}
			if err := sourcehttp.ValidateReplayRequest(r, http.MethodGet, wantPath, wantQuery); err != nil {
				t.Fatalf("ValidateReplayRequest(%d) error = %v", requestCount, err)
			}
			if username, password, ok := r.BasicAuth(); !ok || username != "replay-public-key" || password != "replay-secret-key" {
				t.Fatalf("BasicAuth() = %q/%q/%t, want configured replay key pair", username, password, ok)
			}
			if requestCount == 1 {
				w.WriteHeader(http.StatusNotImplemented)
				_, _ = w.Write([]byte(`{"message":"v2 not implemented"}`))
				return
			}
			w.Header().Set("Content-Type", observationBundle.Manifest.Response.ContentType)
			w.WriteHeader(observationBundle.Manifest.Response.Status)
			_, _ = w.Write(observationBundle.Payload)
		}))
		defer server.Close()

		source, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		source.inner.AllowLoopbackBaseURL = true
		cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
			"base_url":   server.URL,
			"family":     "observation",
			"public_key": "replay-public-key",
			"secret_key": "replay-secret-key",
			"tenant_id":  "writer",
		})
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].Kind != "langfuse.observation" || strings.TrimSpace(pull.Events[0].Attributes["observation_id"]) == "" || requestCount != 2 {
			t.Fatalf("fallback observation replay = %#v requests=%d, want one production-decoded event after exact 501", pull, requestCount)
		}
		requestCount = 0
		compareGenuineProviderOutputs(t, source, cfg, observationBundle, "observation", pull)
		if requestCount != 2 {
			t.Fatalf("Discover(observation) requests = %d, want exact v2 501 then v1 replay", requestCount)
		}
	})

	t.Run("metric", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			wantPath := "/api/public/v2/metrics"
			if requestCount == 2 {
				wantPath = "/api/public/metrics"
			}
			if err := sourcehttp.ValidateReplayRequest(r, http.MethodGet, wantPath, metricsRawQuery); err != nil {
				t.Fatalf("ValidateReplayRequest(%d) error = %v", requestCount, err)
			}
			if username, password, ok := r.BasicAuth(); !ok || username != "replay-public-key" || password != "replay-secret-key" {
				t.Fatalf("BasicAuth() = %q/%q/%t, want configured replay key pair", username, password, ok)
			}
			if requestCount == 1 {
				w.WriteHeader(http.StatusNotImplemented)
				_, _ = w.Write([]byte(`{"message":"v2 not implemented"}`))
				return
			}
			w.Header().Set("Content-Type", metricBundle.Manifest.Response.ContentType)
			w.WriteHeader(metricBundle.Manifest.Response.Status)
			_, _ = w.Write(metricBundle.Payload)
		}))
		defer server.Close()

		source, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		source.inner.AllowLoopbackBaseURL = true
		cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
			"base_url":      server.URL,
			"family":        "metric",
			"metrics_query": metricsQuery,
			"public_key":    "replay-public-key",
			"secret_key":    "replay-secret-key",
			"tenant_id":     "writer",
		})
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].Kind != "langfuse.metric" || strings.TrimSpace(pull.Events[0].Attributes["metric_id"]) == "" || requestCount != 2 {
			t.Fatalf("fallback metric replay = %#v requests=%d, want one production-decoded event after exact 501", pull, requestCount)
		}
		requestCount = 0
		compareGenuineProviderOutputs(t, source, cfg, metricBundle, "metric", pull)
		if requestCount != 2 {
			t.Fatalf("Discover(metric) requests = %d, want exact v2 501 then v1 replay", requestCount)
		}
	})
}

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "langfuse" {
		t.Fatalf("Spec().Id = %q, want langfuse", got)
	}
}

func TestProviderSpecificPaginationAndEnvelopeContracts(t *testing.T) {
	wantUnpaged := map[string]string{
		"project":        "data",
		"project_member": "memberships",
		"api_key":        "apiKeys",
	}
	for _, family := range langfuseFamilies() {
		if listKey, ok := wantUnpaged[family.Name]; ok {
			delete(wantUnpaged, family.Name)
			if !family.DisablePageSize || family.CursorParam != "" || family.PageFirstCursor != "" {
				t.Fatalf("%s pagination = disabled:%t cursor:%q first:%q, want unpaged", family.Name, family.DisablePageSize, family.CursorParam, family.PageFirstCursor)
			}
			if len(family.ListKeys) != 1 || family.ListKeys[0] != listKey {
				t.Fatalf("%s ListKeys = %#v, want %q", family.Name, family.ListKeys, listKey)
			}
		}
		if family.Name == "observation" {
			if family.CursorParam != "cursor" || family.PageFirstCursor != "" {
				t.Fatalf("observation cursor = %q first = %q, want response cursor", family.CursorParam, family.PageFirstCursor)
			}
			if len(family.NextCursorKeys) != 1 || family.NextCursorKeys[0] != "meta.cursor" {
				t.Fatalf("observation NextCursorKeys = %#v, want meta.cursor", family.NextCursorKeys)
			}
		}
	}
	for name := range wantUnpaged {
		t.Fatalf("missing family %s", name)
	}
}

func TestReadProjectAPIKeysUsesBasicAuthAndProjectScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/projects/project_123/apiKeys" {
			t.Fatalf("request path = %q, want /api/public/projects/project_123/apiKeys", got)
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("pk-lf:test-secret"))
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no pagination", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiKeys": []map[string]any{{
				"id":        "key_123",
				"publicKey": "pk-lf-key",
				"createdAt": "2026-06-24T12:00:00Z",
			}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "api_key",
		"project_id": "project_123",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.api_key" {
		t.Fatalf("Kind = %q, want langfuse.api_key", event.Kind)
	}
	for key, want := range map[string]string{
		"api_key_id":      "key_123",
		"credential_type": "langfuse_project_api_key",
		"project_id":      "project_123",
		"public_key":      "pk-lf-key",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	compareSyntheticProviderOutputs(t, source, cfg, "api_key", pull)
}

func TestReadProjectMemberEmitsStaticPrincipalType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/projects/project_123/memberships" {
			t.Fatalf("request path = %q, want /api/public/projects/project_123/memberships", got)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no pagination", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"memberships": []map[string]any{{
				"id":        "member_123",
				"userId":    "user_123",
				"email":     "owner@example.com",
				"role":      "OWNER",
				"createdAt": "2026-06-24T12:00:00Z",
			}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "project_member",
		"project_id": "project_123",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.project_member" {
		t.Fatalf("Kind = %q, want langfuse.project_member", event.Kind)
	}
	if got := event.Attributes["principal_type"]; got != "user" {
		t.Fatalf("principal_type = %q, want user", got)
	}
	compareSyntheticProviderOutputs(t, source, cfg, "project_member", pull)
}

func compareSyntheticProviderOutputs(t *testing.T, source *Source, cfg sourcecdk.Config, family string, pull sourcecdk.Pull) {
	t.Helper()
	stableFixture := sourcefixture.Bundle{Manifest: sourcefixture.Manifest{
		SourceID: "langfuse",
		Family:   family,
		Response: sourcefixture.Response{CapturedAt: "2026-06-24T12:00:00Z"},
	}}
	if err := sourcefixture.StabilizeEvents(stableFixture, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents(%s) error = %v", family, err)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(%s) error = %v", family, err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}

func TestReadObservationMapsUsageAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/v2/observations" {
			t.Fatalf("request path = %q, want /api/public/v2/observations", got)
		}
		if got := r.URL.Query().Get("fromStartTime"); got != "2026-06-24T00:00:00Z" {
			t.Fatalf("fromStartTime = %q, want 2026-06-24T00:00:00Z", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":        "obs_123",
				"traceId":   "trace_123",
				"name":      "completion",
				"type":      "GENERATION",
				"model":     "gpt-4.1",
				"startTime": "2026-06-24T12:00:00Z",
				"usage": map[string]any{
					"input":  12,
					"output": 34,
					"total":  46,
				},
			}},
			"meta": map[string]any{"page": 1, "totalPages": 1},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":        server.URL,
		"family":          "observation",
		"from_start_time": "2026-06-24T00:00:00Z",
		"public_key":      "pk-lf",
		"secret_key":      "test-secret",
		"tenant_id":       "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	event := pull.Events[0]
	if event.Kind != "langfuse.observation" {
		t.Fatalf("Kind = %q, want langfuse.observation", event.Kind)
	}
	for key, want := range map[string]string{
		"input_tokens":   "12",
		"model":          "gpt-4.1",
		"observation_id": "obs_123",
		"output_tokens":  "34",
		"total_tokens":   "46",
		"trace_id":       "trace_123",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadProjectUsesOfficialUnpagedEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/projects" {
			t.Fatalf("request path = %q, want /api/public/projects", got)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no pagination", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "project_123", "name": "Example Project"}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "project",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["project_id"] != "project_123" {
		t.Fatalf("events = %#v, want one official project record", pull.Events)
	}
}

func TestReadObservationUsesResponseCursorInNextRequest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if got := r.URL.EscapedPath(); got != "/api/public/v2/observations" {
			t.Fatalf("request path = %q, want v2 observations", got)
		}
		if got := r.URL.Query().Get("page"); got != "" {
			t.Fatalf("page = %q, want no page pagination", got)
		}
		wantCursor := ""
		if requestCount == 2 {
			wantCursor = "cursor-example"
		}
		if got := r.URL.Query().Get("cursor"); got != wantCursor {
			t.Fatalf("request %d cursor = %q, want %q", requestCount, got, wantCursor)
		}
		next := any(nil)
		if requestCount == 1 {
			next = "cursor-example"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":        fmt.Sprintf("observation_%d", requestCount),
				"traceId":   "trace_123",
				"startTime": "2026-08-20T12:00:00Z",
				"type":      "SPAN",
			}},
			"meta": map[string]any{"cursor": next},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "observation",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "cursor-example" {
		t.Fatalf("first NextCursor = %v, want cursor-example", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if second.NextCursor != nil || len(second.Events) != 1 || requestCount != 2 {
		t.Fatalf("second pull = %#v requests=%d, want terminal second page", second, requestCount)
	}
}

func TestReadObservationFallsBackOnlyFromV2NotImplementedAndPagesV1(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch requestCount {
		case 1:
			if got := r.URL.EscapedPath(); got != "/api/public/v2/observations" {
				t.Fatalf("first request path = %q, want v2 observations", got)
			}
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(`{"message":"v2 not implemented"}`))
		case 2, 3:
			if got := r.URL.EscapedPath(); got != "/api/public/observations" {
				t.Fatalf("fallback request %d path = %q, want v1 observations", requestCount, got)
			}
			wantPage := requestCount - 1
			if got := r.URL.Query().Get("page"); got != fmt.Sprint(wantPage) {
				t.Fatalf("fallback request %d page = %q, want %d", requestCount, got, wantPage)
			}
			if got := r.URL.Query().Get("limit"); got != "100" {
				t.Fatalf("fallback request %d limit = %q, want 100", requestCount, got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":        fmt.Sprintf("observation_%d", wantPage),
					"traceId":   "trace_123",
					"startTime": "2026-08-20T12:00:00Z",
					"type":      "SPAN",
				}},
				"meta": map[string]any{"page": wantPage, "totalPages": 2},
			})
		default:
			t.Fatalf("unexpected request %d", requestCount)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":   server.URL,
		"family":     "observation",
		"public_key": "pk-lf",
		"secret_key": "test-secret",
		"tenant_id":  "writer",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if len(first.Events) != 1 || first.NextCursor == nil || first.NextCursor.GetOpaque() != "langfuse-v1:2" {
		t.Fatalf("first fallback pull = %#v, want one event and langfuse-v1:2", first)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if len(second.Events) != 1 || second.NextCursor != nil || requestCount != 3 {
		t.Fatalf("second fallback pull = %#v requests=%d, want terminal v1 page", second, requestCount)
	}
}

func TestReadMetricFallsBackOnlyFromV2NotImplementedWithExactQuery(t *testing.T) {
	metricsQuery := `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z","config":{"row_limit":100}}`
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		wantPath := "/api/public/v2/metrics"
		if requestCount == 2 {
			wantPath = "/api/public/metrics"
		}
		if got := r.URL.EscapedPath(); got != wantPath {
			t.Fatalf("request %d path = %q, want %q", requestCount, got, wantPath)
		}
		if got := r.URL.Query()["query"]; len(got) != 1 || got[0] != metricsQuery {
			t.Fatalf("request %d query = %#v, want one exact JSON query", requestCount, r.URL.Query())
		}
		if r.URL.Query().Has("page") || r.URL.Query().Has("limit") {
			t.Fatalf("request %d query = %#v, want no pagination", requestCount, r.URL.Query())
		}
		if requestCount == 1 {
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte(`{"message":"v2 not implemented"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"name": "completion", "count_count": 12}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":      server.URL,
		"family":        "metric",
		"metrics_query": metricsQuery,
		"public_key":    "pk-lf",
		"secret_key":    "test-secret",
		"tenant_id":     "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["metric_id"] != "completion" || requestCount != 2 {
		t.Fatalf("fallback pull = %#v requests=%d, want one v1 metric", pull, requestCount)
	}
}

func TestReadDoesNotFallbackFromV2OnAnyStatusExceptNotImplemented(t *testing.T) {
	for _, family := range []string{"observation", "metric"} {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
			t.Run(fmt.Sprintf("%s_%d", family, status), func(t *testing.T) {
				requestCount := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestCount++
					if strings.Contains(r.URL.EscapedPath(), "/api/public/observations") || r.URL.EscapedPath() == "/api/public/metrics" {
						t.Fatalf("unexpected v1 fallback path %q for status %d", r.URL.EscapedPath(), status)
					}
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"message":"provider error"}`))
				}))
				defer server.Close()

				source, err := New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				source.inner.AllowLoopbackBaseURL = true
				cfg := map[string]string{
					"base_url":   server.URL,
					"family":     family,
					"public_key": "pk-lf",
					"secret_key": "test-secret",
					"tenant_id":  "writer",
				}
				if family == "metric" {
					cfg["metrics_query"] = `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z"}`
				}
				if _, err := source.Read(context.Background(), sourcecdk.NewConfig(cfg), nil); err == nil {
					t.Fatal("Read() error = nil, want primary v2 error")
				}
				if requestCount < 1 {
					t.Fatalf("request count = %d, want at least one v2 request", requestCount)
				}
			})
		}
	}
}

func TestReadDoesNotFallbackFromV2OnTransportOrDecodeErrors(t *testing.T) {
	for _, family := range []string{"observation", "metric"} {
		for _, failure := range []string{"transport", "decode"} {
			t.Run(family+"_"+failure, func(t *testing.T) {
				var requestCount atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestCount.Add(1)
					if r.URL.EscapedPath() == "/api/public/observations" || r.URL.EscapedPath() == "/api/public/metrics" {
						t.Fatalf("unexpected v1 fallback path %q for %s error", r.URL.EscapedPath(), failure)
					}
					if failure == "transport" {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Fatalf("Hijack() error = %v", err)
						}
						_ = connection.Close()
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"data":`))
				}))
				defer server.Close()

				source, err := New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				source.inner.AllowLoopbackBaseURL = true
				cfg := map[string]string{
					"base_url":   server.URL,
					"family":     family,
					"public_key": "pk-lf",
					"secret_key": "test-secret",
					"tenant_id":  "writer",
				}
				if family == "metric" {
					cfg["metrics_query"] = `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z"}`
				}
				if _, err := source.Read(context.Background(), sourcecdk.NewConfig(cfg), nil); err == nil {
					t.Fatalf("Read() error = nil, want %s error", failure)
				}
				if count := requestCount.Load(); count < 1 {
					t.Fatalf("request count = %d, want at least one v2 request", count)
				}
			})
		}
	}
}

func TestReadMetricUsesOneBoundedV2JSONQuery(t *testing.T) {
	metricsQuery := `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z","config":{"row_limit":100}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/api/public/v2/metrics" {
			t.Fatalf("request path = %q, want /api/public/v2/metrics", got)
		}
		if got := r.URL.Query()["query"]; len(got) != 1 || got[0] != metricsQuery {
			t.Fatalf("query parameters = %#v, want one metrics JSON query", r.URL.Query())
		}
		if r.URL.Query().Has("page") || r.URL.Query().Has("limit") {
			t.Fatalf("metrics query = %#v, want no page contract", r.URL.Query())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"name": "completion", "count_count": 12}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
		"base_url":      server.URL,
		"family":        "metric",
		"metrics_query": metricsQuery,
		"public_key":    "pk-lf",
		"secret_key":    "test-secret",
		"tenant_id":     "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["metric_id"] != "completion" || pull.Events[0].Attributes["request_count"] != "12" {
		t.Fatalf("events = %#v, want one bounded metric aggregate", pull.Events)
	}
}

func TestMetricQueryFailsClosedWithoutStableBoundedWindow(t *testing.T) {
	for name, query := range map[string]string{
		"missing":         "",
		"unstable id":     `{"view":"observations","metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-08-19T12:00:00Z","toTimestamp":"2026-08-20T12:00:00Z"}`,
		"unbounded range": `{"view":"observations","dimensions":[{"field":"name"}],"metrics":[{"measure":"count","aggregation":"count"}],"fromTimestamp":"2026-01-01T00:00:00Z","toTimestamp":"2026-08-20T12:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMetricsQuery(sourcecdk.NewConfig(map[string]string{"family": "metric", "metrics_query": query})); err == nil {
				t.Fatalf("validateMetricsQuery() = nil, want fail-closed error")
			}
		})
	}
}

func TestReadScoreAndPromptUseDocumentedV2ListRoutes(t *testing.T) {
	tests := []struct {
		family   string
		wantPath string
		response map[string]any
		wantKind string
		wantID   string
		wantKey  string
	}{
		{
			family:   "score",
			wantPath: "/api/public/v2/scores",
			response: map[string]any{
				"data": []map[string]any{{"id": "score_123", "name": "quality", "value": 1}},
				"meta": map[string]any{"page": 1, "totalPages": 1},
			},
			wantKind: "langfuse.score",
			wantID:   "score_123",
			wantKey:  "score_id",
		},
		{
			family:   "prompt",
			wantPath: "/api/public/v2/prompts",
			response: map[string]any{
				"data": []map[string]any{{
					"name":          "policy-review",
					"type":          "text",
					"versions":      []int{1, 3},
					"labels":        []string{"production"},
					"tags":          []string{"policy"},
					"lastUpdatedAt": "2026-08-20T12:00:00Z",
					"lastConfig":    map[string]any{"model": "example-model"},
				}},
				"meta": map[string]any{"page": 1, "totalPages": 1},
			},
			wantKind: "langfuse.prompt",
			wantID:   "policy-review",
			wantKey:  "prompt_id",
		},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != test.wantPath {
					t.Fatalf("request path = %q, want %s", got, test.wantPath)
				}
				if username, password, ok := r.BasicAuth(); !ok || username != "pk-lf" || password != "test-secret" {
					t.Fatalf("BasicAuth() = %q/%q/%t, want configured Langfuse key pair", username, password, ok)
				}
				_ = json.NewEncoder(w).Encode(test.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder secret.
				"base_url":   server.URL,
				"family":     test.family,
				"public_key": "pk-lf",
				"secret_key": "test-secret",
				"tenant_id":  "writer",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != test.wantKind {
				t.Fatalf("Kind = %q, want %q", got, test.wantKind)
			}
			if got := pull.Events[0].Attributes[test.wantKey]; got != test.wantID {
				t.Fatalf("%s = %q, want %q", test.wantKey, got, test.wantID)
			}
			if test.family == "prompt" {
				for key, want := range map[string]string{
					"versions":        "1,3",
					"last_updated_at": "2026-08-20T12:00:00Z",
					"last_config":     `{"model":"example-model"}`,
				} {
					if got := pull.Events[0].Attributes[key]; got != want {
						t.Fatalf("%s = %q, want %q", key, got, want)
					}
				}
			}
		})
	}
}

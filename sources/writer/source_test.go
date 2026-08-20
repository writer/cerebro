package writer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "writer" {
		t.Fatalf("Spec().Id = %q, want writer", got)
	}
}

func TestGenuineProviderResponsesReplayAcceptedRuntimeFamilies(t *testing.T) {
	bundles := map[string]sourcefixture.Bundle{}
	modelBundle, err := sourcefixture.FindBundle("../..", "writer", "model", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(model) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, modelBundle, sourcefixture.ReplayContract{SourceID: "writer", Family: "model", Case: "authorized_first_page", Method: http.MethodGet, Host: "api.writer.com", Path: "/v1/models", RawQuery: ""})
	bundles["model"] = modelBundle
	graphBundle, err := sourcefixture.FindBundle("../..", "writer", "graph", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(graph) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, graphBundle, sourcefixture.ReplayContract{SourceID: "writer", Family: "graph", Case: "authorized_first_page", Method: http.MethodGet, Host: "api.writer.com", Path: "/v1/graphs", RawQuery: "limit=1"})
	bundles["graph"] = graphBundle
	fileBundle, err := sourcefixture.FindBundle("../..", "writer", "file", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(file) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, fileBundle, sourcefixture.ReplayContract{SourceID: "writer", Family: "file", Case: "authorized_first_page", Method: http.MethodGet, Host: "api.writer.com", Path: "/v1/files", RawQuery: "limit=1"})
	bundles["file"] = fileBundle
	listBundle, err := sourcefixture.FindBundle("../..", "writer", "application", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(application list) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, listBundle, sourcefixture.ReplayContract{
		SourceID: "writer",
		Family:   "application",
		Case:     "authorized_first_page",
		Method:   http.MethodGet,
		Host:     "api.writer.com",
		Path:     "/v1/applications",
		RawQuery: "limit=1",
	})
	detailBundle, err := sourcefixture.FindBundle("../..", "writer", "application", "authorized_detail")
	if err != nil {
		t.Fatalf("FindBundle(application detail) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, detailBundle, sourcefixture.ReplayContract{
		SourceID: "writer",
		Family:   "application",
		Case:     "authorized_detail",
		Method:   http.MethodGet,
		Host:     "api.writer.com",
		Path:     "/v1/applications/example-application",
		RawQuery: "",
	})
	applicationJobBundle, err := sourcefixture.FindBundle("../..", "writer", "application_job", "authorized_first_page")
	if err != nil {
		t.Fatalf("FindBundle(application job) error = %v", err)
	}
	sourcefixture.RequireReplayContract(t, applicationJobBundle, sourcefixture.ReplayContract{
		SourceID: "writer",
		Family:   "application_job",
		Case:     "authorized_first_page",
		Method:   http.MethodGet,
		Host:     "api.writer.com",
		Path:     "/v1/applications/example-application/jobs",
		RawQuery: "limit=1&offset=0",
	})

	tests := []struct {
		family       string
		wantPath     string
		runtimeQuery string
		wantKind     string
		wantAttr     string
	}{
		{family: "model", wantPath: "/v1/models", wantKind: "writer.model", wantAttr: "model_id"},
		{family: "graph", wantPath: "/v1/graphs", runtimeQuery: "limit=100", wantKind: "writer.graph", wantAttr: "graph_id"},
		{family: "file", wantPath: "/v1/files", runtimeQuery: "limit=100", wantKind: "writer.file", wantAttr: "file_id"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := bundles[test.family]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := sourcefixture.ValidateHTTPReplayRequest(r, http.MethodGet, test.wantPath, test.runtimeQuery); err != nil {
					t.Fatalf("ValidateHTTPReplayRequest() error = %v", err)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
					t.Fatalf("Authorization = %q, want replay token", got)
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
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"api_key":   "replay-token",
				"base_url":  server.URL,
				"family":    test.family,
				"tenant_id": "writer",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) == 0 {
				t.Fatal("Read() emitted no events")
			}
			for _, event := range pull.Events {
				if event.Kind != test.wantKind || strings.TrimSpace(event.Attributes[test.wantAttr]) == "" {
					t.Fatalf("event kind/attributes = %q/%#v, want %q with %s", event.Kind, event.Attributes, test.wantKind, test.wantAttr)
				}
			}
		})
	}

	t.Run("application", func(t *testing.T) {
		var envelope struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(listBundle.Payload, &envelope); err != nil || len(envelope.Data) != 1 || envelope.Data[0].ID == "" {
			t.Fatalf("decode sanitized application list: data=%#v error=%v", envelope.Data, err)
		}
		detailPath := "/v1/applications/" + envelope.Data[0].ID
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var bundle sourcefixture.Bundle
			wantPath := ""
			wantQuery := ""
			switch r.URL.EscapedPath() {
			case "/v1/applications":
				bundle = listBundle
				wantPath = "/v1/applications"
				wantQuery = "limit=100"
			case detailPath:
				bundle = detailBundle
				wantPath = detailPath
			default:
				t.Fatalf("unexpected application replay path %q", r.URL.EscapedPath())
			}
			if err := sourcefixture.ValidateHTTPReplayRequest(r, http.MethodGet, wantPath, wantQuery); err != nil {
				t.Fatalf("ValidateHTTPReplayRequest() error = %v", err)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
				t.Fatalf("Authorization = %q, want replay token", got)
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
		pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
			"api_key":   "replay-token",
			"base_url":  server.URL,
			"family":    "application",
			"tenant_id": "writer",
		}), nil)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if len(pull.Events) != 1 || pull.Events[0].Kind != "writer.application" || pull.Events[0].Attributes["application_id"] != envelope.Data[0].ID {
			t.Fatalf("application replay events = %#v, want one detail-enriched application", pull.Events)
		}
	})

	t.Run("application_job", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := sourcefixture.ValidateHTTPReplayRequest(r, http.MethodGet, "/v1/applications/replay-application/jobs", "limit=100"); err != nil {
				t.Fatalf("ValidateHTTPReplayRequest() error = %v", err)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
				t.Fatalf("Authorization = %q, want replay token", got)
			}
			w.Header().Set("Content-Type", applicationJobBundle.Manifest.Response.ContentType)
			w.WriteHeader(applicationJobBundle.Manifest.Response.Status)
			_, _ = w.Write(applicationJobBundle.Payload)
		}))
		defer server.Close()

		source, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		source.inner.AllowLoopbackBaseURL = true
		pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
			"api_key":        "replay-token",
			"application_id": "replay-application",
			"base_url":       server.URL,
			"family":         "application_job",
			"tenant_id":      "writer",
		}), nil)
		if err != nil {
			t.Fatalf("Read() error = %v", err)
		}
		if len(pull.Events) != 0 {
			t.Fatalf("len(Events) = %d, want genuine empty provider page", len(pull.Events))
		}
	})
}

func TestReadEmitsRequiredInventoryKindIdentifiers(t *testing.T) {
	cases := []struct {
		family      string
		response    map[string]any
		wantKind    string
		wantAttr    string
		wantAttrVal string
	}{
		{
			family: "model",
			response: map[string]any{
				"models": []map[string]any{{"id": "palmyra-x5", "name": "Palmyra X5"}},
			},
			wantKind: "writer.model", wantAttr: "model_id", wantAttrVal: "palmyra-x5",
		},
		{
			family: "graph",
			response: map[string]any{
				"data":     []map[string]any{{"id": "graph_1", "name": "Security", "type": "manual", "created_at": "2026-06-22T10:00:00Z"}},
				"has_more": false,
			},
			wantKind: "writer.graph", wantAttr: "graph_id", wantAttrVal: "graph_1",
		},
		{
			family: "file",
			response: map[string]any{
				"data":     []map[string]any{{"id": "file_1", "name": "policy.pdf", "status": "completed", "created_at": "2026-06-22T10:00:00Z"}},
				"has_more": false,
			},
			wantKind: "writer.file", wantAttr: "file_id", wantAttrVal: "file_1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer writer-key" {
					t.Fatalf("Authorization = %q, want Bearer writer-key", got)
				}
				_ = json.NewEncoder(w).Encode(tc.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"api_key":   "writer-key",
				"base_url":  server.URL,
				"family":    tc.family,
				"tenant_id": "writer",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tc.wantKind)
			}
			if got := event.Attributes[tc.wantAttr]; got != tc.wantAttrVal {
				t.Fatalf("%s = %q, want %q", tc.wantAttr, got, tc.wantAttrVal)
			}
		})
	}
}

func TestReadApplicationEnrichesDetailAndMapsCursor(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		if got := r.URL.EscapedPath(); got == "/v1/applications" {
			if got := r.URL.Query().Get("limit"); got != "2" {
				t.Fatalf("limit = %q, want 2", got)
			}
			if got := r.URL.Query().Get("order"); got != "asc" {
				t.Fatalf("order = %q, want asc", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":         "app_1",
					"name":       "Policy Agent",
					"type":       "generation",
					"status":     "deployed",
					"created_at": "2026-06-22T10:00:00Z",
				}},
				"has_more": true,
				"last_id":  "app_1",
			})
			return
		}
		if got := r.URL.EscapedPath(); got != "/v1/applications/app_1" {
			t.Fatalf("detail path = %q, want /v1/applications/app_1", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":               "app_1",
			"name":             "Policy Agent",
			"updated_at":       "2026-06-22T11:00:00Z",
			"last_deployed_at": "2026-06-22T11:30:00Z",
			"inputs":           []map[string]any{{"name": "prompt", "input_type": "text", "required": true}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":   "writer-key",
		"base_url":  server.URL,
		"family":    "application",
		"order":     "asc",
		"per_page":  "2",
		"tenant_id": "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["application_id"]; got != "app_1" {
		t.Fatalf("application_id = %q, want app_1", got)
	}
	if got := event.Attributes["updated_at"]; got != "2026-06-22T11:00:00Z" {
		t.Fatalf("updated_at = %q, want detail timestamp", got)
	}
	if got := event.Attributes["inputs"]; got == "" {
		t.Fatalf("inputs attribute empty, want serialized application inputs")
	}
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "app_1" {
		t.Fatalf("NextCursor = %v, want app_1", pull.NextCursor)
	}
	wantTime := time.Date(2026, 6, 22, 11, 0, 0, 0, time.UTC)
	if got := event.OccurredAt.AsTime(); !got.Equal(wantTime) {
		t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), wantTime.Format(time.RFC3339))
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %v, want list and detail requests", paths)
	}
}

func TestReadApplicationGraphUsesPathParamAndNoPageSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v1/applications/app_1/graphs" {
			t.Fatalf("request path = %q, want /v1/applications/app_1/graphs", got)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no page-size params", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"graph_ids": []string{"graph_1", "graph_2"},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":        "writer-key",
		"application_id": "app_1",
		"base_url":       server.URL,
		"family":         "application_graph",
		"tenant_id":      "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "writer.application_graph" {
		t.Fatalf("Kind = %q, want writer.application_graph", event.Kind)
	}
	if got := event.Attributes["application_id"]; got != "app_1" {
		t.Fatalf("application_id = %q, want app_1", got)
	}
	if got := event.Attributes["external_id"]; got != "app_1" {
		t.Fatalf("external_id = %q, want app_1", got)
	}
	if got := event.Attributes["graph_ids"]; got == "" {
		t.Fatalf("graph_ids attribute empty, want serialized graph ids")
	}
}

func TestReadApplicationJobUsesResultListQueryAndOffsetPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/v1/applications/app_1/jobs" {
			t.Fatalf("request path = %q, want /v1/applications/app_1/jobs", got)
		}
		if got := r.URL.Query().Get("limit"); got != "3" {
			t.Fatalf("limit = %q, want 3", got)
		}
		if got := r.URL.Query().Get("offset"); got != "6" {
			t.Fatalf("offset = %q, want 6", got)
		}
		if got := r.URL.Query().Get("status"); got != "failed" {
			t.Fatalf("status = %q, want failed", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":             "job_1",
				"application_id": "app_1",
				"status":         "failed",
				"created_at":     "2026-06-22T10:00:00Z",
				"error":          "input validation failed",
			}},
			"totalCount": 10,
			"pagination": map[string]any{"offset": 6, "limit": 3},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":        "writer-key",
		"application_id": "app_1",
		"base_url":       server.URL,
		"family":         "application_job",
		"offset":         "6",
		"per_page":       "3",
		"status":         "failed",
		"tenant_id":      "writer",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "writer.application_job" {
		t.Fatalf("Kind = %q, want writer.application_job", event.Kind)
	}
	if got := event.Attributes["job_id"]; got != "job_1" {
		t.Fatalf("job_id = %q, want job_1", got)
	}
	if got := event.Attributes["application_id"]; got != "app_1" {
		t.Fatalf("application_id = %q, want app_1", got)
	}
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "9" {
		t.Fatalf("NextCursor = %v, want 9", pull.NextCursor)
	}
}

func TestReadGraphUsesCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("after"); got != "graph_prev" {
			t.Fatalf("after = %q, want graph_prev", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":         "graph_next",
				"name":       "Next Graph",
				"type":       "manual",
				"created_at": "2026-06-22T10:00:00Z",
				"file_status": map[string]any{
					"in_progress": 1,
					"completed":   2,
					"failed":      3,
					"total":       6,
				},
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key":   "writer-key",
		"base_url":  server.URL,
		"family":    "graph",
		"tenant_id": "writer",
	}), &cerebrov1.SourceCursor{Opaque: "graph_prev"})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["file_status_total"]; got != "6" {
		t.Fatalf("file_status_total = %q, want 6", got)
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %v, want nil", pull.NextCursor)
	}
}

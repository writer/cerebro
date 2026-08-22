package catalogruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

const (
	datadogUsers      = "users"
	datadogMonitors   = "monitors"
	datadogSLOs       = "slos"
	datadogDashboards = "dashboards"
	datadogIncidents  = "incidents"
	datadogAudit      = "audit_events"
)

func TestDatadogCatalogRuntimeReplaysCapturedFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		requestPath string
		wantKind    string
	}{
		{family: "users", fixtureCase: "list_users", requestPath: "/api/v2/users", wantKind: "datadog.users"},
		{family: "roles", fixtureCase: "list_roles", requestPath: "/api/v2/roles", wantKind: "datadog.roles"},
		{family: "teams", fixtureCase: "list_teams", requestPath: "/api/v2/team", wantKind: "datadog.teams"},
		{family: "monitors", fixtureCase: "list_monitors", requestPath: "/api/v1/monitor", wantKind: "datadog.monitors"},
		{family: "slos", fixtureCase: "list_slos", requestPath: "/api/v1/slo", wantKind: "datadog.slos"},
		{family: "dashboards", fixtureCase: "list_dashboards", requestPath: "/api/v1/dashboard", wantKind: "datadog.dashboards"},
		{family: "incidents", fixtureCase: "list_incidents", requestPath: "/api/v2/incidents", wantKind: "datadog.incidents"},
		{family: "audit_events", fixtureCase: "list_audit_events", requestPath: "/api/v2/audit/events", wantKind: "datadog.audit_events"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../../..", "datadog", test.family, test.fixtureCase)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertDatadogHeaders(t, r)
				if r.URL.Path != test.requestPath {
					t.Fatalf("request path = %q, want %q", r.URL.Path, test.requestPath)
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source := newDatadogCatalogSource(t)
			cfg := datadogConfig(server.URL, test.family, "100")
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) == 0 || pull.Events[0].Kind != test.wantKind {
				t.Fatalf("Read() events = %#v, want kind %q", pull.Events, test.wantKind)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatal(err)
			}
			fixtureRoot := filepath.Join("..", "..", "datadog")
			if err := sourcefixture.CompareOrUpdateSourceOutputs(fixtureRoot, test.family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDatadogCatalogRuntimeHeadersCursorCheckpointAndTypedError(t *testing.T) {
	requests := []string{}
	failProvider := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertDatadogHeaders(t, r)
		requests = append(requests, r.URL.RawQuery)
		if r.URL.Path == "/api/v1/validate" {
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
			return
		}
		if r.URL.Path != "/api/v2/users" {
			t.Fatalf("request path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("page[size]") != "2" {
			t.Fatalf("page[size] = %q, want 2", r.URL.Query().Get("page[size]"))
		}
		if failProvider {
			http.Error(w, `{"errors":["service unavailable"]}`, http.StatusServiceUnavailable)
			return
		}
		cursor := r.URL.Query().Get("page[cursor]")
		id := "user-1"
		next := "cursor-2"
		if cursor == "cursor-2" {
			id, next = "user-2", ""
		}
		body := map[string]any{"data": []map[string]any{{
			"id": id, "type": "users", "attributes": map[string]any{
				"email": id + "@example.test", "name": id, "created_at": "2026-06-01T00:00:00Z", "modified_at": "2026-06-02T00:00:00Z",
			},
		}}}
		if next != "" {
			body["meta"] = map[string]any{"page": map[string]any{"after": next}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	source := newDatadogCatalogSource(t)
	cfg := datadogConfig(server.URL, datadogUsers, "2")
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if len(first.Events) != 1 || first.Events[0].Attributes["user_id"] != "user-1" || first.Events[0].Attributes["email"] != "user-1@example.test" {
		t.Fatalf("first events = %#v", first.Events)
	}
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, &cerebrov1.SourceCheckpoint{CursorOpaque: "older"})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["user_id"] != "user-2" {
		t.Fatalf("second events = %#v", second.Events)
	}
	if !strings.Contains(requests[len(requests)-1], "page%5Bcursor%5D=cursor-2") {
		t.Fatalf("last request query = %q", requests[len(requests)-1])
	}

	failProvider = true
	_, err = source.Read(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider status error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Read() error = %v, want provider status %d", err, http.StatusServiceUnavailable)
	}
}

func TestDatadogCatalogRuntimePaginationFamilies(t *testing.T) {
	t.Run("monitors page starts at zero", func(t *testing.T) {
		queries := []string{}
		server := datadogTestServer(t, "/api/v1/monitor", func(r *http.Request) any {
			queries = append(queries, r.URL.RawQuery)
			if r.URL.Query().Get("page_size") != "2" {
				t.Fatalf("page_size = %q", r.URL.Query().Get("page_size"))
			}
			if r.URL.Query().Get("page") == "0" {
				return []map[string]any{{"id": 1, "name": "one", "type": "query alert"}, {"id": 2, "name": "two", "type": "query alert"}}
			}
			return []map[string]any{{"id": 3, "name": "three", "type": "query alert"}}
		})
		defer server.Close()
		assertTwoPageRead(t, server.URL, datadogMonitors, "1")
		if len(queries) != 2 || !strings.Contains(queries[0], "page=0") || !strings.Contains(queries[1], "page=1") {
			t.Fatalf("queries = %#v", queries)
		}
	})

	t.Run("slo offset advances by limit", func(t *testing.T) {
		server := datadogTestServer(t, "/api/v1/slo", func(r *http.Request) any {
			offset := r.URL.Query().Get("offset")
			if r.URL.Query().Get("limit") != "2" {
				t.Fatalf("limit = %q", r.URL.Query().Get("limit"))
			}
			if offset == "" {
				return datadogSLOPage([]string{"slo-1", "slo-2"}, 0, 2, 3)
			}
			if offset != "2" {
				t.Fatalf("offset = %q", offset)
			}
			return datadogSLOPage([]string{"slo-3"}, 2, 2, 3)
		})
		defer server.Close()
		assertTwoPageRead(t, server.URL, datadogSLOs, "2")
	})

	t.Run("dashboard start advances by count", func(t *testing.T) {
		server := datadogTestServer(t, "/api/v1/dashboard", func(r *http.Request) any {
			start := r.URL.Query().Get("start")
			if r.URL.Query().Get("count") != "2" {
				t.Fatalf("count = %q", r.URL.Query().Get("count"))
			}
			if start == "0" {
				return map[string]any{"dashboards": []map[string]any{{"id": "d1", "title": "one"}, {"id": "d2", "title": "two"}}}
			}
			if start != "2" {
				t.Fatalf("start = %q", start)
			}
			return map[string]any{"dashboards": []map[string]any{{"id": "d3", "title": "three"}}}
		})
		defer server.Close()
		assertTwoPageRead(t, server.URL, datadogDashboards, "2")
	})

	t.Run("incident offset cursor", func(t *testing.T) {
		server := datadogTestServer(t, "/api/v2/incidents", func(r *http.Request) any {
			cursor := r.URL.Query().Get("page[offset]")
			if r.URL.Query().Get("page[size]") != "2" {
				t.Fatalf("page[size] = %q", r.URL.Query().Get("page[size]"))
			}
			if cursor == "" {
				return datadogV2Page("incidents", []string{"i1", "i2"}, map[string]any{"pagination": map[string]any{"next_offset": "2"}})
			}
			if cursor != "2" {
				t.Fatalf("page[offset] = %q", cursor)
			}
			return datadogV2Page("incidents", []string{"i3"}, nil)
		})
		defer server.Close()
		assertTwoPageRead(t, server.URL, datadogIncidents, "2")
	})

	t.Run("audit cursor follows links next and limit", func(t *testing.T) {
		var serverURL string
		server := datadogTestServer(t, "/api/v2/audit/events", func(r *http.Request) any {
			cursor := r.URL.Query().Get("page[cursor]")
			if r.URL.Query().Get("page[limit]") != "2" {
				t.Fatalf("page[limit] = %q", r.URL.Query().Get("page[limit]"))
			}
			if cursor == "" {
				page := datadogV2Page("audit_events", []string{"a1", "a2"}, nil)
				page["links"] = map[string]any{"next": serverURL + "/api/v2/audit/events?page%5Bcursor%5D=cursor-2&page%5Blimit%5D=2"}
				return page
			}
			if cursor != "cursor-2" {
				t.Fatalf("page[cursor] = %q", cursor)
			}
			return datadogV2Page("audit_events", []string{"a3"}, nil)
		})
		serverURL = server.URL
		defer server.Close()
		first := readDatadog(t, server.URL, datadogAudit, nil)
		if first.NextCursor == nil || !strings.Contains(first.NextCursor.GetOpaque(), "cursor-2") {
			t.Fatalf("NextCursor = %#v", first.NextCursor)
		}
		second := readDatadog(t, server.URL, datadogAudit, first.NextCursor)
		if len(second.Events) != 1 || second.NextCursor != nil {
			t.Fatalf("second pull = %#v", second)
		}
	})
}

func newDatadogCatalogSource(t *testing.T) *Source {
	t.Helper()
	entry, found, err := connectorcatalog.BuiltinEntry("datadog")
	if err != nil || !found {
		t.Fatalf("BuiltinEntry(datadog) found=%v error=%v", found, err)
	}
	source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewDefinitionWithValidationOptions(datadog) error = %v", err)
	}
	return source
}

func datadogConfig(baseURL, family, perPage string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant", "base_url": baseURL, "family": family, "api_key": "api-key", "application_key": "app-key", "per_page": perPage,
	})
}

func assertDatadogHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("DD-API-KEY") != "api-key" || r.Header.Get("DD-APPLICATION-KEY") != "app-key" {
		t.Fatalf("Datadog auth headers = %q/%q", r.Header.Get("DD-API-KEY"), r.Header.Get("DD-APPLICATION-KEY"))
	}
}

func datadogTestServer(t *testing.T, path string, response func(*http.Request) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertDatadogHeaders(t, r)
		if r.URL.Path != path {
			t.Fatalf("request path = %q, want %q", r.URL.Path, path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response(r))
	}))
}

func readDatadog(t *testing.T, baseURL, family string, cursor *cerebrov1.SourceCursor) sourcecdk.Pull {
	t.Helper()
	pull, err := newDatadogCatalogSource(t).Read(context.Background(), datadogConfig(baseURL, family, "2"), cursor)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", family, err)
	}
	return pull
}

func assertTwoPageRead(t *testing.T, baseURL, family, wantCursor string) {
	t.Helper()
	first := readDatadog(t, baseURL, family, nil)
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != wantCursor || len(first.Events) != 2 {
		t.Fatalf("first pull = %#v, want cursor %q and 2 events", first, wantCursor)
	}
	second := readDatadog(t, baseURL, family, first.NextCursor)
	if second.NextCursor != nil || len(second.Events) != 1 {
		t.Fatalf("second pull = %#v, want terminal 1 event", second)
	}
}

func datadogSLOPage(ids []string, offset, limit, total int) map[string]any {
	data := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]any{"id": id, "name": id, "type": "monitor"})
	}
	return map[string]any{"data": data, "metadata": map[string]any{"page": map[string]any{"offset": offset, "limit": limit, "total_count": total}}}
}

func datadogV2Page(family string, ids []string, meta map[string]any) map[string]any {
	data := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		attributes := map[string]any{"title": id, "state": "active", "created": "2026-06-01T00:00:00Z"}
		if family == "audit_events" {
			attributes = map[string]any{"timestamp": "2026-06-01T00:00:00Z", "evt": map[string]any{"name": "role.updated"}}
		}
		data = append(data, map[string]any{"id": id, "type": family, "attributes": attributes})
	}
	out := map[string]any{"data": data}
	if meta != nil {
		out["meta"] = meta
	}
	return out
}

package datadog

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

func TestSourceCheckReadAndCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got != "api-key" {
			t.Fatalf("DD-API-KEY = %q", got)
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got != "app-key" {
			t.Fatalf("DD-APPLICATION-KEY = %q", got)
		}
		requests = append(requests, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case defaultHealthPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
		case "/api/v2/users":
			if got := r.URL.Query().Get("page[size]"); got != "2" {
				t.Fatalf("page[size] = %q, want 2", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":   "user-1",
					"type": "users",
					"attributes": map[string]any{
						"email":       "alice@example.test",
						"name":        "Alice Example",
						"handle":      "alice@example.test",
						"status":      "Active",
						"disabled":    false,
						"verified":    true,
						"created_at":  "2026-06-01T00:00:00Z",
						"modified_at": "2026-06-02T00:00:00Z",
					},
				}},
				"meta": map[string]any{"page": map[string]any{"after": "cursor-2"}},
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := datadogTestConfig(server.URL, familyUsers)
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
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("NextCursor = %#v, want cursor-2", pull.NextCursor)
	}
	event := pull.Events[0]
	if event.Kind != "datadog.users" || event.SchemaRef != "datadog/users/v1" {
		t.Fatalf("event kind/schema = %q/%q", event.Kind, event.SchemaRef)
	}
	if got := event.Attributes["email"]; got != "alice@example.test" {
		t.Fatalf("email attribute = %q", got)
	}
	assertDatadogEventContracts(t, source, event)
	if _, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "cursor-2"}); err != nil {
		t.Fatalf("Read(cursor) error = %v", err)
	}
	if len(requests) < 3 || !strings.Contains(requests[len(requests)-1], "page%5Bcursor%5D=cursor-2") {
		t.Fatalf("last query = %q, want encoded page cursor", requests[len(requests)-1])
	}
}

func TestSourceReadWithCheckpointUsesCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got != "api-key" {
			t.Fatalf("DD-API-KEY = %q", got)
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got != "app-key" {
			t.Fatalf("DD-APPLICATION-KEY = %q", got)
		}
		if r.URL.Path != "/api/v2/users" {
			t.Fatalf("request path = %q, want /api/v2/users", r.URL.Path)
		}
		if got := r.URL.Query().Get("page[size]"); got != "2" {
			t.Fatalf("page[size] = %q, want 2", got)
		}
		if got := r.URL.Query().Get("page[cursor]"); got != "cursor-2" {
			t.Fatalf("page[cursor] = %q, want cursor-2", got)
		}
		requests = append(requests, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":   "user-2",
				"type": "users",
				"attributes": map[string]any{
					"email":       "bob@example.test",
					"name":        "Bob Example",
					"created_at":  "2026-06-01T00:00:00Z",
					"modified_at": "2026-06-02T00:00:00Z",
				},
			}},
		})
	}))
	defer server.Close()

	pull, err := source.ReadWithCheckpoint(
		context.Background(),
		datadogTestConfig(server.URL, familyUsers),
		&cerebrov1.SourceCursor{Opaque: "cursor-2"},
		&cerebrov1.SourceCheckpoint{CursorOpaque: "older"},
	)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["user_id"]; got != "user-2" {
		t.Fatalf("user_id attribute = %q, want user-2", got)
	}
	if len(requests) != 1 || !strings.Contains(requests[0], "page%5Bcursor%5D=cursor-2") {
		t.Fatalf("requests = %#v, want encoded page cursor", requests)
	}
	assertDatadogEventContracts(t, source, pull.Events[0])
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/users" {
			t.Fatalf("request path = %q, want /api/v2/users", r.URL.Path)
		}
		http.Error(w, `{"errors":["service unavailable"]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), datadogTestConfig(server.URL, familyUsers), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if !strings.Contains(err.Error(), "datadog API returned 503") {
		t.Fatalf("Read() error = %v, want datadog API returned 503", err)
	}
}

func TestSourceMapsRuntimeFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/roles":
			_ = json.NewEncoder(w).Encode(v2List("role-1", "roles", map[string]any{"name": "Datadog Admin", "description": "Full administration"}))
		case "/api/v2/team":
			_ = json.NewEncoder(w).Encode(v2List("team-1", "team", map[string]any{"name": "Platform", "handle": "platform", "description": "Platform owners"}))
		case "/api/v1/monitor":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 123, "name": "Latency", "type": "query alert", "query": "avg(last_5m):...", "overall_state": "OK", "tags": []string{"service:payments", "team:platform"}}})
		case "/api/v1/slo":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "slo-1", "name": "Checkout availability", "type": "monitor", "target_threshold": 99.9, "monitor_ids": []int{123}, "tags": []string{"service:checkout", "team:platform"}}}})
		case "/api/v1/dashboard":
			_ = json.NewEncoder(w).Encode(map[string]any{"dashboards": []map[string]any{{"id": "dash-1", "title": "Payments", "description": "Payment health", "author_handle": "alice@example.test", "tags": []string{"service:payments"}}}})
		case "/api/v2/incidents":
			_ = json.NewEncoder(w).Encode(v2ListWithRelationships("inc-1", "incidents", map[string]any{"title": "Checkout outage", "state": "active", "severity": "SEV-2", "created": "2026-06-01T00:00:00Z", "service": "checkout"}, map[string]any{
				"commander_user": map[string]any{"data": map[string]any{"id": "user-1", "type": "users"}},
				"teams":          map[string]any{"data": []map[string]any{{"id": "team-1", "type": "team"}, {"id": "team-2", "type": "team"}}},
			}))
		case "/api/v2/audit/events":
			_ = json.NewEncoder(w).Encode(v2List("audit-1", "audit_events", map[string]any{"timestamp": "2026-06-01T00:00:00Z", "evt": map[string]any{"name": "role.updated"}, "usr": map[string]any{"id": "user-1", "email": "alice@example.test"}, "resource": map[string]any{"id": "role-1", "name": "Datadog Admin", "type": "role"}}))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	tests := []struct {
		family string
		kind   string
		attrs  map[string]string
	}{
		{family: familyRoles, kind: "datadog.roles", attrs: map[string]string{"role_id": "role-1", "name": "Datadog Admin"}},
		{family: familyTeams, kind: "datadog.teams", attrs: map[string]string{"team_id": "team-1", "handle": "platform"}},
		{family: familyMonitors, kind: "datadog.monitors", attrs: map[string]string{"monitor_id": "123", "type": "query alert", "tags": "service:payments,team:platform"}},
		{family: familySLOs, kind: "datadog.slos", attrs: map[string]string{"slo_id": "slo-1", "monitor_ids": "123"}},
		{family: familyDashboards, kind: "datadog.dashboards", attrs: map[string]string{"dashboard_id": "dash-1", "title": "Payments"}},
		{family: familyIncidents, kind: "datadog.incidents", attrs: map[string]string{"incident_id": "inc-1", "state": "active", "service": "checkout", "commander_user_id": "user-1", "team_id": "team-1,team-2"}},
		{family: familyAudit, kind: "datadog.audit_events", attrs: map[string]string{"audit_id": "audit-1", "event_type": "role.updated", "actor_email": "alice@example.test"}},
	}
	contracts := datadogEventContracts(t, source)
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), datadogTestConfig(server.URL, tt.family), nil)
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
			assertEventContracts(t, contracts, event)
			for key, want := range tt.attrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestSourceReadsSLOOffsetPagesFromMetadata(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		if r.URL.Path != "/api/v1/slo" {
			t.Fatalf("request path = %q, want /api/v1/slo", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit query = %q, want 1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("offset") {
		case "":
			_ = json.NewEncoder(w).Encode(sloList("slo-1", 0, 1, 2))
		case "1":
			_ = json.NewEncoder(w).Encode(sloList("slo-2", 1, 1, 2))
		default:
			t.Fatalf("offset query = %q, want empty or 1", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":       "tenant",
		"base_url":        server.URL,
		"family":          familySLOs,
		"api_key":         "api-key",
		"application_key": "app-key",
		"per_page":        "1",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "1" {
		t.Fatalf("first NextCursor = %#v, want 1", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["slo_id"] != "slo-2" {
		t.Fatalf("second Events = %#v, want slo-2", second.Events)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "offset=1") {
		t.Fatalf("requests = %#v, want second request with offset=1", requests)
	}
	contracts := datadogEventContracts(t, source)
	assertEventContracts(t, contracts, first.Events[0])
	assertEventContracts(t, contracts, second.Events[0])
}

func TestSourceReadsDashboardStartPages(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		if r.URL.Path != "/api/v1/dashboard" {
			t.Fatalf("request path = %q, want /api/v1/dashboard", r.URL.Path)
		}
		if got := r.URL.Query().Get("count"); got != "2" {
			t.Fatalf("count query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("start") {
		case "0":
			_ = json.NewEncoder(w).Encode(dashboardList("dash-1", "dash-2"))
		case "2":
			_ = json.NewEncoder(w).Encode(dashboardList("dash-3"))
		default:
			t.Fatalf("start query = %q, want 0 or 2", r.URL.Query().Get("start"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":       "tenant",
		"base_url":        server.URL,
		"family":          familyDashboards,
		"api_key":         "api-key",
		"application_key": "app-key",
		"per_page":        "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %#v, want 2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["dashboard_id"] != "dash-3" {
		t.Fatalf("second Events = %#v, want dash-3", second.Events)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "start=2") {
		t.Fatalf("requests = %#v, want second request with start=2", requests)
	}
	contracts := datadogEventContracts(t, source)
	for _, event := range append(first.Events, second.Events...) {
		assertEventContracts(t, contracts, event)
	}
}

func TestSourceReadsIncidentOffsetPages(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		if r.URL.Path != "/api/v2/incidents" {
			t.Fatalf("request path = %q, want /api/v2/incidents", r.URL.Path)
		}
		if got := r.URL.Query().Get("page[size]"); got != "2" {
			t.Fatalf("page[size] query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page[offset]") {
		case "":
			_ = json.NewEncoder(w).Encode(incidentList([]string{"inc-1", "inc-2"}, "2"))
		case "2":
			_ = json.NewEncoder(w).Encode(incidentList([]string{"inc-3"}, ""))
		default:
			t.Fatalf("page[offset] query = %q, want empty or 2", r.URL.Query().Get("page[offset]"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":       "tenant",
		"base_url":        server.URL,
		"family":          familyIncidents,
		"api_key":         "api-key",
		"application_key": "app-key",
		"per_page":        "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %#v, want 2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["incident_id"] != "inc-3" {
		t.Fatalf("second Events = %#v, want inc-3", second.Events)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "page%5Boffset%5D=2") {
		t.Fatalf("requests = %#v, want second request with page[offset]=2", requests)
	}
	contracts := datadogEventContracts(t, source)
	for _, event := range append(first.Events, second.Events...) {
		assertEventContracts(t, contracts, event)
	}
}

func TestSourceReadsAuditCursorPagesWithLimitParam(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		if r.URL.Path != "/api/v2/audit/events" {
			t.Fatalf("request path = %q, want /api/v2/audit/events", r.URL.Path)
		}
		if got := r.URL.Query().Get("page[limit]"); got != "2" {
			t.Fatalf("page[limit] query = %q, want 2", got)
		}
		if got := r.URL.Query().Get("page[size]"); got != "" {
			t.Fatalf("page[size] query = %q, want empty", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page[cursor]") {
		case "":
			_ = json.NewEncoder(w).Encode(auditList([]string{"audit-1", "audit-2"}, "cursor-2"))
		case "cursor-2":
			_ = json.NewEncoder(w).Encode(auditList([]string{"audit-3"}, ""))
		default:
			t.Fatalf("page[cursor] query = %q, want empty or cursor-2", r.URL.Query().Get("page[cursor]"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":       "tenant",
		"base_url":        server.URL,
		"family":          familyAudit,
		"api_key":         "api-key",
		"application_key": "app-key",
		"per_page":        "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("first NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["audit_id"] != "audit-3" {
		t.Fatalf("second Events = %#v, want audit-3", second.Events)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "page%5Bcursor%5D=cursor-2") {
		t.Fatalf("requests = %#v, want second request with page[cursor]=cursor-2", requests)
	}
	contracts := datadogEventContracts(t, source)
	for _, event := range append(first.Events, second.Events...) {
		assertEventContracts(t, contracts, event)
	}
}

func TestValidateConfigRequiresDatadogKeys(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant"})); err == nil {
		t.Fatal("Check() error = nil, want missing key error")
	}
}

func datadogTestConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"tenant_id":       "tenant",
		"base_url":        baseURL,
		"family":          family,
		"api_key":         "api-key",
		"application_key": "app-key",
		"per_page":        "2",
	})
}

func v2List(id string, typ string, attributes map[string]any) map[string]any {
	return map[string]any{"data": []map[string]any{{"id": id, "type": typ, "attributes": attributes}}}
}

func v2ListWithRelationships(id string, typ string, attributes map[string]any, relationships map[string]any) map[string]any {
	return map[string]any{"data": []map[string]any{{"id": id, "type": typ, "attributes": attributes, "relationships": relationships}}}
}

func sloList(id string, offset int, limit int, total int) map[string]any {
	return map[string]any{
		"data": []map[string]any{{
			"id":               id,
			"name":             "Checkout availability",
			"type":             "monitor",
			"target_threshold": 99.9,
			"monitor_ids":      []int{123},
			"tags":             []string{"service:checkout", "team:platform"},
		}},
		"metadata": map[string]any{"page": map[string]any{"offset": offset, "limit": limit, "total_count": total}},
	}
}

func dashboardList(ids ...string) map[string]any {
	dashboards := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		dashboards = append(dashboards, map[string]any{
			"id":            id,
			"title":         "Payments",
			"description":   "Payment health",
			"author_handle": "alice@example.test",
			"tags":          []string{"service:payments"},
		})
	}
	return map[string]any{"dashboards": dashboards}
}

func incidentList(ids []string, nextOffset string) map[string]any {
	incidents := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		incidents = append(incidents, map[string]any{
			"id":   id,
			"type": "incidents",
			"attributes": map[string]any{
				"title":   "Checkout outage",
				"state":   "active",
				"created": "2026-06-01T00:00:00Z",
			},
		})
	}
	out := map[string]any{"data": incidents}
	if strings.TrimSpace(nextOffset) != "" {
		out["meta"] = map[string]any{"pagination": map[string]any{"next_offset": nextOffset}}
	}
	return out
}

func auditList(ids []string, nextCursor string) map[string]any {
	events := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		events = append(events, map[string]any{
			"id":   id,
			"type": "audit_events",
			"attributes": map[string]any{
				"timestamp": "2026-06-01T00:00:00Z",
				"evt":       map[string]any{"name": "role.updated"},
				"usr":       map[string]any{"id": "user-1", "email": "alice@example.test"},
			},
		})
	}
	out := map[string]any{"data": events}
	if strings.TrimSpace(nextCursor) != "" {
		out["meta"] = map[string]any{"page": map[string]any{"after": nextCursor}}
	}
	return out
}

func assertDatadogEventContracts(t *testing.T, source *Source, events ...*cerebrov1.EventEnvelope) {
	t.Helper()
	assertEventContracts(t, datadogEventContracts(t, source), events...)
}

func datadogEventContracts(t *testing.T, source *Source) []sourcecdk.EventContract {
	t.Helper()
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry(datadog) error = %v", err)
	}
	registered, ok := registry.Get(sourceID)
	if !ok {
		t.Fatalf("registry missing source %q", sourceID)
	}
	provider, ok := registered.(sourcecdk.EventContractProvider)
	if !ok {
		t.Fatalf("registered source %T does not expose event contracts", registered)
	}
	contracts := provider.EventContracts()
	if len(contracts) != len(fixtureFamilies) {
		t.Fatalf("EventContracts() = %d contracts, want %d", len(contracts), len(fixtureFamilies))
	}
	return contracts
}

func assertEventContracts(t *testing.T, contracts []sourcecdk.EventContract, events ...*cerebrov1.EventEnvelope) {
	t.Helper()
	for _, event := range events {
		if err := sourcecdk.ValidateEventEnvelopeWithContracts(event, contracts); err != nil {
			t.Fatalf("ValidateEventEnvelopeWithContracts(%s) error = %v; attrs=%#v", event.GetKind(), err, event.GetAttributes())
		}
	}
}

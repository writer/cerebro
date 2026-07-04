package addigy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	t.Run(familyDevices, testSourceCheckAndReadDevices)
	t.Run(familyUsers, testSourceReadsOrganizationUsers)
	t.Run(familyGroups, testSourceReadsEndUserGroups)
	t.Run(familyPolicies, testSourceReadsPoliciesWithStaticPolicyAttributes)
	t.Run(familyAuditEvents, testSourceReadsAuditEvents)
}

func testSourceCheckAndReadDevices(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "test-key" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/devices" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		body := decodeBody(t, r)
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"agentid":    "agent-1",
				"audit_date": "2026-07-01T10:00:00Z",
				"facts": map[string]any{
					"device_name":   map[string]any{"value": "MacBook One"},
					"host_name":     map[string]any{"value": "macbook-one"},
					"serial_number": map[string]any{"value": "C02TEST"},
				},
				"orgid": "org-1",
			}},
			"metadata": map[string]any{"page": 1, "page_count": 2, "per_page": 1, "result_count": 1, "total": 2},
		})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key", "per_page": "1"})
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
	if got := pull.Events[0].Kind; got != "addigy.devices" {
		t.Fatalf("kind = %q", got)
	}
	if got := pull.Events[0].Attributes["resource_name"]; got != "MacBook One" {
		t.Fatalf("resource_name = %q", got)
	}
	requireSourceEventID(t, pull.Events[0].Attributes, "agent-1")
	if pull.NextCursor == nil || sourcecdk.CursorToken(pull.NextCursor) != "2" {
		t.Fatalf("next cursor = %#v, want page 2", pull.NextCursor)
	}
	if len(bodies) < 2 {
		t.Fatalf("captured request bodies = %d, want check and read", len(bodies))
	}
	if bodies[0]["page"].(float64) != 1 || bodies[0]["per_page"].(float64) != 1 {
		t.Fatalf("body = %#v, want page/per_page", bodies[0])
	}
}

func testSourceReadsOrganizationUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/o/org-1/users/query" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":    []map[string]any{{"email": "admin@example.test", "name": "Admin One", "addigy_role": "Owner", "orgid": "org-1"}},
			"metadata": map[string]any{"page": 1, "page_count": 1, "per_page": 100, "result_count": 1, "total": 1},
		})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key", "family": familyUsers, "organization_id": "org-1"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "addigy.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["email"] != "admin@example.test" || event.Attributes["addigy_role"] != "Owner" {
		t.Fatalf("attributes = %#v", event.Attributes)
	}
	requireSourceEventID(t, event.Attributes, "admin@example.test")
}

func testSourceReadsEndUserGroups(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/o/org-1/end-users/groups/query" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Fatalf("x-api-key = %q", r.Header.Get("x-api-key"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"displayName": "Engineering",
				"id":          "group-1",
				"orgid":       "org-1",
			}},
			"metadata": map[string]any{"page": 1, "page_count": 1, "per_page": 100, "result_count": 1, "total": 1},
		})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key", "family": familyGroups, "organization_id": "org-1"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "addigy.groups" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["group_name"] != "Engineering" {
		t.Fatalf("attributes = %#v", event.Attributes)
	}
	requireSourceEventID(t, event.Attributes, "group-1")
}

func testSourceReadsPoliciesWithStaticPolicyAttributes(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oa/policies/query" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %q, want POST", r.Method)
		}
		if body := decodeBody(t, r); len(body) != 0 {
			t.Fatalf("body = %#v, want empty JSON object", body)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"policyId": "policy-1", "name": "Default Policy", "orgid": "org-1"}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key", "family": familyPolicies})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "addigy.policies" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["policy_status"] != "configured" || event.Attributes["policy_type"] != "device_policy" {
		t.Fatalf("policy attributes = %#v", event.Attributes)
	}
	requireSourceEventID(t, event.Attributes, "policy-1")
}

func testSourceReadsAuditEvents(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/system-events/search" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		body := decodeBody(t, r)
		if body["from_date_time"] != "2026-07-01T00:00:00Z" {
			t.Fatalf("from_date_time = %#v", body["from_date_time"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"event_id": "evt-1",
				"date":     "2026-07-01T12:00:00Z",
				"source":   "policies",
				"action": map[string]any{
					"name": "policy.updated",
					"entity": map[string]any{
						"identifier": "policy-1",
						"name":       "Default Policy",
						"type":       "policy",
					},
				},
				"action_sender": map[string]any{"identifier": "admin@example.test", "name": "Admin One"},
				"result":        map[string]any{"status": "success"},
			}},
			"metadata": map[string]any{"page": 1, "page_count": 1, "per_page": 100, "result_count": 1, "total": 1},
		})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key", "family": familyAuditEvents, "audit_start_time": "2026-07-01T00:00:00Z"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "addigy.audit_events" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["event_type"] != "policy.updated" || event.Attributes["resource_id"] != "policy-1" {
		t.Fatalf("attributes = %#v", event.Attributes)
	}
	requireSourceEventID(t, event.Attributes, "evt-1")
}

func TestSourceCheckReportsProviderUnavailable(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "api_key": "test-key"})
	err = source.Check(context.Background(), cfg)
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable failure")
	}
}

func requireSourceEventID(t *testing.T, attrs map[string]string, want string) {
	t.Helper()
	if got := attrs["source_event_id"]; got != want {
		t.Fatalf("source_event_id = %q, want %q in %#v", got, want, attrs)
	}
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	body := map[string]any{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode body %q: %v", strings.TrimSpace(string(raw)), err)
	}
	return body
}

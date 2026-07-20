package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type stubAuditEventReader struct {
	page    ports.AuditEventPageV1
	err     error
	queries []ports.AuditEventQueryV1
}

func (s *stubAuditEventReader) Ping(context.Context) error { return nil }

func (s *stubAuditEventReader) ListAuditEvents(_ context.Context, query ports.AuditEventQueryV1) (ports.AuditEventPageV1, error) {
	s.queries = append(s.queries, query)
	return s.page, s.err
}

func auditEventTestRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "tenant-a"},
	}))
}

func TestHandleListAuditEventsReturnsAllowlistedTenantScopedPage(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	duration := int64(18)
	store := &stubAuditEventReader{page: ports.AuditEventPageV1{
		HasMore: true,
		Events: []*ports.AuditEventV1{{
			ID: "event-1", TenantID: "tenant-a", Action: "record.read", Category: "access",
			OccurredAt: now, Outcome: ports.AuditEventOutcomeSuccess, DurationMS: &duration,
			Actor:    &ports.AuditEventActorV1{ID: "actor-1", Kind: "service", Label: "Service actor"},
			Resource: &ports.AuditEventResourceV1{ID: "resource-1", Type: "record", Label: "Record"},
			Service:  "api", Summary: "Read a record", RequestID: "request-1", TraceID: "trace-1",
		}},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	recorder := httptest.NewRecorder()
	app.handleListAuditEvents(recorder, auditEventTestRequest("/platform/audit-events?minutes=30&limit=1"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	events := response["events"].([]any)
	event := events[0].(map[string]any)
	if _, exists := event["tenant_id"]; exists {
		t.Fatal("response exposed tenant_id")
	}
	if event["trace_id"] != "trace-1" || response["next_cursor"] == "" || response["status"] != "complete" {
		t.Fatalf("response = %#v", response)
	}
	if len(store.queries) != 1 || store.queries[0].TenantID != "tenant-a" || store.queries[0].Limit != 1 {
		t.Fatalf("queries = %+v", store.queries)
	}

	store.page = ports.AuditEventPageV1{Events: []*ports.AuditEventV1{}}
	cursor := response["next_cursor"].(string)
	second := httptest.NewRecorder()
	app.handleListAuditEvents(second, auditEventTestRequest("/platform/audit-events?minutes=30&limit=1&cursor="+url.QueryEscape(cursor)))
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	if len(store.queries) != 2 || store.queries[1].PageBeforeID != "event-1" || !store.queries[1].Before.Equal(store.queries[0].Before) {
		t.Fatalf("cursor query = %+v; first = %+v", store.queries[1], store.queries[0])
	}
}

func TestHandleListAuditEventsPreservesPartialStatus(t *testing.T) {
	store := &stubAuditEventReader{page: ports.AuditEventPageV1{Partial: true, Events: []*ports.AuditEventV1{}}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	recorder := httptest.NewRecorder()
	app.handleListAuditEvents(recorder, auditEventTestRequest("/platform/audit-events"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"partial"`) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleListAuditEventsRejectsCrossTenantAndInvalidBounds(t *testing.T) {
	store := &stubAuditEventReader{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	for _, tc := range []struct {
		name   string
		target string
		want   int
	}{
		{name: "cross tenant", target: "/platform/audit-events?tenant_id=tenant-b", want: http.StatusForbidden},
		{name: "small window", target: "/platform/audit-events?minutes=4", want: http.StatusBadRequest},
		{name: "large limit", target: "/platform/audit-events?limit=501", want: http.StatusBadRequest},
		{name: "invalid outcome", target: "/platform/audit-events?outcome=maybe", want: http.StatusBadRequest},
		{name: "invalid cursor", target: "/platform/audit-events?cursor=not-a-cursor", want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			app.handleListAuditEvents(recorder, auditEventTestRequest(tc.target))
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
	if len(store.queries) != 0 {
		t.Fatalf("invalid requests reached store: %+v", store.queries)
	}
}

func TestHandleListAuditEventsRejectsUnavailableOrWrongTenantReader(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: stubNoAskQueryStore{}}, nil)
	recorder := httptest.NewRecorder()
	app.handleListAuditEvents(recorder, auditEventTestRequest("/platform/audit-events"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d", recorder.Code)
	}
	store := &stubAuditEventReader{err: context.DeadlineExceeded}
	app = New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	recorder = httptest.NewRecorder()
	app.handleListAuditEvents(recorder, auditEventTestRequest("/platform/audit-events"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("reader failure status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	store = &stubAuditEventReader{page: ports.AuditEventPageV1{Events: []*ports.AuditEventV1{{
		ID: "event-1", TenantID: "tenant-b", Action: "record.read", OccurredAt: time.Now(), Outcome: ports.AuditEventOutcomeSuccess,
	}}}}
	app = New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
	recorder = httptest.NewRecorder()
	app.handleListAuditEvents(recorder, auditEventTestRequest("/platform/audit-events"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("wrong-tenant status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestAuditEventRouteRequiresReadScope(t *testing.T) {
	policy := httpRoutePolicyFor(http.MethodGet, "/platform/audit-events")
	if policy.Scope != scopeCosmoSecurityRead || !policy.Static {
		t.Fatalf("policy = %#v", policy)
	}
}

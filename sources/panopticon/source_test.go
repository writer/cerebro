package panopticon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

func TestSpecLoadsFromCatalog(t *testing.T) {
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	spec := src.Spec()
	if spec == nil {
		t.Fatal("Spec() returned nil")
	}
	if spec.Id != sourceID {
		t.Fatalf("Spec().Id = %q, want %q", spec.Id, sourceID)
	}
	wantKinds := map[string]bool{kindAlert: false, kindCase: false, kindIOC: false}
	for _, kind := range spec.EmittedKinds {
		if _, ok := wantKinds[kind]; ok {
			wantKinds[kind] = true
		}
	}
	for kind, seen := range wantKinds {
		if !seen {
			t.Errorf("Spec().EmittedKinds missing %q", kind)
		}
	}
}

func TestParseSettings(t *testing.T) {
	tests := []struct {
		name      string
		values    map[string]string
		loopback  bool
		wantErrIs error
		want      settings
	}{
		{
			name:     "defaults",
			values:   map[string]string{"base_url": "http://127.0.0.1", "token": "token", "tenant_id": "writer"},
			loopback: true,
			want:     settings{family: familyCase, baseURL: "http://127.0.0.1", apiPath: "/api/v2/cases", token: "token", tenantID: "writer", perPage: defaultPageSize},
		},
		{
			name:     "case-family-runtime-page-and-api-key",
			values:   map[string]string{"mode": modeAPI, "family": familyCase, "base_url": "http://127.0.0.1", "api_key": "token", "per_page": "25", "tenant_id": "writer", "runtime_id": "writer-panopticon-cases"},
			loopback: true,
			want:     settings{family: familyCase, baseURL: "http://127.0.0.1", apiPath: "/api/v2/cases", token: "token", tenantID: "writer", runtimeID: "writer-panopticon-cases", perPage: 25},
		},
		{
			name:     "ioc-family-uses-cases-api",
			values:   map[string]string{"family": familyIOC, "base_url": "http://127.0.0.1", "token": "token", "tenant_id": "writer"},
			loopback: true,
			want:     settings{family: familyIOC, baseURL: "http://127.0.0.1", apiPath: "/api/v2/cases", token: "token", tenantID: "writer", perPage: defaultPageSize},
		},
		{
			name:     "runtime-tenant",
			values:   map[string]string{"base_url": "http://127.0.0.1", "token": "token", sourceconfig.RuntimeTenantIDKey: "writer"},
			loopback: true,
			want:     settings{family: familyCase, baseURL: "http://127.0.0.1", apiPath: "/api/v2/cases", token: "token", tenantID: "writer", perPage: defaultPageSize},
		},
		{
			name:   "private-endpoint-allowlist",
			values: map[string]string{"base_url": "https://panopticon.internal.example", "token": "token", "tenant_id": "writer", "private_endpoint_allowlist": "panopticon.internal.example"},
			want: settings{
				family:                   familyCase,
				baseURL:                  "https://panopticon.internal.example",
				apiPath:                  "/api/v2/cases",
				token:                    "token",
				tenantID:                 "writer",
				privateEndpointAllowlist: []string{"panopticon.internal.example"},
				perPage:                  defaultPageSize,
			},
		},
		{name: "missing-base-url", values: map[string]string{"token": "token", "tenant_id": "writer"}, wantErrIs: ErrBaseURLRequired},
		{name: "missing-token", values: map[string]string{"base_url": "https://panopticon.example.com", "tenant_id": "writer"}, wantErrIs: ErrTokenRequired},
		{name: "missing-tenant", values: map[string]string{"base_url": "https://panopticon.example.com", "token": "token"}, wantErrIs: ErrTenantIDRequired},
		{name: "unknown-family", values: map[string]string{"family": "garbage", "base_url": "https://panopticon.example.com", "token": "token", "tenant_id": "writer"}, wantErrIs: ErrUnsupportedFamily},
		{name: "invalid-page-size", values: map[string]string{"base_url": "https://panopticon.example.com", "token": "token", "page_size": "0", "tenant_id": "writer"}, wantErrIs: ErrInvalidPageSize},
		{name: "s3-mode-rejected", values: map[string]string{"mode": "s3", "base_url": "https://panopticon.example.com", "token": "token", "tenant_id": "writer"}, wantErrIs: ErrUnsupportedMode},
		{name: "unsafe-base-url", values: map[string]string{"base_url": "http://169.254.169.254", "token": "token", "tenant_id": "writer"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSettingsWithLoopback(sourcecdk.NewConfig(tc.values), tc.loopback)
			if tc.wantErrIs != nil || tc.name == "unsafe-base-url" {
				if err == nil {
					t.Fatal("parseSettingsWithLoopback() error = nil, want non-nil")
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("parseSettingsWithLoopback() error = %v, want errors.Is %v", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSettingsWithLoopback() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseSettingsWithLoopback() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPrivateEndpointAllowlistFailsClosedWhenCustomTransportCannotPin(t *testing.T) {
	src := &Source{
		lookupIPAddrs: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.20.0.10")}}, nil
		},
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Hostname() != "panopticon.internal.example" {
				t.Fatalf("host = %q, want panopticon.internal.example", req.URL.Hostname())
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: req}, nil
		})},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://panopticon.internal.example/api/v2/alerts", nil)
	resp, err := sourceHTTPClient(src, []string{"panopticon.internal.example"}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, sourcehttp.ErrTransportPinningUnsupported) {
		t.Fatalf("Do() error = %v, want pinned host dialing error", err)
	}
	req, _ = http.NewRequest(http.MethodGet, "https://panopticon.internal.example/api/v2/alerts", nil)
	resp, err = sourceHTTPClient(src, nil).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !errorContains(err, "must not resolve to loopback, private, or link-local") {
		t.Fatalf("Do() error = %v, want private endpoint rejection without allowlist", err)
	}
}

func TestCheckAndDiscoverUseDefaultCasesEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/cases" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("per_page"); got != "1" {
			t.Fatalf("check per_page = %q, want 1", got)
		}
		writePage(w, []map[string]interface{}{validNativeCase("1", fixedTime())}, 1, 0)
	}))
	defer server.Close()

	src := newTestSource(t)
	cfg := apiConfig(server.URL, map[string]string{"per_page": "25"})
	if err := src.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	urns, err := src.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || !strings.Contains(urns[0].String(), "%2Fapi%2Fv2%2Fcases") {
		t.Fatalf("Discover() urns = %v, want cases URN", urns)
	}
}

func TestReadExistingAlertsAPIPaginatesAndMapsNativeFields(t *testing.T) {
	fixed := fixedTime()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("User-Agent"); got != panopticonUserAgent {
			t.Fatalf("User-Agent = %q, want %q", got, panopticonUserAgent)
		}
		if got := r.URL.Query().Get("per_page"); got != "1" {
			t.Fatalf("per_page = %q, want 1", got)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			writePage(w, []map[string]interface{}{validNativeAlert("1", fixed)}, 1, 2)
		case "2":
			writePage(w, []map[string]interface{}{validNativeAlert("2", fixed.Add(time.Minute))}, 2, 0)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	src := newTestSource(t)
	cfg := apiConfig(server.URL, map[string]string{"family": familyAlert, "per_page": "1"})
	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := eventIDs(first.Events); len(got) != 1 || got[0] != "alert-1" || first.NextCursor == nil {
		t.Fatalf("first events/cursor = %v/%v, want alert-1 and cursor", got, first.NextCursor)
	}
	firstCursor := decodeAPICursor(first.NextCursor)
	if firstCursor.Source != cursorSourceAPI || firstCursor.Page != 2 {
		t.Fatalf("first cursor = %+v, want api page 2", firstCursor)
	}

	second, err := src.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if got := eventIDs(second.Events); len(got) != 1 || got[0] != "alert-2" || second.NextCursor != nil {
		t.Fatalf("second events/cursor = %v/%v, want alert-2 without cursor", got, second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.GetWatermark().AsTime() != fixed.Add(time.Minute) {
		t.Fatalf("second checkpoint = %+v, want watermark", second.Checkpoint)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestReadAlertAPIPromotesClosureFields(t *testing.T) {
	fixed := fixedTime()
	observedAt := fixed.Add(30 * time.Minute).Format(time.RFC3339Nano)
	createdAt := fixed.Add(-time.Hour).Format(time.RFC3339Nano)
	closedAt := fixed.Add(2 * time.Hour).Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		alert := validNativeAlert("closed-1", fixed)
		delete(alert, "alert_source_event_time")
		alert["observed_at"] = observedAt
		alert["created_at"] = createdAt
		alert["status"] = map[string]interface{}{"status_name": "closed"}
		alert["close_date"] = closedAt
		alert["updated_at"] = fixed.Add(time.Hour).Format(time.RFC3339Nano)
		alert["case_id"] = "case-1"
		writePage(w, []map[string]interface{}{alert}, 1, 0)
	}))
	defer server.Close()

	src := newTestSource(t)
	pull, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": familyAlert, "runtime_id": "writer-panopticon-alerts"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want one alert event", len(pull.Events))
	}
	attrs := pull.Events[0].GetAttributes()
	if got := attrs["status"]; got != "closed" {
		t.Fatalf("status = %q, want closed", got)
	}
	if got := attrs["closed_at"]; got != closedAt {
		t.Fatalf("closed_at = %q, want %q", got, closedAt)
	}
	if got := attrs["observed_at"]; got != observedAt {
		t.Fatalf("observed_at = %q, want %q", got, observedAt)
	}
	if got := attrs["created_at"]; got != createdAt {
		t.Fatalf("created_at = %q, want %q", got, createdAt)
	}
	if got := attrs["case_id"]; got != "case-1" {
		t.Fatalf("case_id = %q, want case-1", got)
	}
	if got := attrs["runtime_id"]; got != "writer-panopticon-alerts" {
		t.Fatalf("runtime_id = %q, want writer-panopticon-alerts", got)
	}
	if got := attrs[ports.EventAttributeSourceRuntimeID]; got != "writer-panopticon-alerts" {
		t.Fatalf("source_runtime_id = %q, want writer-panopticon-alerts", got)
	}
}

func TestReadCaseAPIPromotesResolvedAt(t *testing.T) {
	fixed := fixedTime()
	resolvedAt := fixed.Add(3 * time.Hour).Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		item := validNativeCase("resolved-1", fixed)
		item["resolved_date"] = resolvedAt
		writePage(w, []map[string]interface{}{item}, 1, 0)
	}))
	defer server.Close()

	src := newTestSource(t)
	pull, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": familyCase}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want one case event", len(pull.Events))
	}
	if got := pull.Events[0].GetAttributes()["resolved_at"]; got != resolvedAt {
		t.Fatalf("resolved_at = %q, want %q", got, resolvedAt)
	}
}

func TestReadExistingCasesAndIOCsAPI(t *testing.T) {
	fixed := fixedTime()
	for _, tc := range []struct {
		family string
		kind   string
	}{
		{familyCase, kindCase},
		{familyIOC, kindIOC},
	} {
		t.Run(tc.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v2/cases":
					writePage(w, []map[string]interface{}{validNativeCase("42", fixed)}, 1, 0)
				case "/api/v2/cases/42/iocs":
					writePage(w, []map[string]interface{}{validNativeIOC("7")}, 1, 0)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			src := newTestSource(t)
			pull, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": tc.family}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 || pull.Events[0].GetKind() != tc.kind {
				t.Fatalf("events = %v, want one %s event", pull.Events, tc.kind)
			}
		})
	}
}

func TestReadAPIRejectsInvalidNativeRecordsAndHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePage(w, []map[string]interface{}{{"alert_id": "1"}}, 1, 0)
	}))
	defer server.Close()

	src := newTestSource(t)
	_, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": familyAlert}), nil)
	if err == nil || !errorContains(err, "occurred_at") {
		t.Fatalf("Read() error = %v, want occurred_at validation", err)
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err = src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": familyAlert}), nil)
	if err == nil || !errorContains(err, "status 401") {
		t.Fatalf("Read() error = %v, want HTTP status error", err)
	}
}

func TestReadCasesPreservesEvidenceReferencesForCorrelation(t *testing.T) {
	fixed := fixedTime()
	caseItem := validNativeCase("88", fixed)
	caseItem["evidence"] = []map[string]interface{}{
		{
			"evidence_id":  "evidence-1",
			"evidence_cas": "evidencecas://cases/88/evidence/triage.tar",
			"sha256":       "sha256:abc",
		},
		{
			"uri":    "evidencecas://cases/88/evidence/timeline.json",
			"digest": "sha256:def",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/cases" {
			http.NotFound(w, r)
			return
		}
		writePage(w, []map[string]interface{}{caseItem}, 1, 0)
	}))
	defer server.Close()

	src := newTestSource(t)
	pull, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"family": familyCase}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1 case event", len(pull.Events))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(pull.Events[0].GetPayload(), &payload); err != nil {
		t.Fatalf("decode case payload: %v", err)
	}
	evidence, ok := payload["evidence"].([]interface{})
	if !ok || len(evidence) != 2 {
		t.Fatalf("case payload evidence = %#v, want 2 preserved references", payload["evidence"])
	}
	first, ok := evidence[0].(map[string]interface{})
	if !ok || first["evidence_id"] != "evidence-1" || first["evidence_cas"] != "evidencecas://cases/88/evidence/triage.tar" {
		t.Fatalf("first evidence reference = %#v, want Evidence CAS correlation identifiers preserved", evidence[0])
	}
}

func newTestSource(t *testing.T) *Source {
	t.Helper()
	src, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	src.allowLoopbackBaseURL = true
	return src
}

func apiConfig(baseURL string, overrides map[string]string) sourcecdk.Config {
	values := map[string]string{"base_url": baseURL, "token": "api-token", "tenant_id": "writer"}
	for key, value := range overrides {
		values[key] = value
	}
	return sourcecdk.NewConfig(values)
}

func writePage(w http.ResponseWriter, data []map[string]interface{}, currentPage, nextPage int) {
	payload := map[string]interface{}{
		"total":        len(data),
		"data":         data,
		"last_page":    currentPage,
		"current_page": currentPage,
		"next_page":    nil,
	}
	if nextPage > 0 {
		payload["next_page"] = nextPage
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
}

func validNativeAlert(id string, occurredAt time.Time) map[string]interface{} {
	return map[string]interface{}{
		"alert_id":                id,
		"alert_title":             "Suspicious activity",
		"alert_source_event_time": occurredAt.Format(time.RFC3339Nano),
		"severity":                map[string]interface{}{"severity_name": "high"},
		"status":                  map[string]interface{}{"status_name": "open"},
	}
}

func validNativeCase(id string, occurredAt time.Time) map[string]interface{} {
	return map[string]interface{}{
		"case_id":      id,
		"case_name":    "Incident case",
		"initial_date": occurredAt.Format(time.RFC3339Nano),
		"state":        map[string]interface{}{"state_name": "investigating"},
	}
}

func validNativeIOC(id string) map[string]interface{} {
	return map[string]interface{}{
		"ioc_id":    id,
		"ioc_value": "evil.example",
		"ioc_type":  map[string]interface{}{"type_name": "domain"},
	}
}

func errorContains(err error, want string) bool {
	return strings.Contains(fmt.Sprint(err), want)
}

func eventIDs(events []*cerebrov1.EventEnvelope) []string {
	ids := make([]string, 0, len(events))
	for _, ev := range events {
		ids = append(ids, ev.GetId())
	}
	return ids
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

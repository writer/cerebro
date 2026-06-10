package panopticon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
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
			want:     settings{family: familyAlert, baseURL: "http://127.0.0.1", apiPath: "/api/cerebro/alerts", token: "token", tenantID: "writer", perPage: defaultPageSize},
		},
		{
			name:     "case-family-runtime-page-and-api-key",
			values:   map[string]string{"mode": modeAPI, "family": familyCase, "base_url": "http://127.0.0.1", "api_key": "token", "per_page": "25", "tenant_id": "writer", "runtime_id": "writer-panopticon-cases"},
			loopback: true,
			want:     settings{family: familyCase, baseURL: "http://127.0.0.1", apiPath: "/api/cerebro/cases", token: "token", tenantID: "writer", runtimeID: "writer-panopticon-cases", perPage: 25},
		},
		{
			name:     "runtime-tenant",
			values:   map[string]string{"base_url": "http://127.0.0.1", "token": "token", sourceconfig.RuntimeTenantIDKey: "writer"},
			loopback: true,
			want:     settings{family: familyAlert, baseURL: "http://127.0.0.1", apiPath: "/api/cerebro/alerts", token: "token", tenantID: "writer", perPage: defaultPageSize},
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
			if got != tc.want {
				t.Fatalf("parseSettingsWithLoopback() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestCheckAndDiscoverUseAPIEndpoint(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/alerts" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("check limit = %q, want 1", got)
		}
		_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Records: []panopticonRecord{validAlert("alert-1", fixed)}})
	}))
	defer server.Close()

	src := newTestSource(t)
	cfg := apiConfig(server.URL, map[string]string{"per_page": "1"})
	if err := src.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	urns, err := src.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || !strings.Contains(urns[0].String(), "panopticon") {
		t.Fatalf("Discover() urns = %v, want Panopticon URN", urns)
	}
}

func TestReadAPIPaginatesAndValidatesEvents(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cerebro/alerts" {
			http.NotFound(w, r)
			return
		}
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		if got := r.URL.Query().Get("tenant_id"); got != "writer" {
			t.Fatalf("tenant_id = %q, want writer", got)
		}
		if got := r.URL.Query().Get("family"); got != familyAlert {
			t.Fatalf("family = %q, want %q", got, familyAlert)
		}
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			_ = json.NewEncoder(w).Encode(panopticonAPIResponse{
				Records:    []panopticonRecord{validAlert("alert-1", fixed)},
				NextCursor: "page-2",
				Watermark:  fixed.Format(time.RFC3339Nano),
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(panopticonAPIResponse{
				Records:   []panopticonRecord{validAlert("alert-2", fixed.Add(time.Minute))},
				Watermark: fixed.Add(time.Minute).Format(time.RFC3339Nano),
			})
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	src := newTestSource(t)
	cfg := apiConfig(server.URL, map[string]string{"per_page": "1"})
	first, err := src.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := eventIDs(first.Events); len(got) != 1 || got[0] != "alert-1" || first.NextCursor == nil {
		t.Fatalf("first events/cursor = %v/%v, want alert-1 and cursor", got, first.NextCursor)
	}
	firstCursor := decodeAPICursor(first.NextCursor)
	if firstCursor.Source != cursorSourceAPI || firstCursor.Cursor != "page-2" {
		t.Fatalf("first cursor = %+v, want api cursor page-2", firstCursor)
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

func TestReadAPIAcceptsEventsResponseAndAllFamilies(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		family string
		path   string
		record panopticonRecord
		kind   string
	}{
		{familyAlert, "/api/cerebro/alerts", validAlert("alert-1", fixed), kindAlert},
		{familyCase, "/api/cerebro/cases", validCase("case-1", fixed), kindCase},
		{familyIOC, "/api/cerebro/iocs", validIOC("ioc-1", fixed), kindIOC},
	} {
		t.Run(tc.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Events: []panopticonRecord{tc.record}})
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

func TestReadAPIFiltersRuntimeID(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("runtime_id"); got != "writer-panopticon-alerts" {
			t.Fatalf("runtime_id query = %q, want writer-panopticon-alerts", got)
		}
		_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Records: []panopticonRecord{
			withRuntime(validAlert("other-runtime", fixed), "writer-panopticon-cases"),
			withRuntime(validAlert("accepted", fixed), "writer-panopticon-alerts"),
		}})
	}))
	defer server.Close()

	src := newTestSource(t)
	pull, err := src.Read(context.Background(), apiConfig(server.URL, map[string]string{"runtime_id": "writer-panopticon-alerts"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := eventIDs(pull.Events); len(got) != 1 || got[0] != "accepted" {
		t.Fatalf("events = %v, want [accepted]", got)
	}
}

func TestReadAPIRejectsCrossTenantEvents(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Records: []panopticonRecord{withTenant(validAlert("alert-1", fixed), "other")}})
	}))
	defer server.Close()

	src := newTestSource(t)
	_, err := src.Read(context.Background(), apiConfig(server.URL, nil), nil)
	if err == nil || !errorContains(err, "does not match runtime tenant") {
		t.Fatalf("Read() error = %v, want cross-tenant rejection", err)
	}
}

func TestReadAPIRejectsInvalidEnvelopesAndFamilyContracts(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		record panopticonRecord
		want   string
	}{
		{"wrong-source", withSource(validAlert("alert-1", fixed), "other"), "source_id"},
		{"unsupported-kind", withKind(validAlert("alert-1", fixed), kindCase, schemaRefCase), "kind"},
		{"schema-mismatch", withKind(validAlert("alert-1", fixed), kindAlert, "panopticon/alert/v2"), "schema_ref"},
		{"missing-tenant", withTenant(validAlert("alert-1", fixed), ""), "tenant_id"},
		{"blank-tenant", withTenant(validAlert("alert-1", fixed), "  "), "tenant_id"},
		{"missing-title", withoutPayloadField(validAlert("alert-1", fixed), "title"), "title"},
		{"empty-required-attribute", withAttribute(validAlert("alert-1", fixed), "severity", ""), "severity"},
		{"mismatched-attribute-payload", withAttribute(validAlert("alert-1", fixed), "status", "closed"), "does not match"},
		{"missing-payload", panopticonRecord{ID: "alert-1", TenantID: "writer", SourceID: sourceID, Kind: kindAlert, OccurredAt: fixed, SchemaRef: schemaRefAlert, Attributes: map[string]string{"alert_id": "a-1", "severity": "high", "status": "open"}}, "payload"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Records: []panopticonRecord{tc.record}})
			}))
			defer server.Close()

			src := newTestSource(t)
			_, err := src.Read(context.Background(), apiConfig(server.URL, nil), nil)
			if err == nil || !errorContains(err, tc.want) {
				t.Fatalf("Read() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestReadAPIRejectsTooManyRecordsAndHTTPError(t *testing.T) {
	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	tooMany := make([]panopticonRecord, maxEventsPerPull+1)
	for i := range tooMany {
		tooMany[i] = validAlert(fmt.Sprintf("alert-%04d", i), fixed)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(panopticonAPIResponse{Records: tooMany})
	}))
	defer server.Close()

	src := newTestSource(t)
	_, err := src.Read(context.Background(), apiConfig(server.URL, nil), nil)
	if err == nil || !errorContains(err, "max") {
		t.Fatalf("Read() error = %v, want max records rejection", err)
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err = src.Read(context.Background(), apiConfig(server.URL, nil), nil)
	if err == nil || !errorContains(err, "status 401") {
		t.Fatalf("Read() error = %v, want HTTP status error", err)
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

func errorContains(err error, want string) bool {
	return strings.Contains(fmt.Sprint(err), want)
}

func validAlert(id string, occurredAt time.Time) panopticonRecord {
	alertID := strings.TrimPrefix(id, "alert-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindAlert, OccurredAt: occurredAt, SchemaRef: schemaRefAlert, Attributes: map[string]string{"alert_id": alertID, "severity": "high", "status": "open"}, Payload: map[string]interface{}{"alert_id": alertID, "severity": "high", "status": "open", "title": "Suspicious activity"}}
}

func validCase(id string, occurredAt time.Time) panopticonRecord {
	caseID := strings.TrimPrefix(id, "case-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindCase, OccurredAt: occurredAt, SchemaRef: schemaRefCase, Attributes: map[string]string{"case_id": caseID, "status": "investigating"}, Payload: map[string]interface{}{"case_id": caseID, "status": "investigating", "title": "Incident case", "evidence": []interface{}{map[string]interface{}{"evidence_cas": "cas://object/abc", "sha256": "abc"}}}}
}

func validIOC(id string, occurredAt time.Time) panopticonRecord {
	iocID := strings.TrimPrefix(id, "ioc-")
	return panopticonRecord{ID: id, TenantID: "writer", SourceID: sourceID, Kind: kindIOC, OccurredAt: occurredAt, SchemaRef: schemaRefIOC, Attributes: map[string]string{"ioc_id": iocID, "ioc_type": "domain", "value": "evil.example"}, Payload: map[string]interface{}{"ioc_id": iocID, "ioc_type": "domain", "value": "evil.example"}}
}

func withTenant(rec panopticonRecord, tenant string) panopticonRecord {
	rec.TenantID = tenant
	return rec
}
func withSource(rec panopticonRecord, source string) panopticonRecord {
	rec.SourceID = source
	return rec
}
func withKind(rec panopticonRecord, kind, schemaRef string) panopticonRecord {
	rec.Kind = kind
	rec.SchemaRef = schemaRef
	return rec
}
func withRuntime(rec panopticonRecord, runtimeID string) panopticonRecord {
	rec.Attributes["runtime_id"] = runtimeID
	return rec
}
func withAttribute(rec panopticonRecord, key, value string) panopticonRecord {
	rec.Attributes[key] = value
	return rec
}
func withoutPayloadField(rec panopticonRecord, key string) panopticonRecord {
	delete(rec.Payload, key)
	return rec
}

func eventIDs(events []*cerebrov1.EventEnvelope) []string {
	ids := make([]string, 0, len(events))
	for _, ev := range events {
		ids = append(ids, ev.GetId())
	}
	return ids
}

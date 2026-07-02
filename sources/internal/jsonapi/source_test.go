package jsonapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Duo Admin API HMAC auth requires HMAC-SHA1.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

func TestStableIDPreservesLegacySHA256Digest(t *testing.T) {
	value := "https://api.example.test\x00/api/v1/devices"
	sum := sha256.Sum256([]byte(value))
	wantStableID := hex.EncodeToString(sum[:])[:24]
	if got := stableID(value); got != wantStableID {
		t.Fatalf("stableID() = %q, want %q", got, wantStableID)
	}

	wantEventID := "jsonapi-tenant-a-b587ade5b643-device-dev-1"
	if got := eventID("jsonapi", "tenant-a", "https://api.example.test", "/api/v1/devices", "device", "dev-1"); got != wantEventID {
		t.Fatalf("eventID() = %q, want %q", got, wantEventID)
	}
}

func TestRecordIdentityIncludesFanoutScope(t *testing.T) {
	values := map[string]any{"group_id": "group-a"}
	if got := recordIdentity("user-1", values, nil); got != "user-1" {
		t.Fatalf("recordIdentity() = %q, want unscoped legacy id", got)
	}
	first := recordIdentity("user-1", values, []string{"group_id"})
	second := recordIdentity("user-1", map[string]any{"group_id": "group-b"}, []string{"group_id"})
	if first == second {
		t.Fatalf("recordIdentity() collapsed fanout scopes: %q", first)
	}
	if !strings.HasPrefix(first, "user-1-") || !strings.HasPrefix(second, "user-1-") {
		t.Fatalf("record identities = %q, %q; want stable id prefix", first, second)
	}
}

func TestRecordFromRawUsesIDTemplate(t *testing.T) {
	record, err := recordFromRaw(Family{
		Name:   "audit_logs",
		IDKeys: []string{"created"},
		Config: FamilyConfig{
			IDTemplate:   "${created}-${event}",
			IdentityKeys: []string{"content.user_id"},
		},
	}, json.RawMessage(`{"created":"2026-06-01T00:00:00Z","event":"org.project.create","content":{"user_id":"user-1"}}`))
	if err != nil {
		t.Fatalf("recordFromRaw() error = %v", err)
	}
	if record.ID != "2026-06-01T00:00:00Z-org.project.create" {
		t.Fatalf("record.ID = %q, want templated id", record.ID)
	}
	if got := firstValueString(record.Values, "_record_id"); got != record.ID {
		t.Fatalf("_record_id = %q, want record id %q", got, record.ID)
	}
	if record.Identity == record.ID || !strings.HasPrefix(record.Identity, record.ID+"-") {
		t.Fatalf("record.Identity = %q, want scoped templated identity", record.Identity)
	}
}

func TestMergedRecordOmitsSyntheticRecordIDFromRawPayload(t *testing.T) {
	family := Family{
		Name:   "audit_logs",
		IDKeys: []string{"created"},
		Config: FamilyConfig{
			IDTemplate: "${created}-${event}",
		},
	}
	original, err := recordFromRaw(family, json.RawMessage(`{"created":"2026-06-01T00:00:00Z","event":"org.project.create","summary":"list"}`))
	if err != nil {
		t.Fatalf("recordFromRaw() error = %v", err)
	}
	merged, err := mergedRecord(family, original, json.RawMessage(`{"summary":"detail","actor":"user-1"}`))
	if err != nil {
		t.Fatalf("mergedRecord() error = %v", err)
	}
	if strings.Contains(string(merged.Raw), "_record_id") {
		t.Fatalf("merged raw payload leaked synthetic _record_id: %s", string(merged.Raw))
	}
	if got := firstValueString(merged.Values, "_record_id"); got != original.ID {
		t.Fatalf("_record_id = %q, want original id %q", got, original.ID)
	}
	if got := firstValueString(merged.Values, "summary"); got != "detail" {
		t.Fatalf("summary = %q, want detail", got)
	}
}

func TestParseTimeAcceptsProviderTimestampWithoutTimezone(t *testing.T) {
	got, ok := parseTime("2026-06-01T03:33:51")
	if !ok {
		t.Fatal("parseTime() ok = false, want true")
	}
	want := time.Date(2026, 6, 1, 3, 33, 51, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("parseTime() = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestRecordIdentityRetainsDeviceScopeByDefault(t *testing.T) {
	first := recordIdentity("install-1", map[string]any{"device_id": "device-a"}, nil)
	second := recordIdentity("install-1", map[string]any{"device_id": "device-b"}, nil)
	if first == second {
		t.Fatalf("recordIdentity() collapsed device scopes: %q", first)
	}
}

func TestFirstValueStringReadsArrayCountAndSum(t *testing.T) {
	values := map[string]any{
		"results": []any{
			map[string]any{"input_tokens": json.Number("1200")},
			map[string]any{"input_tokens": json.Number("340")},
		},
	}
	if got := firstValueString(values, "results.__count"); got != "2" {
		t.Fatalf("results.__count = %q, want 2", got)
	}
	if got := firstValueString(values, "results.input_tokens.__sum"); got != "1540" {
		t.Fatalf("results.input_tokens.__sum = %q, want 1540", got)
	}
}

func TestReadPagesJSONAPIRecords(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("Authorization = %q, want Bearer token-1", got)
		}
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit query = %q, want 2", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "2" {
			t.Fatalf("per_page query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cursor") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":         "device-1",
					"name":       "macbook-1",
					"updated_at": "2026-05-01T12:00:00Z",
					"owner": map[string]any{
						"email": "alice@example.com",
					},
				}},
				"next_cursor": "page-2",
			})
		case "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":         "device-2",
					"name":       "macbook-2",
					"updated_at": "2026-05-02T12:00:00Z",
					"owner": map[string]any{
						"email": "bob@example.com",
					},
				}},
			})
		default:
			t.Fatalf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	source := newTestSource(t, server.URL+"/api/v1")
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "device",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
	event := pull.Events[0]
	if event.Kind != "test.device" {
		t.Fatalf("Kind = %q, want test.device", event.Kind)
	}
	if event.TenantId != "writer" {
		t.Fatalf("TenantId = %q, want writer", event.TenantId)
	}
	if event.Attributes["external_id"] != "device-1" {
		t.Fatalf("external_id = %q, want device-1", event.Attributes["external_id"])
	}
	if event.Attributes["owner_email"] != "alice@example.com" {
		t.Fatalf("owner_email = %q, want alice@example.com", event.Attributes["owner_email"])
	}
	if event.Attributes["display_name"] != "macbook-1" {
		t.Fatalf("display_name = %q, want macbook-1", event.Attributes["display_name"])
	}

	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "device",
		"token":     "token-1",
		"per_page":  "2",
	}), &cerebrov1.SourceCursor{Opaque: pull.NextCursor.GetOpaque()})
	if err != nil {
		t.Fatalf("Read(second page) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["external_id"] != "device-2" {
		t.Fatalf("second Events = %#v, want device-2", second.Events)
	}
	if len(requests) != 2 {
		t.Fatalf("request count = %d, want 2", len(requests))
	}
	if got := requests[1].URL.Query().Get("cursor"); got != "page-2" {
		t.Fatalf("second cursor query = %q, want page-2", got)
	}
}

func TestReadPathParamValuesPreservesValueAndProviderCursor(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.EscapedPath()+"?cursor="+r.URL.Query().Get("cursor"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.EscapedPath() == "/accounts/acct-a/devices" && r.URL.Query().Get("cursor") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":        []map[string]any{{"id": "device-a-1"}},
				"next_cursor": "page-2",
			})
		case r.URL.EscapedPath() == "/accounts/acct-a/devices" && r.URL.Query().Get("cursor") == "page-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "device-a-2"}},
			})
		case r.URL.EscapedPath() == "/accounts/acct-b/devices" && r.URL.Query().Get("cursor") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "device-b-1"}},
			})
		default:
			t.Fatalf("request = %s?%s, want configured fan-out page", r.URL.EscapedPath(), r.URL.RawQuery)
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "device",
		Path:           "/accounts/{account_id}/devices",
		PathParams:     []string{"account_id"},
		CursorParam:    "cursor",
		NextCursorKeys: []string{"next_cursor"},
		URNKind:        "test_device",
		IDKeys:         []string{"id"},
		Attributes:     map[string]string{"account_id": "account_id"},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "device",
		"token":     "token-1",
	})
	first, err := source.ReadPathParamValues(context.Background(), cfg, nil, "account_id", []string{"acct-a", "acct-b"})
	if err != nil {
		t.Fatalf("ReadPathParamValues(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.Events[0].Attributes["external_id"] != "device-a-1" {
		t.Fatalf("first Events = %#v, want device-a-1", first.Events)
	}
	firstState := parseFanoutCursor(sourcecdk.CursorToken(first.NextCursor))
	if firstState.Index != 0 || firstState.Cursor != "page-2" {
		t.Fatalf("first fan-out cursor = %#v, want acct-a page-2", firstState)
	}

	second, err := source.ReadPathParamValues(context.Background(), cfg, first.NextCursor, "account_id", []string{"acct-a", "acct-b"})
	if err != nil {
		t.Fatalf("ReadPathParamValues(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["external_id"] != "device-a-2" {
		t.Fatalf("second Events = %#v, want device-a-2", second.Events)
	}
	secondState := parseFanoutCursor(sourcecdk.CursorToken(second.NextCursor))
	if secondState.Index != 1 || secondState.Cursor != "" {
		t.Fatalf("second fan-out cursor = %#v, want acct-b start", secondState)
	}

	third, err := source.ReadPathParamValues(context.Background(), cfg, second.NextCursor, "account_id", []string{"acct-a", "acct-b"})
	if err != nil {
		t.Fatalf("ReadPathParamValues(third) error = %v", err)
	}
	if len(third.Events) != 1 || third.Events[0].Attributes["external_id"] != "device-b-1" {
		t.Fatalf("third Events = %#v, want device-b-1", third.Events)
	}
	if third.NextCursor != nil {
		t.Fatalf("third NextCursor = %#v, want nil", third.NextCursor)
	}
	wantRequests := []string{
		"/accounts/acct-a/devices?cursor=",
		"/accounts/acct-a/devices?cursor=page-2",
		"/accounts/acct-b/devices?cursor=",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
	}
}

func TestReadPathParamValuesWithCheckpointAppliesIncrementalWatermark(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/accounts/acct-a/devices" {
			t.Fatalf("request path = %q, want fan-out path", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "device-a-1", "updated_at": "2026-05-01T00:00:00Z"}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:                 "device",
		Path:                 "/accounts/{account_id}/devices",
		PathParams:           []string{"account_id"},
		URNKind:              "test_device",
		IDKeys:               []string{"id"},
		TimestampKeys:        []string{"updated_at"},
		IncrementalWatermark: true,
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "device",
		"token":     "token-1",
	})
	checkpoint := &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC))}
	pull, err := source.ReadPathParamValuesWithCheckpoint(context.Background(), cfg, nil, checkpoint, "account_id", []string{"acct-a"})
	if err != nil {
		t.Fatalf("ReadPathParamValuesWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("events = %d, want checkpoint-filtered empty pull", len(pull.Events))
	}
}

func TestReadSynthesizesPageCursorForFullPages(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("per_page"); got != "2" {
			t.Fatalf("per_page query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "1":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "enrollment-1"}, {"id": "enrollment-2"}})
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "enrollment-3"}})
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "enrollments",
		Path:            "/enrollments",
		CursorParam:     "page",
		PageSizeParams:  []string{"per_page"},
		PageFirstCursor: "1",
		URNKind:         "test_enrollment",
		IDKeys:          []string{"id"},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests len = %d, want 2", len(requests))
	}
	if got := requests[0].URL.Query().Get("page"); got != "1" {
		t.Fatalf("first page query = %q, want 1", got)
	}
	if got := requests[1].URL.Query().Get("page"); got != "2" {
		t.Fatalf("second page query = %q, want 2", got)
	}
}

func TestReadSynthesizesStartOffsetCursorForFullPages(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("count"); got != "2" {
			t.Fatalf("count query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("start") {
		case "0":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "item-1"}, {"id": "item-2"}}})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "item-3"}}})
		default:
			t.Fatalf("unexpected start %q", r.URL.Query().Get("start"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "items",
		Path:            "/items",
		CursorParam:     "start",
		PageSizeParams:  []string{"count"},
		PageFirstCursor: "0",
		URNKind:         "test_item",
		IDKeys:          []string{"id"},
		ListKeys:        []string{"items"},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := requests[0].URL.Query().Get("start"); got != "0" {
		t.Fatalf("first start query = %q, want 0", got)
	}
	if got := requests[1].URL.Query().Get("start"); got != "2" {
		t.Fatalf("second start query = %q, want 2", got)
	}
}

func TestReadSynthesizesStartAtOffsetCursorForFullPages(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("maxResults"); got != "2" {
			t.Fatalf("maxResults query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("startAt") {
		case "0":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "user-1"}, {"id": "user-2"}})
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "user-3"}})
		default:
			t.Fatalf("unexpected startAt %q", r.URL.Query().Get("startAt"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "users",
		Path:            "/users/search",
		CursorParam:     "startAt",
		PageSizeParams:  []string{"maxResults"},
		PageFirstCursor: "0",
		URNKind:         "test_user",
		IDKeys:          []string{"id"},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := requests[0].URL.Query().Get("startAt"); got != "0" {
		t.Fatalf("first startAt query = %q, want 0", got)
	}
	if got := requests[1].URL.Query().Get("startAt"); got != "2" {
		t.Fatalf("second startAt query = %q, want 2", got)
	}
}

func TestReadUsesSkipOffsetCursorFromResponseMetadata(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit query = %q, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("skip") {
		case "0":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results":    []map[string]any{{"id": "user-1"}, {"id": "user-2"}},
				"skip":       0,
				"limit":      2,
				"totalCount": 4,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results":    []map[string]any{{"id": "user-3"}, {"id": "user-4"}},
				"skip":       2,
				"limit":      2,
				"totalCount": 4,
			})
		default:
			t.Fatalf("unexpected skip %q", r.URL.Query().Get("skip"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "users",
		Path:            "/systemusers",
		CursorParam:     "skip",
		PageSizeParams:  []string{"limit"},
		PageFirstCursor: "0",
		URNKind:         "test_user",
		IDKeys:          []string{"id"},
		ListKeys:        []string{"results"},
		Config:          FamilyConfig{OffsetCursor: true, TotalKeys: []string{"totalCount"}},
	})
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := requests[0].URL.Query().Get("skip"); got != "0" {
		t.Fatalf("first skip query = %q, want 0", got)
	}
	if got := requests[1].URL.Query().Get("skip"); got != "2" {
		t.Fatalf("second skip query = %q, want 2", got)
	}
}

func TestReadTreatsSkipAsPageCursorWithoutOffsetConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit query = %q, want 2", got)
		}
		if got := r.URL.Query().Get("skip"); got != "0" {
			t.Fatalf("skip query = %q, want 0", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "item-1"}, {"id": "item-2"}})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "items",
		Path:            "/items",
		CursorParam:     "skip",
		PageSizeParams:  []string{"limit"},
		PageFirstCursor: "0",
		URNKind:         "test_item",
		IDKeys:          []string{"id"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if pull.NextCursor.GetOpaque() != "1" {
		t.Fatalf("NextCursor = %q, want page-style skip cursor 1", pull.NextCursor.GetOpaque())
	}
}

func TestParseTimeSupportsJiraAuditOffsetTimestamp(t *testing.T) {
	got, ok := parseTime("2026-05-01T12:34:56.789+0000")
	if !ok {
		t.Fatal("parseTime() ok = false")
	}
	want := time.Date(2026, 5, 1, 12, 34, 56, 789_000_000, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("parseTime() = %s, want %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

func TestReadMergesBareDetailObjectWhenAllowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1", "name": "macbook-1"}}})
		case "/devices/device-1/detail":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"serial": "SERIAL1"},
			})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:                  "device",
		Path:                  "/devices",
		DetailPath:            "/devices/{id}/detail",
		AllowBareDetailRecord: true,
		URNKind:               "test_device",
		IDKeys:                []string{"id"},
		Attributes: map[string]string{
			"device_name":   "name",
			"serial_number": "metadata.serial",
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["serial_number"]; got != "SERIAL1" {
		t.Fatalf("serial_number = %q, want detail value", got)
	}
}

func TestReadUsesFamilyMethod(t *testing.T) {
	var gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if r.URL.Path != "/devices/search" {
			t.Fatalf("request path = %q, want /devices/search", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "device-1", "name": "macbook-1"}})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:    "device",
		Path:    "/devices/search",
		Method:  http.MethodPost,
		URNKind: "test_device",
		IDKeys:  []string{"id"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("request method = %q, want POST", gotMethod)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestReadUsesBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
		if got := r.Header.Get("Authorization"); got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1"}}})
	}))
	defer server.Close()

	source := newCustomAuthTestSource(t, server.URL, "basic")
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"username":  "alice",
		"password":  "secret",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
}

func TestDuoHMACAuthLowercasesCanonicalHost(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://API-ABC.DUOSECURITY.COM/admin/v1/users?limit=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	err = setDuoHMACAuth(request, settings{
		clientID:     "DIXXXXXXXXXXXXXXXXXX",
		clientSecret: "deadbeefsecret",
	}, "duo")
	if err != nil {
		t.Fatalf("setDuoHMACAuth: %v", err)
	}
	if got := request.Header.Get("Host"); got != "" {
		t.Fatalf("Host header map value = %q, want empty", got)
	}
	date := request.Header.Get("Date")
	if date == "" {
		t.Fatal("Date header is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(request.Header.Get("Authorization"), "Basic "))
	if err != nil {
		t.Fatalf("decode Authorization: %v", err)
	}
	username, signature, ok := strings.Cut(string(decoded), ":")
	if !ok {
		t.Fatalf("Authorization payload = %q, want username:signature", decoded)
	}
	if username != "DIXXXXXXXXXXXXXXXXXX" {
		t.Fatalf("Duo integration key = %q, want DIXXXXXXXXXXXXXXXXXX", username)
	}
	canonical := strings.Join([]string{
		date,
		http.MethodGet,
		"api-abc.duosecurity.com",
		"/admin/v1/users",
		"limit=1",
	}, "\n")
	mac := hmac.New(sha1.New, []byte("deadbeefsecret"))
	_, _ = mac.Write([]byte(canonical))
	if want := hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("Duo HMAC signature = %q, want %q", signature, want)
	}
}

func TestReadExchangesOAuthClientCredentials(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "client-1" || r.Form.Get("client_secret") != "secret-1" || r.Form.Get("scope") != "read:devices" {
				t.Fatalf("token form = %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/devices":
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("Authorization = %q, want Bearer test-token", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1"}}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	source := newOAuthTestSource(t, server.URL, server.URL+"/oauth/token")
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"client_id":     "client-1",
		"client_secret": "secret-1",
	})
	for i := 0; i < 2; i++ {
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read(%d) error = %v", i, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%d) events = %d, want 1", i, len(pull.Events))
		}
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want cached token reuse", tokenRequests)
	}
}

func TestOAuthCacheKeySeparatesTenantAndClientSecret(t *testing.T) {
	tokenRequests := 0
	deviceRequests := 0
	wantAuth := []string{"Bearer token-1", "Bearer token-2", "Bearer token-3"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			if tokenRequests > len(wantAuth) {
				t.Fatalf("unexpected extra token request")
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if r.Form.Get("client_id") != "client-1" || r.Form.Get("client_secret") == "" {
				t.Fatalf("token form = %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": wantAuth[tokenRequests-1][len("Bearer "):],
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/devices":
			if deviceRequests >= len(wantAuth) {
				t.Fatalf("unexpected extra device request")
			}
			if got := r.Header.Get("Authorization"); got != wantAuth[deviceRequests] {
				t.Fatalf("Authorization = %q, want %q", got, wantAuth[deviceRequests])
			}
			deviceRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1"}}})
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	source := newOAuthTestSource(t, server.URL, server.URL+"/oauth/token")
	for _, cfg := range []map[string]string{
		{"tenant_id": "tenant-a", "client_id": "client-1", "client_secret": "secret-1"},
		{"tenant_id": "tenant-b", "client_id": "client-1", "client_secret": "secret-1"},
		{"tenant_id": "tenant-b", "client_id": "client-1", "client_secret": "secret-2"},
	} {
		if _, err := source.Read(context.Background(), sourcecdk.NewConfig(cfg), nil); err != nil {
			t.Fatalf("Read(%#v) error = %v", cfg, err)
		}
	}
	if tokenRequests != len(wantAuth) {
		t.Fatalf("token requests = %d, want %d", tokenRequests, len(wantAuth))
	}
}

func TestResolveConfigTemplateRejectsRecursiveConfig(t *testing.T) {
	_, err := resolveConfigTemplate("test", "${config.loop}", sourcecdk.NewConfig(map[string]string{
		"loop": "${config.loop}",
	}))
	if err == nil {
		t.Fatal("resolveConfigTemplate() error = nil, want recursion error")
	}
}

func TestReadPreservesNextCursorForEmptyPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":        []map[string]any{},
			"next_cursor": "page-2",
		})
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want empty page", len(pull.Events))
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
	if pull.Checkpoint != nil {
		t.Fatalf("Checkpoint = %#v, want nil so an empty page does not overwrite the last watermark", pull.Checkpoint)
	}
}

func TestDiscoverReturnsFamilyURNs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"devices": []map[string]any{{"id": "device-1"}},
		})
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || urns[0].String() != "urn:cerebro:writer:test_device:device-1" {
		t.Fatalf("URNs = %#v, want test device URN", urns)
	}
}

func TestDiscoverEncodesFamilyURNIDWhenEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"devices": []map[string]any{{"id": "auth0|user-1"}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:     "device",
		Path:     "/api/v1/devices",
		URNKind:  "test_device",
		IDKeys:   []string{"id"},
		ListKeys: []string{"devices"},
		Config:   FamilyConfig{EncodeURNID: true},
	})
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || urns[0].String() != "urn:cerebro:writer:test_device:auth0%7Cuser-1" {
		t.Fatalf("URNs = %#v, want encoded test device URN", urns)
	}
}

func TestReadSynthesizesEncodedResourceURNAttributeWhenConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"devices": []map[string]any{{"id": "auth0|user-1", "name": "User One"}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:       "device",
		Path:       "/api/v1/devices",
		URNKind:    "test_device",
		IDKeys:     []string{"id"},
		ListKeys:   []string{"devices"},
		Attributes: map[string]string{"resource_id": "id", "resource_name": "name"},
		Config:     FamilyConfig{EncodeURNID: true, ResourceURNKind: "test_device"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "device",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["external_id"]; got != "auth0|user-1" {
		t.Fatalf("external_id = %q, want raw provider ID", got)
	}
	if got := attrs["resource_urn"]; got != "urn:cerebro:writer:test_device:auth0%7Cuser-1" {
		t.Fatalf("resource_urn = %q, want encoded runtime URN", got)
	}
}

func TestReadUsesConfiguredListKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"members": []map[string]any{{"id": "U1", "name": "alice"}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:       "user",
		Path:       "/users.list",
		URNKind:    "test_user",
		IDKeys:     []string{"id"},
		ListKeys:   []string{"members"},
		Attributes: map[string]string{"user_id": "id", "name": "name"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "user",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["user_id"] != "U1" {
		t.Fatalf("Events = %#v, want user from members list", pull.Events)
	}
}

func TestReadWrapsScalarListItemsWithIDKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("channel"); got != "C1" {
			t.Fatalf("channel query = %q, want C1", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"members": []string{"U1"},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:     "channel_member",
		Path:     "/conversations.members",
		URNKind:  "test_channel_member",
		IDKeys:   []string{"user_id"},
		ListKeys: []string{"members"},
		Config: FamilyConfig{
			ConfigQuery: map[string]string{"channel": "channel_id"},
		},
		PathParams: []string{"channel_id"},
		Attributes: map[string]string{
			"channel_id": "channel_id",
			"user_id":    "user_id",
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "writer",
		"family":     "channel_member",
		"token":      "token-1",
		"channel_id": "C1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["user_id"] != "U1" || attrs["channel_id"] != "C1" {
		t.Fatalf("attributes = %#v, want scalar member with channel context", attrs)
	}
	var payload map[string]string
	if err := json.Unmarshal(pull.Events[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["user_id"] != "U1" || payload["channel_id"] != "C1" {
		t.Fatalf("payload = %#v, want scalar member with channel context", payload)
	}
}

func TestReadSplitsBracketConfigQueryValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()["tags[]"]
		if len(values) != 2 || values[0] != "alpha" || values[1] != "beta" {
			t.Fatalf("tags[] = %#v, want alpha and beta", values)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "item-1"}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:    "item",
		Path:    "/items",
		URNKind: "item",
		IDKeys:  []string{"id"},
		Config:  FamilyConfig{ConfigQuery: map[string]string{"tags[]": "tags"}},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"tags":      "alpha, beta",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
}

func TestReadResolvesPathParamsAndResultList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/accounts/account%2Fone/items" {
			t.Fatalf("request path = %q, want /accounts/account%%2Fone/items", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":   "item-1",
				"name": "Item One",
			}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:       "item",
		Path:       "/accounts/{account_id}/items",
		PathParams: []string{"account_id"},
		URNKind:    "item",
		IDKeys:     []string{"id"},
		ListKeys:   []string{"result"},
		Attributes: map[string]string{"display_name": "name"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "writer",
		"token":      "token-1",
		"account_id": "account/one",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["display_name"]; got != "Item One" {
		t.Fatalf("display_name = %q, want Item One", got)
	}
	if got := pull.Events[0].Attributes["account_id"]; got != "account/one" {
		t.Fatalf("account_id = %q, want account/one", got)
	}
}

func TestReadRequiresPathParamValue(t *testing.T) {
	source := newCustomTestSource(t, "https://example.com", Family{
		Name:       "item",
		Path:       "/accounts/{account_id}/items",
		PathParams: []string{"account_id"},
		IDKeys:     []string{"id"},
	})
	_, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want missing account_id error")
	}
	var paramErr *pathParamError
	if !errors.As(err, &paramErr) {
		t.Fatalf("Read() error = %v, want pathParamError", err)
	}
	if paramErr.param != "account_id" {
		t.Fatalf("path param = %q, want account_id", paramErr.param)
	}
}

func TestReadUsesCursorParamAndResultInfoPages(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("per_page"); got != "1" {
			t.Fatalf("per_page = %q, want 1", got)
		}
		if got := r.URL.Query().Get("limit"); got != "" {
			t.Fatalf("limit = %q, want empty", got)
		}
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result":      []map[string]any{{"id": "item-1"}},
				"result_info": map[string]any{"page": 1, "total_pages": 2},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result":      []map[string]any{{"id": "item-2"}},
				"result_info": map[string]any{"page": 2, "total_pages": 2},
			})
		default:
			t.Fatalf("page = %q, want empty or 2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "page",
		URNKind:        "item",
		IDKeys:         []string{"id"},
		ListKeys:       []string{"result"},
		PageSizeParams: []string{"per_page"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("page") != "2" {
		t.Fatalf("requests = %#v, want second request with page=2", requests)
	}
}

func TestReadUsesFamilyCursorKeysAndHasMore(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("limit"); got != "1" {
			t.Fatalf("limit = %q, want 1", got)
		}
		switch r.URL.Query().Get("after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     []map[string]any{{"id": "item-1"}},
				"has_more": true,
				"last_id":  "item-1",
			})
		case "item-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":     []map[string]any{{"id": "item-2"}},
				"has_more": false,
				"last_id":  "item-2",
			})
		default:
			t.Fatalf("after = %q, want empty or item-1", r.URL.Query().Get("after"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "after",
		NextCursorKeys: []string{"last_id"},
		HasMoreKey:     "has_more",
		URNKind:        "item",
		IDKeys:         []string{"id"},
		PageSizeParams: []string{"limit"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "item-1" {
		t.Fatalf("first NextCursor = %q, want item-1", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("after") != "item-1" {
		t.Fatalf("requests = %#v, want second request with after=item-1", requests)
	}
}

func TestReadUsesLastItemCursorForBareArray(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("take"); got != "2" {
			t.Fatalf("take = %q, want 2", got)
		}
		switch r.URL.Query().Get("from") {
		case "":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"log_id": "log-1"}, {"log_id": "log-2"}})
		case "log-2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"log_id": "log-3"}})
		default:
			t.Fatalf("from = %q, want empty or log-2", r.URL.Query().Get("from"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "log",
		Path:           "/logs",
		CursorParam:    "from",
		Config:         FamilyConfig{LastItemCursorKeys: []string{"log_id"}},
		URNKind:        "log",
		IDKeys:         []string{"log_id"},
		PageSizeParams: []string{"take"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if got := sourcecdk.CursorToken(first.NextCursor); got != "log-2" {
		t.Fatalf("first NextCursor token = %q, want log-2", got)
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("from") != "log-2" {
		t.Fatalf("requests = %#v, want second request with from=log-2", requests)
	}
}

func TestReadUsesOffsetCursorWithHasMoreWithoutTotal(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		switch r.URL.Query().Get("offset") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":   []map[string]any{{"id": "item-1"}, {"id": "item-2"}},
				"limit":  2,
				"offset": 0,
				"more":   true,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":   []map[string]any{{"id": "item-3"}},
				"limit":  2,
				"offset": 2,
				"more":   false,
			})
		default:
			t.Fatalf("offset = %q, want empty or 2", r.URL.Query().Get("offset"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "offset",
		HasMoreKey:     "more",
		URNKind:        "item",
		IDKeys:         []string{"id"},
		PageSizeParams: []string{"limit"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("offset") != "2" {
		t.Fatalf("requests = %#v, want second request with offset=2", requests)
	}
}

func TestReadUsesOffsetTotalZeroBeforeHasMore(t *testing.T) {
	requests := make([]*http.Request, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("limit"); got != "2" {
			t.Fatalf("limit = %q, want 2", got)
		}
		if got := r.URL.Query().Get("offset"); got != "" {
			t.Fatalf("offset = %q, want empty", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":   []map[string]any{},
			"limit":  2,
			"offset": 0,
			"total":  0,
			"more":   true,
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "offset",
		HasMoreKey:     "more",
		URNKind:        "item",
		IDKeys:         []string{"id"},
		PageSizeParams: []string{"limit"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("NextCursor = %#v, want nil", pull.NextCursor)
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
}

func TestReadUsesOneIndexedPageCursorWithOffsetMetadata(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get("per_page"); got != "2" {
			t.Fatalf("per_page = %q, want 2", got)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":   []map[string]any{{"id": "item-1"}, {"id": "item-2"}},
				"limit":  2,
				"offset": 0,
				"total":  3,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":   []map[string]any{{"id": "item-3"}},
				"limit":  2,
				"offset": 2,
				"total":  3,
			})
		default:
			t.Fatalf("page = %q, want 1 or 2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "item",
		Path:            "/items",
		CursorParam:     "page",
		PageFirstCursor: "1",
		URNKind:         "item",
		IDKeys:          []string{"id"},
		PageSizeParams:  []string{"per_page"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[0].URL.Query().Get("page") != "1" || requests[1].URL.Query().Get("page") != "2" {
		t.Fatalf("requests = %#v, want page 1 then page 2", requests)
	}
}

func TestReadUsesDottedFamilyCursorKey(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "item-1"}},
				"paging": map[string]any{
					"continuation": "item-1",
				},
			})
		case "item-1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "item-2"}},
			})
		default:
			t.Fatalf("after = %q, want empty or item-1", r.URL.Query().Get("after"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "after",
		NextCursorKeys: []string{"paging.continuation"},
		URNKind:        "item",
		IDKeys:         []string{"id"},
		PageSizeParams: []string{"limit"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "item-1" {
		t.Fatalf("first NextCursor = %q, want item-1", first.NextCursor.GetOpaque())
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("after") != "item-1" {
		t.Fatalf("requests = %#v, want second request with after=item-1", requests)
	}
}

func TestReadUsesLinkHeaderCursor(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("cursor") {
		case "":
			w.Header().Set("Link", `<http://`+r.Host+`/items?cursor=item-1&limit=1>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "item-1"}})
		case "item-1":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "item-2"}})
		default:
			t.Fatalf("cursor = %q, want empty or item-1", r.URL.Query().Get("cursor"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:           "item",
		Path:           "/items",
		CursorParam:    "cursor",
		LinkHeader:     "Link",
		URNKind:        "item",
		IDKeys:         []string{"id"},
		PageSizeParams: []string{"limit"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "item-1" {
		t.Fatalf("first NextCursor = %q, want item-1", first.NextCursor.GetOpaque())
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("cursor") != "item-1" {
		t.Fatalf("requests = %#v, want second request with cursor=item-1", requests)
	}
}

func TestReadUsesNextURLCursor(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		switch r.URL.Query().Get("page") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    []map[string]any{{"id": "item-1"}},
				"nextLink": "http://" + r.Host + "/items?page=2",
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{"id": "item-2"}},
			})
		default:
			t.Fatalf("page = %q, want empty or 2", r.URL.Query().Get("page"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "item",
		Path:            "/items",
		NextCursorKeys:  []string{"nextLink"},
		URNKind:         "item",
		IDKeys:          []string{"id"},
		ListKeys:        []string{"value"},
		PageSizeParams:  []string{"limit"},
		DisablePageSize: true,
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if want := "http://" + requests[0].Host + "/items?page=2"; first.NextCursor.GetOpaque() != want {
		t.Fatalf("first NextCursor = %q, want %q", first.NextCursor.GetOpaque(), want)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "1",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("page") != "2" || requests[1].URL.Query().Has("limit") {
		t.Fatalf("requests = %#v, want second request to follow nextLink without page-size query", requests)
	}
}

func TestReadUsesAbsoluteNextPageWithOffsetCursor(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.URL.Path != "/jira/groups" {
			t.Fatalf("path = %q, want /jira/groups", r.URL.Path)
		}
		if got := r.URL.Query().Get("maxResults"); got != "2" {
			t.Fatalf("maxResults = %q, want 2", got)
		}
		switch r.URL.Query().Get("startAt") {
		case "0":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values":   []map[string]any{{"id": "group-1"}},
				"nextPage": "http://" + r.Host + "/jira/groups?startAt=2&maxResults=2",
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{{"id": "group-2"}},
			})
		default:
			t.Fatalf("startAt = %q, want 0 or 2", r.URL.Query().Get("startAt"))
		}
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "group",
		Path:            "/jira/groups",
		CursorParam:     "startAt",
		NextCursorKeys:  []string{"nextPage"},
		PageFirstCursor: "0",
		PageSizeParams:  []string{"maxResults"},
		URNKind:         "group",
		IDKeys:          []string{"id"},
		ListKeys:        []string{"values"},
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if want := "http://" + requests[0].Host + "/jira/groups?startAt=2&maxResults=2"; first.NextCursor.GetOpaque() != want {
		t.Fatalf("first NextCursor = %q, want %q", first.NextCursor.GetOpaque(), want)
	}
	second, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"per_page":  "2",
	}), first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["external_id"] != "group-2" {
		t.Fatalf("second Events = %#v, want group-2", second.Events)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if got := requests[1].URL.Query().Get("startAt"); got != "2" {
		t.Fatalf("second startAt = %q, want 2", got)
	}
	if strings.Contains(requests[1].URL.RawQuery, "http") {
		t.Fatalf("second query = %q, want followed nextPage URL rather than startAt=<url>", requests[1].URL.RawQuery)
	}
}

func TestReadRejectsNextURLCursorWithUserInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value":    []map[string]any{{"id": "item-1"}},
			"nextLink": "http://user@" + r.Host + "/items?page=2",
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "item",
		Path:            "/items",
		NextCursorKeys:  []string{"nextLink"},
		URNKind:         "item",
		IDKeys:          []string{"id"},
		ListKeys:        []string{"value"},
		DisablePageSize: true,
	})
	first, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), first.NextCursor)
	if err == nil {
		t.Fatal("Read(second) error = nil, want userinfo rejection")
	}
}

func TestReadSingletonObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"devicesApprovalOn":    true,
			"networkFlowLoggingOn": false,
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:      "tailnet",
		Path:      "/tailnet/-/settings",
		URNKind:   "test_tailnet",
		IDKeys:    []string{"id"},
		Singleton: true,
		Attributes: map[string]string{
			"tailnet":                 "id",
			"devices_approval_on":     "devicesApprovalOn",
			"network_flow_logging_on": "networkFlowLoggingOn",
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "tailnet",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want singleton event", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["tailnet"]; got != "tailnet" {
		t.Fatalf("tailnet attribute = %q, want fallback singleton id", got)
	}
}

func TestReadSingletonCanDisablePageSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; got != "" {
			t.Fatalf("raw query = %q, want no page-size params", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "Settings",
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:            "settings",
		Path:            "/settings",
		URNKind:         "settings",
		IDKeys:          []string{"id"},
		Singleton:       true,
		DisablePageSize: true,
		Attributes:      map[string]string{"settings_name": "name"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want singleton event", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["settings_name"]; got != "Settings" {
		t.Fatalf("settings_name = %q, want Settings", got)
	}
}

func TestReadObjectMapRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"groups": map[string][]string{
				"group:eng": {"alice@example.com", "bob@example.com"},
			},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:       "group",
		Path:       "/acl",
		URNKind:    "test_group",
		IDKeys:     []string{"id"},
		MapRecords: map[string]string{"groups": "members"},
		Attributes: map[string]string{"group_id": "id", "members": "members"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "group",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want map-derived record", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["group_id"]; got != "group:eng" {
		t.Fatalf("group_id = %q, want group:eng", got)
	}
	if got := pull.Events[0].Attributes["members"]; got != "alice@example.com,bob@example.com" {
		t.Fatalf("members = %q, want joined map values", got)
	}
}

func TestReadUsesNestedIdentityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resources": []map[string]any{{
				"metadata": map[string]any{"id": "model-1"},
				"entity":   map[string]any{"name": "Risk Model"},
			}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:    "models",
		Path:    "/models",
		URNKind: "test_model",
		IDKeys:  []string{"metadata.id"},
		ListKeys: []string{
			"resources",
		},
		Attributes: map[string]string{
			"model_id":   "metadata.id",
			"model_name": "entity.name",
		},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"family":    "models",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want nested record", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["external_id"]; got != "model-1" {
		t.Fatalf("external_id = %q, want model-1", got)
	}
	if got := pull.Events[0].Attributes["model_name"]; got != "Risk Model" {
		t.Fatalf("model_name = %q, want Risk Model", got)
	}
}

func TestReadParsesUnixTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":         "item-1",
				"created_at": 1711471533,
			}},
		})
	}))
	defer server.Close()

	source := newCustomTestSource(t, server.URL, Family{
		Name:          "item",
		Path:          "/items",
		URNKind:       "item",
		IDKeys:        []string{"id"},
		TimestampKeys: []string{"created_at"},
	})
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	want := time.Unix(1711471533, 0).UTC()
	if got := pull.Events[0].OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestReadDedupesRecordsByExternalID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "device-1", "name": "first"},
				{"id": "device-1", "name": "duplicate"},
				{"id": "device-2", "name": "second"},
			},
		})
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2 deduped records", len(pull.Events))
	}
	if pull.Events[0].Attributes["external_id"] != "device-1" || pull.Events[1].Attributes["external_id"] != "device-2" {
		t.Fatalf("Events = %#v, want first unique records by external id", pull.Events)
	}
}

func TestReadUsesRuntimeTenantID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"id": "device-1", "name": "macbook-1"}},
		})
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		sourceconfig.RuntimeTenantIDKey: "writer",
		"token":                         "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.Events[0].TenantId != "writer" {
		t.Fatalf("TenantId = %q, want writer", pull.Events[0].TenantId)
	}
}

func TestReadKeepsSameRecordIDDifferentDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "CVE-2026-0001", "device_id": "device-1", "version": "1.0.0"},
				{"id": "CVE-2026-0001", "device_id": "device-2", "version": "1.0.0"},
			},
		})
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want same source ID retained per device", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs are equal %q, want device-scoped identities", pull.Events[0].Id)
	}
}

func TestConfigurableBearerAuthUsesAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "":
			if got := r.Header.Get("x-api-key"); got != "admin-key" {
				t.Fatalf("x-api-key = %q, want admin-key", got)
			}
		case "Bearer oauth-value":
			if got := r.Header.Get("x-api-key"); got != "" {
				t.Fatalf("x-api-key = %q, want empty for bearer auth", got)
			}
		default:
			t.Fatalf("Authorization = %q, want empty or Bearer oauth-value", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1"}}})
	}))
	defer server.Close()

	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{ // #nosec G101 -- test placeholder OAuth config only.
		SourceID:               "test",
		DefaultBaseURL:         server.URL,
		DefaultFamily:          "device",
		RequireTenantID:        true,
		TokenHeader:            "x-api-key",
		ConfigurableAuthModels: []string{"bearer_token"},
		Families: []Family{{
			Name:   "device",
			Path:   "/devices",
			IDKeys: []string{"id"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true

	if _, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"api_key":   "admin-key",
	}), nil); err != nil {
		t.Fatalf("Read(default auth) error = %v", err)
	}
	if _, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test placeholder auth config only.
		"tenant_id":  "writer",
		"auth_model": "bearer_token",
		"token":      "oauth-value",
	}), nil); err != nil {
		t.Fatalf("Read(bearer auth) error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":  "writer",
		"auth_model": "basic",
		"token":      "admin-key",
	})); err == nil {
		t.Fatal("Check(unsupported auth_model) error = nil, want error")
	}
}

func TestReadAppliesConfigHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Organization-Id"); got != "org_123" {
			t.Fatalf("X-Organization-Id = %q, want org_123", got)
		}
		if got := r.Header.Get("X-Tenant-Id"); got != "workspace_123" {
			t.Fatalf("X-Tenant-Id = %q, want workspace_123", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "device-1"}}})
	}))
	defer server.Close()

	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  server.URL,
		DefaultFamily:   "device",
		RequireTenantID: true,
		TokenHeader:     "x-api-key",
		ConfigHeaders: map[string]string{
			"X-Organization-Id": "organization_id",
			"X-Tenant-Id":       "workspace_id",
		},
		Families: []Family{{
			Name: "device",
			Path: "/devices",
			Config: FamilyConfig{
				ConfigAttributes: map[string]string{
					"organization_id": "organization_id",
					"workspace_id":    "workspace_id",
				},
			},
			IDKeys: []string{"id"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true
	if _, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":         "fixture-key",
		"organization_id": "org_123",
		"tenant_id":       "writer",
		"workspace_id":    "workspace_123",
	}), nil); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":         "fixture-key",
		"organization_id": "org_123",
		"tenant_id":       "writer",
		"workspace_id":    "workspace_123",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := pull.Events[0].Attributes["workspace_id"]; got != "workspace_123" {
		t.Fatalf("workspace_id attribute = %q, want workspace_123", got)
	}
}

func TestReadRejectsMalformedRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[[]]}`))
	}))
	defer server.Close()

	source := newTestSource(t, server.URL)
	if _, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
	}), nil); err == nil {
		t.Fatal("Read() error = nil, want malformed record error")
	}
}

func TestRejectsInvalidConfigBeforeNetwork(t *testing.T) {
	source := newTestSource(t, "https://example.com")
	for name, cfg := range map[string]sourcecdk.Config{
		"missing tenant": sourcecdk.NewConfig(map[string]string{"token": "token-1"}),
		"missing token":  sourcecdk.NewConfig(map[string]string{"tenant_id": "writer"}),
		"bad family": sourcecdk.NewConfig(map[string]string{
			"tenant_id": "writer",
			"token":     "token-1",
			"family":    "unknown",
		}),
		"bad path": sourcecdk.NewConfig(map[string]string{
			"tenant_id": "writer",
			"token":     "token-1",
			"path":      "relative",
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if err := source.Check(context.Background(), cfg); err == nil {
				t.Fatal("Check() error = nil, want error")
			}
		})
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source := newTestSource(t, "https://example.com")
	source.AllowLoopbackBaseURL = false
	_, err := source.parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"token":     "token-1",
		"base_url":  "http://127.0.0.1:8080",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want unsafe base_url error")
	}
}

func TestPrivateEndpointAllowlistIsOptInPerSource(t *testing.T) {
	source := newTestSource(t, "https://example.com")
	source.AllowLoopbackBaseURL = false
	source.lookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.10")}}, nil
	}
	err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":                  "writer",
		"token":                      "token-1",
		"base_url":                   "https://cas.internal.example",
		"private_endpoint_allowlist": "cas.internal.example",
	}))
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-EvidenceCAS source to ignore private_endpoint_allowlist and keep default SSRF protection")
	}
}

func TestPrivateEndpointAllowlistAllowsConfiguredJSONAPISource(t *testing.T) {
	source := newTestSource(t, "https://example.com")
	source.options.PrivateEndpointAllowlistConfigKey = "private_endpoint_allowlist"
	source.AllowLoopbackBaseURL = false
	source.lookupIPAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.10")}}, nil
	}
	settings, err := source.parseSettings(sourcecdk.NewConfig(map[string]string{
		"tenant_id":                  "writer",
		"token":                      "token-1",
		"base_url":                   "https://cas.internal.example",
		"private_endpoint_allowlist": "cas.internal.example",
	}))
	if err != nil {
		t.Fatalf("parseSettings() error = %v, want allowlisted private endpoint accepted", err)
	}
	if settings.host != "cas.internal.example" {
		t.Fatalf("host = %q, want cas.internal.example", settings.host)
	}
}

func TestSafeRoundTripperPinsValidatedHostnameAddress(t *testing.T) {
	var dialed string
	rt := sourcehttp.SafeRoundTripper{
		SourceID: "test",
		Base: &http.Transport{DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("stop")
		}},
		LookupIPAddrs: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.example.test:8080/devices", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	response, err := rt.RoundTrip(req)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("RoundTrip() error = nil, want dial sentinel")
	}
	if dialed != "203.0.113.10:8080" {
		t.Fatalf("dialed = %q, want pinned resolved address", dialed)
	}
}

func TestSafeRoundTripperRejectsUnsafeResolvedHostnameBeforeDial(t *testing.T) {
	var dialed bool
	rt := sourcehttp.SafeRoundTripper{
		SourceID: "test",
		Base: &http.Transport{DialContext: func(_ context.Context, _ string, _ string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("should not dial")
		}},
		LookupIPAddrs: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://rebind.example.test/devices", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	response, err := rt.RoundTrip(req)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("RoundTrip() error = nil, want unsafe resolved host rejection")
	}
	if dialed {
		t.Fatal("DialContext was called before rejecting unsafe resolved host")
	}
}

func newTestSource(t *testing.T, baseURL string) *Source {
	t.Helper()
	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  baseURL,
		DefaultFamily:   "device",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []Family{{
			Name:    "device",
			Path:    "/devices",
			URNKind: "test_device",
			IDKeys:  []string{"id"},
			TimestampKeys: []string{
				"updated_at",
			},
			Attributes: map[string]string{
				"device_name":  "name",
				"display_name": "missing|name",
				"owner_email":  "owner.email",
			},
			StaticAttributes: map[string]string{"source_product": "test"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true
	return source
}

func newCustomTestSource(t *testing.T, baseURL string, family Family) *Source {
	t.Helper()
	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  baseURL,
		DefaultFamily:   family.Name,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families:        []Family{family},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true
	return source
}

func newCustomAuthTestSource(t *testing.T, baseURL string, authModel string) *Source {
	t.Helper()
	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  baseURL,
		DefaultFamily:   "device",
		RequireTenantID: true,
		AuthModel:       authModel,
		Families: []Family{{
			Name:   "device",
			Path:   "/devices",
			IDKeys: []string{"id"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true
	return source
}

func newOAuthTestSource(t *testing.T, baseURL string, tokenURL string) *Source {
	t.Helper()
	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  baseURL,
		DefaultFamily:   "device",
		RequireTenantID: true,
		AuthModel:       "oauth_client_credentials",
		OAuthTokenURL:   tokenURL,
		OAuthScopes:     []string{"read:devices"},
		Families: []Family{{
			Name:   "device",
			Path:   "/devices",
			IDKeys: []string{"id"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.AllowLoopbackBaseURL = true
	return source
}

func TestParseSettingsRejectsProviderManagedTokenURLOverride(t *testing.T) {
	t.Parallel()

	providerTokenURL := "https://auth.example.test/oauth/" + "token"
	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
		SourceID:        "test",
		DefaultBaseURL:  "https://api.example.test",
		DefaultFamily:   "device",
		RequireTenantID: true,
		AuthModel:       "oauth_client_credentials",
		OAuthTokenURL:   providerTokenURL,
		Families: []Family{{
			Name:   "device",
			Path:   "/devices",
			IDKeys: []string{"id"},
		}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test placeholder auth config only.
		"tenant_id":     "tenant",
		"token_url":     "https://attacker.example/oauth/token",
		"client_id":     "client",
		"client_secret": "secret",
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("parseSettings() err = %v, want ErrInvalidConfig", err)
	}
	source.AllowLoopbackBaseURL = true
	_, err = source.parseSettings(sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test placeholder auth config only.
		"tenant_id":     "tenant",
		"token_url":     "https://attacker.example/oauth/token",
		"client_id":     "client",
		"client_secret": "secret",
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("parseSettings() with loopback allowance err = %v, want ErrInvalidConfig for non-loopback override", err)
	}
}

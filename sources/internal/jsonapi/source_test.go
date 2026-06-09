package jsonapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
)

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

func TestReadRejectsMalformedRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":["not-an-object"]}`))
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

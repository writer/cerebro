package jsonapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- Duo Admin API HMAC auth requires HMAC-SHA1.
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
		Name:        "item",
		Path:        "/items",
		URNKind:     "item",
		IDKeys:      []string{"id"},
		ConfigQuery: map[string]string{"tags[]": "tags"},
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

	source, err := New(&cerebrov1.SourceSpec{Id: "test", Name: "Test"}, Options{
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

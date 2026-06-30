package sentinelone

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

const (
	fixtureBaseURL = "https://sentinelone.example.test"
	fixtureToken   = "test-token"
)

func newFixtureConfig(family string, extra map[string]string) map[string]string {
	cfg := map[string]string{
		"base_url": fixtureBaseURL,
		"family":   family,
		"token":    fixtureToken,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return cfg
}

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "sentinelone" {
		t.Fatalf("Spec().Id = %q, want sentinelone", source.Spec().Id)
	}
	if source.Spec().Name != "SentinelOne" {
		t.Fatalf("Spec().Name = %q, want SentinelOne", source.Spec().Name)
	}
}

func TestParseSettingsRequiresBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family": "threat",
		"token":  fixtureToken,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestParseSettingsRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family":   "threat",
		"base_url": fixtureBaseURL,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestParseSettingsRejectsUnknownFamily(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"family":   "unknown",
		"base_url": fixtureBaseURL,
		"token":    fixtureToken,
	}))
	if err == nil {
		t.Fatal("Check(unknown) error = nil, want non-nil")
	}
}

func TestApplicationFamilyFansOutWithoutAgentID(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "application",
		"per_page": "1",
		"token":    fixtureToken,
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(application) error = %v", err)
	}
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(application first page) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if got := first.Events[0].Attributes["agent_id"]; got != "A-1" {
		t.Fatalf("first agent_id = %q, want A-1", got)
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want second agent page")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(application second page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["agent_id"]; got != "A-2" {
		t.Fatalf("second agent_id = %q, want A-2", got)
	}
}

func TestApplicationFamilyKeepsAgentCursorWhenPageHasNoApplications(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "ApiToken "+fixtureToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"detail": "invalid token", "title": "Auth Failed"}}})
			return
		}
		switch r.URL.Path {
		case "/web/api/v2.1/agents":
			if r.URL.Query().Get("cursor") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       []map[string]any{{"id": "A-empty", "computerName": "empty-host"}},
					"pagination": map[string]any{"nextCursor": "cursor-A-2"},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":       []map[string]any{{"id": "A-2", "computerName": "host-A-2"}},
				"pagination": map[string]any{},
			})
		case "/web/api/v2.1/agents/applications":
			if r.URL.Query().Get("ids") == "A-empty" {
				_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
				"name": "Example App", "publisher": "Example Inc", "version": "1.0.0",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "application",
		"per_page": "1",
		"token":    fixtureToken,
	})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(application first empty page) error = %v", err)
	}
	if len(first.Events) != 0 {
		t.Fatalf("len(first.Events) = %d, want 0", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "cursor-A-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-A-2", first.NextCursor)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(application second page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["agent_id"]; got != "A-2" {
		t.Fatalf("second agent_id = %q, want A-2", got)
	}
}

func TestSinceRejectedForNonTimeFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(newFixtureConfig("agent", map[string]string{
		"since": "2026-04-23T00:00:00Z",
	})))
	if err == nil {
		t.Fatal("Check(agent, since) error = nil, want non-nil")
	}
}

func TestNewFixtureDiscoversAndReadsAllFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, family := range []string{
		familyActivity, familyAgent, familyApplication, familyExclusion, familyGroup, familySite, familyThreat,
	} {
		t.Run(family, func(t *testing.T) {
			cfg := newFixtureConfig(family, nil)
			urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(cfg))
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", family, err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", family, len(urns))
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfg), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", family, len(pull.Events))
			}
		})
	}
}

func TestCheckDiscoverAndReadLiveThreats(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "threat",
		"per_page": "1",
		"token":    fixtureToken,
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(threat) error = %v", err)
	}
	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(threat) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(threat)) = %d, want 1", len(discover))
	}
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(threat first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(threat first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "sentinelone.threat" {
		t.Fatalf("first.Events[0].Kind = %q, want sentinelone.threat", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal threat payload: %v", err)
	}
	threatInfo, ok := payload["threat_info"].(map[string]any)
	if !ok {
		t.Fatalf("payload threat_info = %#v, want object", payload["threat_info"])
	}
	if got := threatInfo["classification"]; got != "Malware" {
		t.Fatalf("threat_info.classification = %#v, want Malware", got)
	}
	if got := first.Events[0].Attributes["mitre_tactics"]; got != "Execution" {
		t.Fatalf("threat attribute mitre_tactics = %q, want Execution", got)
	}
	for key, want := range map[string]string{
		"analyst_verdict_norm":   "true_positive",
		"automatically_resolved": "false",
		"classification_norm":    "malware",
		"incident_status_norm":   "unresolved",
		"mitigation_status_norm": "not_mitigated",
	} {
		if got := first.Events[0].Attributes[key]; got != want {
			t.Fatalf("threat attribute %s = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]string{
		"hostname":     "host-A-1",
		"agent_ip_v4":  "203.0.113.20",
		"agent_ip_v6":  "2001:db8::20",
		"external_ip":  "198.51.100.20",
		"ip":           "203.0.113.20",
		"ip_addresses": "203.0.113.20,2001:db8::20,198.51.100.20",
	} {
		if got := first.Events[0].Attributes[key]; got != want {
			t.Fatalf("threat attribute %s = %q, want %q", key, got, want)
		}
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(threat second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(threat second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "T-2" {
		t.Fatalf("second.Checkpoint = %#v, want cursor T-2", second.Checkpoint)
	}
}

func TestCheckDiscoverAndReadLiveAgents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "agent",
		"per_page": "1",
		"token":    fixtureToken,
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(agent) error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(agent) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(agent).Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Kind; got != "sentinelone.agent" {
		t.Fatalf("agent event kind = %q, want sentinelone.agent", got)
	}
	attrs := pull.Events[0].Attributes
	for k, want := range map[string]string{
		"agent_id":      "A-1",
		"computer_name": "host-A-1",
		"hostname":      "host-A-1",
		"ip":            "203.0.113.10",
		"ip_addresses":  "203.0.113.10,10.0.0.10",
		"is_active":     "true",
		"family":        "agent",
		"user_email":    "owner@writer.com",
		"user_name":     "owner@writer.com",
	} {
		if got := attrs[k]; got != want {
			t.Fatalf("agent attribute %s = %q, want %q", k, got, want)
		}
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "ApiToken "+fixtureToken {
			t.Fatalf("Authorization = %q, want ApiToken token", got)
		}
		if r.URL.Path != "/web/api/v2.1/agents" {
			t.Fatalf("path = %q, want /web/api/v2.1/agents", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{
			"title":  "Service Unavailable",
			"detail": "retry later",
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   familyAgent,
		"token":    fixtureToken,
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "sentinelone API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestSentinelOneEmailLikeRejectsUsernameOnlyUPNs(t *testing.T) {
	for _, value := range []string{"owner@WRITER", "user@localhost", "jdoe@"} {
		if got := sentinelOneEmailLike(value); got != "" {
			t.Fatalf("sentinelOneEmailLike(%q) = %q, want empty", value, got)
		}
	}
	if got := sentinelOneEmailLike(" Owner@Writer.COM "); got != "owner@writer.com" {
		t.Fatalf("sentinelOneEmailLike(valid email) = %q", got)
	}
}

func TestRecords_FirewallEnabledConditionalEmit(t *testing.T) {
	for _, tt := range []struct {
		name        string
		raw         string
		want        string
		wantPresent bool
	}{
		{
			name: "missing",
			raw:  `{"id":"agent-missing","computerName":"host-missing","isActive":true,"updatedAt":"2026-04-23T01:00:00Z"}`,
		},
		{
			name:        "explicit_false",
			raw:         `{"id":"agent-false","computerName":"host-false","firewallEnabled":false,"updatedAt":"2026-04-23T01:00:00Z"}`,
			want:        "false",
			wantPresent: true,
		},
		{
			name:        "explicit_true",
			raw:         `{"id":"agent-true","computerName":"host-true","firewallEnabled":true,"updatedAt":"2026-04-23T01:00:00Z"}`,
			want:        "true",
			wantPresent: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var record agentRecord
			raw := json.RawMessage(tt.raw)
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatalf("unmarshal agent: %v", err)
			}
			record.setRaw(raw)
			event, err := agentEvent(settings{host: "sentinelone.example.test"}, record)
			if err != nil {
				t.Fatalf("agentEvent() error = %v", err)
			}
			got, exists := event.Attributes["firewall_enabled"]
			if exists != tt.wantPresent {
				t.Fatalf("firewall_enabled present = %v with value %q, want present=%v; attrs=%v", exists, got, tt.wantPresent, event.Attributes)
			}
			if exists && got != tt.want {
				t.Fatalf("firewall_enabled = %q, want %q; attrs=%v", got, tt.want, event.Attributes)
			}
		})
	}
}

func TestReadLiveJoinFamilies(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	for _, tt := range []struct {
		family string
		extra  map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: "site", kind: "sentinelone.site", attr: "site_id", want: "S-1"},
		{family: "group", kind: "sentinelone.group", attr: "group_id", want: "G-1"},
		{family: "exclusion", kind: "sentinelone.exclusion", attr: "exclusion_id", want: "X-1"},
		{family: "activity", kind: "sentinelone.activity", attr: "activity_id", want: "Y-1"},
		{family: "application", extra: map[string]string{"agent_id": "A-1"}, kind: "sentinelone.application_inventory", attr: "application_name", want: "Example App"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{
				"base_url": server.URL,
				"family":   tt.family,
				"per_page": "1",
				"token":    fixtureToken,
			}
			for k, v := range tt.extra {
				config[k] = v
			}
			if err := source.Check(context.Background(), sourcecdk.NewConfig(config)); err != nil {
				t.Fatalf("Check(%s) error = %v", tt.family, err)
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("Read(%s).Events[0].Attributes[%q] = %q, want %q", tt.family, tt.attr, got, tt.want)
			}
		})
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, baseURL := range []string{
		"http://sentinelone.example.test",
		"https://sentinelone.example.test:8443",
		"https://sentinelone.example.test/path",
		"https://user@sentinelone.example.test",
		"https://localhost.",
		"https://127.1",
		"https://10.0.0.1",
		"https://172.16.0.1",
		"https://192.168.1.10",
		"https://169.254.169.254",
		"https://[fe80::1]",
		"https://0.0.0.0",
		"https://2130706433",
		"https://0177.0.0.1",
		"https://0x7f000001",
	} {
		t.Run(baseURL, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url": baseURL,
				"family":   "threat",
				"token":    fixtureToken,
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestGetJSONRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" + strings.Repeat(" ", maxBodyBytes) + "]"))
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	var target []map[string]any
	err = source.getJSON(context.Background(), settings{
		baseURL: server.URL,
		token:   fixtureToken,
	}, "/web/api/v2.1/threats", nil, &target)
	if err == nil {
		t.Fatal("getJSON() error = nil, want non-nil")
	}
}

func TestGetJSONDoesNotFollowRedirects(t *testing.T) {
	redirectHit := false
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectHit = true
	}))
	defer redirectTarget.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirector.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	var target []map[string]any
	err = source.getJSON(context.Background(), settings{
		baseURL: redirector.URL,
		token:   fixtureToken,
	}, "/web/api/v2.1/threats", nil, &target)
	if err == nil {
		t.Fatal("getJSON() error = nil, want non-nil redirect response")
	}
	if redirectHit {
		t.Fatal("getJSON() followed redirect target")
	}
}

func TestHTTPClientRejectsHostsResolvingToPrivateIPs(t *testing.T) {
	called := false
	client := httpClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://attacker.example/web/api/v2.1/threats", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("Do() error = nil, want non-nil")
	}
	if called {
		t.Fatal("Do() reached wrapped transport for unsafe resolved host")
	}
}

func TestHTTPClientFailsClosedWhenHostResolutionFails(t *testing.T) {
	called := false
	client := httpClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("dns failed")
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://attacker.example/web/api/v2.1/threats", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("Do() error = nil, want non-nil")
	}
	if called {
		t.Fatal("Do() reached wrapped transport after DNS failure")
	}
}

func TestUnauthorizedReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"code":4000040,"detail":"invalid token","title":"Authentication Failed"}]}`))
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "threat",
		"token":    fixtureToken,
	})
	err = source.Check(context.Background(), cfg)
	if err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
	var respErr *responseError
	if !errors.As(err, &respErr) {
		t.Fatalf("Check() error = %v, want *responseError", err)
	}
	if respErr.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("Check() status = %d, want %d", respErr.StatusCode(), http.StatusUnauthorized)
	}
}

func TestThreatEventComputesMitreTactics(t *testing.T) {
	event, err := threatEvent(settings{host: "sentinelone.example.test"}, threatRecord{
		ID: "T-7",
		ThreatInfo: threatInfoRecord{
			threatClassificationRecord: threatClassificationRecord{
				Classification:       "Trojan",
				ClassificationSource: "Engine",
				AnalystVerdict:       "true_positive",
				IncidentStatus:       "unresolved",
				MitigationStatus:     "not_mitigated",
				ConfidenceLevel:      "malicious",
			},
			threatLifecycleRecord: threatLifecycleRecord{
				IdentifiedAt: "2026-04-23T01:00:00Z",
			},
		},
		AgentRealtimeInfo: agentRealtimeInfoRecord{
			agentRealtimeIdentity: agentRealtimeIdentity{AgentID: "A-1", AgentComputerName: "host-A-1"},
			agentRealtimeStatus:   agentRealtimeStatus{AgentIsActive: true},
		},
		Indicators: []threatIndicatorRecord{
			{Category: "Exploitation", Tactics: []indicatorTactic{
				{Name: "Execution", Techniques: []indicatorTactic2{{Name: "Native API"}, {Name: "Native API"}}},
				{Name: "Defense Evasion"},
			}},
		},
		raw: json.RawMessage(`{"id":"T-7"}`),
	})
	if err != nil {
		t.Fatalf("threatEvent() error = %v", err)
	}
	tactics := event.Attributes["mitre_tactics"]
	if tactics != "Defense Evasion,Execution" {
		t.Fatalf("mitre_tactics = %q, want sorted [Defense Evasion,Execution]", tactics)
	}
	if got := event.Attributes["mitre_techniques"]; got != "Native API" {
		t.Fatalf("mitre_techniques = %q, want Native API", got)
	}
	if got := event.Attributes["indicator_categories"]; got != "Exploitation" {
		t.Fatalf("indicator_categories = %q, want Exploitation", got)
	}
}

func TestNextCursorPreservedFromBody(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"family":   "agent",
		"per_page": "1",
		"token":    fixtureToken,
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(agent first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-A-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-A-2", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(agent second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
}

// Test API handler.

func newTestAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	threats := []map[string]any{
		{
			"id": "T-1",
			"threatInfo": map[string]any{
				"analystVerdict":       "true_positive",
				"classification":       "Malware",
				"classificationSource": "Engine",
				"confidenceLevel":      "malicious",
				"incidentStatus":       "unresolved",
				"mitigationStatus":     "not_mitigated",
				"identifiedAt":         "2026-04-23T01:00:00Z",
				"sha256":               "feedfacecafebeef",
			},
			"agentRealtimeInfo": map[string]any{
				"agentId":           "A-1",
				"agentComputerName": "host-A-1",
				"agentIsActive":     true,
				"agentInfected":     true,
			},
			"agentDetectionInfo": map[string]any{
				"agentIpV4":  "203.0.113.20",
				"agentIpV6":  "2001:db8::20",
				"externalIp": "198.51.100.20",
				"siteId":     "S-1",
				"groupId":    "G-1",
			},
			"indicators": []map[string]any{
				{"category": "Malware", "tactics": []map[string]any{{"name": "Execution"}}},
			},
		},
		{
			"id": "T-2",
			"threatInfo": map[string]any{
				"classification":   "Trojan",
				"incidentStatus":   "resolved",
				"mitigationStatus": "mitigated",
				"identifiedAt":     "2026-04-23T00:00:00Z",
			},
			"agentRealtimeInfo": map[string]any{
				"agentId": "A-2",
			},
		},
	}
	agents := []map[string]any{
		{
			"id":                   "A-1",
			"computerName":         "host-A-1",
			"osName":               "macOS",
			"osType":               "macos",
			"isActive":             true,
			"isUpToDate":           true,
			"externalIp":           "203.0.113.10",
			"lastIpToMgmt":         "10.0.0.10",
			"lastLoggedInUserName": "owner@writer.com",
			"siteId":               "S-1",
			"groupId":              "G-1",
			"lastActiveDate":       "2026-04-23T01:00:00Z",
			"updatedAt":            "2026-04-23T01:00:00Z",
		},
		{
			"id":             "A-2",
			"computerName":   "host-A-2",
			"osName":         "Windows",
			"osType":         "windows",
			"isActive":       false,
			"siteId":         "S-1",
			"groupId":        "G-1",
			"lastActiveDate": "2026-03-23T01:00:00Z",
			"updatedAt":      "2026-04-23T00:00:00Z",
		},
	}
	sites := []map[string]any{{"id": "S-1", "name": "Production", "state": "active", "isDefault": true}}
	groups := []map[string]any{{"id": "G-1", "name": "Default Group", "type": "static", "isDefault": true, "siteId": "S-1", "totalAgents": 2}}
	exclusions := []map[string]any{{"id": "X-1", "type": "path", "mode": "suppress_alerts", "osType": "macos", "scope": map[string]any{"name": "Production", "type": "site"}, "scopeName": "Production", "value": "/Applications/Approved.app", "notRecommended": "NONE", "includeChildren": "true"}}
	activities := []map[string]any{{"id": "Y-1", "activityType": 27, "primaryDescription": "User user@example.test logged in", "agentId": "A-1", "siteId": "S-1", "groupId": "G-1", "createdAt": "2026-04-23T00:30:00Z"}}
	apps := []map[string]any{
		{"name": "Example App", "publisher": "Example Inc", "version": "1.0.0", "installedDate": "2026-04-20T00:00:00Z", "size": 12345},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "ApiToken "+fixtureToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"detail": "invalid token", "title": "Auth Failed"}}})
			return
		}
		switch r.URL.Path {
		case "/web/api/v2.1/threats":
			cursor := r.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       threats[:1],
					"pagination": map[string]any{"nextCursor": "cursor-2", "totalItems": 2},
				})
				return
			}
			if cursor == "cursor-2" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       threats[1:2],
					"pagination": map[string]any{"nextCursor": nil, "totalItems": 2},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{}, "pagination": map[string]any{}})
		case "/web/api/v2.1/agents":
			cursor := r.URL.Query().Get("cursor")
			if cursor == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       agents[:1],
					"pagination": map[string]any{"nextCursor": "cursor-A-2"},
				})
				return
			}
			if cursor == "cursor-A-2" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       agents[1:2],
					"pagination": map[string]any{},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{}, "pagination": map[string]any{}})
		case "/web/api/v2.1/sites":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": sites, "pagination": map[string]any{}})
		case "/web/api/v2.1/groups":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": groups, "pagination": map[string]any{}})
		case "/web/api/v2.1/exclusions":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": exclusions, "pagination": map[string]any{}})
		case "/web/api/v2.1/activities":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": activities, "pagination": map[string]any{}})
		case "/web/api/v2.1/agents/applications":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": apps})
		default:
			http.NotFound(w, r)
		}
	})
}

// avoid unused error in TestNextCursor; refer to cerebrov1 to keep import alive when partial test runs.
var _ = cerebrov1.SourceCursor{}

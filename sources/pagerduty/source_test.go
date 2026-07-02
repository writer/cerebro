package pagerduty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "pagerduty" {
		t.Fatalf("Spec().Id = %q, want pagerduty", got)
	}
}

func TestReadPagerDutyResponderTopologyKinds(t *testing.T) {
	for _, tt := range []struct {
		name     string
		family   string
		kind     string
		path     string
		response map[string]any
		want     map[string]string
	}{
		{
			name:   "user",
			family: familyUser,
			kind:   "pagerduty.user",
			path:   "/users",
			response: map[string]any{"users": []map[string]any{{
				"id": "PU1", "name": "Alice Responder", "email": "alice@writer.com",
				"role": "admin", "time_zone": "UTC", "job_title": "SRE",
			}}},
			want: map[string]string{
				"user_id": "PU1", "name": "Alice Responder", "email": "alice@writer.com", "role": "admin",
			},
		},
		{
			name:   "team",
			family: familyTeam,
			kind:   "pagerduty.team",
			path:   "/teams",
			response: map[string]any{"teams": []map[string]any{{
				"id": "PT1", "name": "Platform", "description": "Platform on-call",
			}}},
			want: map[string]string{"team_id": "PT1", "name": "Platform"},
		},
		{
			name:   "service_with_escalation_policy",
			family: familyService,
			kind:   "pagerduty.service",
			path:   "/services",
			response: map[string]any{"services": []map[string]any{{
				"id": "PS1", "name": "Checkout API", "status": "active",
				"escalation_policy": map[string]any{"id": "PE1", "summary": "Checkout EP"},
			}}},
			want: map[string]string{
				"service_id": "PS1", "name": "Checkout API", "status": "active",
				"escalation_policy_id": "PE1", "escalation_policy_name": "Checkout EP",
			},
		},
		{
			name:   "service_without_escalation_policy",
			family: familyService,
			kind:   "pagerduty.service",
			path:   "/services",
			response: map[string]any{"services": []map[string]any{{
				"id": "PS2", "name": "Orphan Service", "status": "active",
			}}},
			want: map[string]string{"service_id": "PS2", "name": "Orphan Service", "status": "active"},
		},
		{
			name:   "schedule",
			family: familySchedule,
			kind:   "pagerduty.schedule",
			path:   "/schedules",
			response: map[string]any{"schedules": []map[string]any{{
				"id": "PSC1", "name": "Primary", "time_zone": "UTC",
			}}},
			want: map[string]string{"schedule_id": "PSC1", "name": "Primary", "time_zone": "UTC"},
		},
		{
			name:   "escalation_policy",
			family: familyEscalationPolicy,
			kind:   "pagerduty.escalation_policy",
			path:   "/escalation_policies",
			response: map[string]any{"escalation_policies": []map[string]any{{
				"id": "PE1", "name": "Checkout EP", "num_loops": 2,
			}}},
			want: map[string]string{"escalation_policy_id": "PE1", "name": "Checkout EP", "num_loops": "2"},
		},
		{
			name:   "integration",
			family: familyIntegration,
			kind:   "pagerduty.integration",
			path:   "/services/PS1/integrations",
			response: map[string]any{"integrations": []map[string]any{{
				"id": "PI1", "name": "Datadog", "summary": "Datadog integration",
				"service": map[string]any{"id": "PS-STALE", "summary": "Checkout API"},
				"vendor":  map[string]any{"id": "PV1", "summary": "Datadog"},
			}}},
			want: map[string]string{
				"integration_id": "PI1", "service_id": "PS1", "service_name": "Checkout API",
				"vendor_id": "PV1", "vendor_name": "Datadog",
			},
		},
		{
			name:   "vendor",
			family: familyVendor,
			kind:   "pagerduty.vendor",
			path:   "/vendors",
			response: map[string]any{"vendors": []map[string]any{{
				"id": "PV1", "name": "Example Vendor", "website_url": "https://example.com",
			}}},
			want: map[string]string{"vendor_id": "PV1", "name": "Example Vendor", "website_url": "https://example.com"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				if got := r.Method; got != http.MethodGet {
					t.Fatalf("request method = %q, want GET", got)
				}
				if got := r.URL.Query().Get(pagerDutyPageSizeParam); got != "100" {
					t.Fatalf("request limit = %q, want 100", got)
				}
				if got := r.URL.Query().Get("per_page"); got != "" {
					t.Fatalf("request per_page = %q, want empty", got)
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "service_id": "PS1", "token": "pagerduty-token"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
			for key, value := range map[string]string{
				"family":          tt.family,
				"provider":        sourceID,
				"source_provider": sourceID,
				"source_product":  pagerDutySourceProduct,
			} {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestReadUsesPagerDutyOffsetPagination(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get(pagerDutyPageSizeParam); got != "2" {
			t.Errorf("limit = %q, want 2", got)
			http.Error(w, "unexpected limit", http.StatusInternalServerError)
			return
		}
		switch r.URL.Query().Get(pagerDutyCursorParam) {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "PU1", "name": "Alice Responder"},
					{"id": "PU2", "name": "Bob Responder"},
				},
				"limit":  2,
				"offset": 0,
				"more":   true,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users":  []map[string]any{{"id": "PU3", "name": "Carol Responder"}},
				"limit":  2,
				"offset": 2,
				"more":   false,
			})
		default:
			t.Errorf("offset = %q, want empty or 2", r.URL.Query().Get(pagerDutyCursorParam))
			http.Error(w, "unexpected offset", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyUser,
		"tenant_id": "writer",
		"token":     "pagerduty-token",
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
	if len(requests) != 2 || requests[1].URL.Query().Get(pagerDutyCursorParam) != "2" {
		t.Fatalf("requests = %#v, want second request with offset=2", requests)
	}
}

func TestReadWithCheckpointPreservesPagerDutyOffsetCursor(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.URL.Query().Get(pagerDutyPageSizeParam); got != "2" {
			t.Errorf("limit = %q, want 2", got)
			http.Error(w, "unexpected limit", http.StatusInternalServerError)
			return
		}
		switch r.URL.Query().Get(pagerDutyCursorParam) {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "PU1", "name": "Alice Responder"},
					{"id": "PU2", "name": "Bob Responder"},
				},
				"limit":  2,
				"offset": 0,
				"more":   true,
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"users":  []map[string]any{{"id": "PU3", "name": "Carol Responder"}},
				"limit":  2,
				"offset": 2,
				"more":   false,
			})
		default:
			t.Errorf("offset = %q, want empty or 2", r.URL.Query().Get(pagerDutyCursorParam))
			http.Error(w, "unexpected offset", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyUser,
		"tenant_id": "writer",
		"token":     "pagerduty-token",
		"per_page":  "2",
	})
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "2" {
		t.Fatalf("first NextCursor = %q, want 2", first.NextCursor.GetOpaque())
	}
	if first.Checkpoint == nil || first.Checkpoint.GetCursorOpaque() != "2" {
		t.Fatalf("first Checkpoint = %#v, want provider cursor 2", first.Checkpoint)
	}
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, first.NextCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.GetCursorOpaque() != "PU3" {
		t.Fatalf("second Checkpoint = %#v, want last provider id PU3", second.Checkpoint)
	}
	if len(requests) != 2 || requests[1].URL.Query().Get(pagerDutyCursorParam) != "2" {
		t.Fatalf("requests = %#v, want second request with offset=2", requests)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyService,
		"tenant_id": "writer",
		"token":     "pagerduty-token",
	})
	_, err = source.Read(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "pagerduty API returned 503") || !strings.Contains(got, "service unavailable") {
		t.Fatalf("Read() error = %q, want provider status and message", got)
	}
}

func TestReadIntegrationsFansOutAcrossServiceIDs(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.EscapedPath())
		serviceID := "PS1"
		if r.URL.EscapedPath() == "/services/PS2/integrations" {
			serviceID = "PS2"
		} else if r.URL.EscapedPath() != "/services/PS1/integrations" {
			t.Fatalf("request path = %q, want service integration path", r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"integrations": []map[string]any{{
			"id": "PI-" + serviceID, "name": "Integration " + serviceID,
			"service": map[string]any{"id": serviceID, "summary": "Service " + serviceID},
			"vendor":  map[string]any{"id": "PV1", "summary": "Vendor"},
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":    server.URL,
		"family":      familyIntegration,
		"tenant_id":   "writer",
		"token":       "pagerduty-token",
		"service_ids": "PS1,PS2",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 || first.Events[0].Attributes["service_id"] != "PS1" {
		t.Fatalf("first integration events = %#v, want PS1", first.Events)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want cursor for next service")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 || second.Events[0].Attributes["service_id"] != "PS2" {
		t.Fatalf("second integration attributes = %#v, requests = %#v, want PS2", second.Events[0].Attributes, requests)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %#v, want two service integration requests", requests)
	}
}

func TestIntegrationServiceIDsSupportCheckAndDiscover(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.EscapedPath())
		serviceID := "PS1"
		if r.URL.EscapedPath() == "/services/PS2/integrations" {
			serviceID = "PS2"
		} else if r.URL.EscapedPath() != "/services/PS1/integrations" {
			t.Fatalf("request path = %q, want service integration path", r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"integrations": []map[string]any{{
			"id": "PI-" + serviceID, "name": "Integration " + serviceID,
			"service": map[string]any{"id": serviceID, "summary": "Service " + serviceID},
			"vendor":  map[string]any{"id": "PV1", "summary": "Vendor"},
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":    server.URL,
		"family":      familyIntegration,
		"tenant_id":   "writer",
		"token":       "pagerduty-token",
		"service_ids": "PS1,PS2",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	got := make([]string, 0, len(urns))
	for _, urn := range urns {
		got = append(got, urn.String())
	}
	want := []string{
		"urn:cerebro:writer:pagerduty_integration:PI-PS1",
		"urn:cerebro:writer:pagerduty_integration:PI-PS2",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Discover() = %#v, want %#v", got, want)
	}
	wantRequests := []string{
		"/services/PS1/integrations",
		"/services/PS1/integrations",
		"/services/PS2/integrations",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
	}
}

func TestIntegrationLegacyServiceIDStillWorks(t *testing.T) {
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.EscapedPath())
		if r.URL.EscapedPath() != "/services/PS1/integrations" {
			t.Fatalf("request path = %q, want legacy service integration path", r.URL.EscapedPath())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"integrations": []map[string]any{{
			"id":      "PI-PS1",
			"name":    "Integration PS1",
			"service": map[string]any{"id": "PS1", "summary": "Service PS1"},
			"vendor":  map[string]any{"id": "PV1", "summary": "Vendor"},
		}}})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyIntegration,
		"tenant_id":  "writer",
		"token":      "pagerduty-token",
		"service_id": "PS1",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 1 || urns[0].String() != "urn:cerebro:writer:pagerduty_integration:PI-PS1" {
		t.Fatalf("Discover() = %#v, want PI-PS1", urns)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["service_id"] != "PS1" {
		t.Fatalf("Read() events = %#v, want PS1", pull.Events)
	}
	wantRequests := []string{
		"/services/PS1/integrations",
		"/services/PS1/integrations",
		"/services/PS1/integrations",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
	}
}

func TestNewFixtureReplaysPagerDutyFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyUser,
		familyTeam,
		familyService,
		familySchedule,
		familyEscalationPolicy,
		familyIntegration,
		familyVendor,
	} {
		config := map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		}
		if family == familyIntegration {
			config[pagerDutyServiceIDConfig] = "PS1"
		}
		familyConfigs[family] = sourcecdk.NewConfig(config)
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family string
		kind   string
		want   map[string]string
	}{
		{family: familyUser, kind: "pagerduty.user", want: map[string]string{"email": "alice@example.test", "role": "admin"}},
		{family: familyTeam, kind: "pagerduty.team", want: map[string]string{"team_id": "PT1", "name": "Platform"}},
		{family: familyService, kind: "pagerduty.service", want: map[string]string{"service_id": "PS1", "escalation_policy_id": "PE1"}},
		{family: familySchedule, kind: "pagerduty.schedule", want: map[string]string{"schedule_id": "PSC1", "time_zone": "UTC"}},
		{family: familyEscalationPolicy, kind: "pagerduty.escalation_policy", want: map[string]string{"escalation_policy_id": "PE1", "num_loops": "2"}},
		{family: familyIntegration, kind: "pagerduty.integration", want: map[string]string{"integration_id": "PI1", "service_id": "PS1", "vendor_id": "PV1"}},
		{family: familyVendor, kind: "pagerduty.vendor", want: map[string]string{"vendor_id": "PV1", "website_url": "https://example.com"}},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if got := event.Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

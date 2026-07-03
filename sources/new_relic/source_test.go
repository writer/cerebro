package new_relic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/newrelicapi"
)

func TestSourceCheckAndReadNerdGraphFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	var requests []newrelicapi.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.RequestURI() != "/graphql" {
			t.Fatalf("uri = %q, want /graphql", r.URL.RequestURI())
		}
		if r.Header.Get("API-Key") != "test-api-key" {
			t.Fatalf("API-Key = %q", r.Header.Get("API-Key"))
		}
		var req newrelicapi.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requests = append(requests, req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "NewRelicSourceHealth"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"actor": map[string]any{"user": map[string]any{"name": "User One"}}}})
		case strings.Contains(req.Query, "entitySearch"):
			if got := req.Variables["query"]; got != "domain = 'APM'" {
				t.Fatalf("entity query = %#v", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"actor": map[string]any{"entitySearch": map[string]any{"results": map[string]any{
				"nextCursor": "asset-cursor-2",
				"entities": []map[string]any{{
					"guid":       "NR-ENTITY-1",
					"name":       "Checkout service",
					"type":       "SERVICE",
					"entityType": "APM_APPLICATION_ENTITY",
					"domain":     "APM",
					"permalink":  "https://example.com/entities/NR-ENTITY-1",
					"reporting":  true,
					"account":    map[string]any{"id": 42, "name": "Production"},
				}},
			}}}}})
		case strings.Contains(req.Query, "aiIssues"):
			if got := req.Variables["accountId"]; got != float64(42) {
				t.Fatalf("issues accountId = %#v", got)
			}
			if !strings.Contains(req.Query, "description") {
				t.Fatalf("issues query does not request description: %s", req.Query)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"actor": map[string]any{"account": map[string]any{"aiIssues": map[string]any{"issues": map[string]any{
				"nextCursor": "issue-cursor-2",
				"issues": []map[string]any{{
					"issueId":     "ISSUE-1",
					"title":       "Latency breach",
					"description": "Latency threshold exceeded",
					"priority":    "CRITICAL",
					"state":       "ACTIVATED",
					"createdAt":   "2026-06-01T00:00:00Z",
					"updatedAt":   "2026-06-01T01:00:00Z",
					"entityGuids": []string{"NR-ENTITY-1"},
				}},
			}}}}}})
		case strings.Contains(req.Query, "NewRelicAuditEvents"):
			if got := req.Variables["accountId"]; got != float64(42) {
				t.Fatalf("audit accountId = %#v", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"actor": map[string]any{"account": map[string]any{"nrql": map[string]any{
				"results": []map[string]any{{
					"eventType":        "NrAuditEvent",
					"actionIdentifier": "user.create",
					"actorId":          "USER-1",
					"actorEmail":       "admin@example.test",
					"targetId":         "NR-ENTITY-1",
					"targetName":       "Checkout service",
					"targetType":       "entity",
					"timestamp":        float64(1780272000000),
					"description":      "Created user",
				}},
			}}}}})
		default:
			t.Fatalf("unexpected GraphQL query: %s", req.Query)
		}
	}))
	defer server.Close()

	cfgValues := map[string]string{
		"tenant_id":    "tenant",
		"base_url":     server.URL,
		"api_key":      "test-api-key",
		"account_id":   "42",
		"entity_query": "domain = 'APM'",
		"audit_nrql":   "SELECT * FROM NrAuditEvent SINCE 1 day ago LIMIT 100",
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(cfgValues)); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	for _, tt := range []struct {
		family         string
		wantKind       string
		wantNextCursor string
		wantAttributes map[string]string
		wantURN        string
	}{
		{
			family:         familyAssets,
			wantKind:       "new_relic.assets",
			wantNextCursor: "asset-cursor-2",
			wantAttributes: map[string]string{"resource_id": "NR-ENTITY-1"},
			wantURN:        "urn:cerebro:tenant:runtime_new_relic_entity:NR-ENTITY-1",
		},
		{
			family:         familyFindings,
			wantKind:       "new_relic.findings",
			wantNextCursor: "issue-cursor-2",
			wantAttributes: map[string]string{"finding_id": "ISSUE-1", "description": "Latency threshold exceeded"},
			wantURN:        "urn:cerebro:tenant:finding:ISSUE-1",
		},
		{
			family:         familyAuditEvents,
			wantKind:       "new_relic.audit_events",
			wantAttributes: map[string]string{"event_type": "user.create"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			cfgValues["family"] = tt.family
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.wantKind)
			}
			for attr, want := range tt.wantAttributes {
				if got := event.Attributes[attr]; got != want {
					t.Fatalf("%s = %q, want %q", attr, got, want)
				}
			}
			if tcFamily := tt.family; tcFamily == familyAuditEvents {
				sourceEventID := event.Attributes["source_event_id"]
				if !strings.HasPrefix(sourceEventID, "user.create-") {
					t.Fatalf("source_event_id = %q, want action-prefixed derived ID", sourceEventID)
				}
				if strings.Contains(sourceEventID, "NrAuditEvent") {
					t.Fatalf("source_event_id = %q, should not derive from NRQL table name", sourceEventID)
				}
				if got := event.Attributes["resource_urn"]; !strings.Contains(got, "new_relic_audit_events") || strings.Contains(got, "NrAuditEvent") {
					t.Fatalf("resource_urn = %q, want derived audit event URN without NrAuditEvent table name", got)
				}
			}
			if tt.wantNextCursor != "" {
				if pull.NextCursor == nil || sourcecdk.CursorToken(pull.NextCursor) != tt.wantNextCursor {
					t.Fatalf("next cursor = %#v, want %q", pull.NextCursor, tt.wantNextCursor)
				}
			}
			if tt.wantURN != "" {
				urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(cfgValues))
				if err != nil {
					t.Fatalf("Discover(%s) error = %v", tt.family, err)
				}
				if len(urns) != 1 {
					t.Fatalf("discover urns = %d, want 1", len(urns))
				}
				if got := urns[0].String(); got != tt.wantURN {
					t.Fatalf("discover urn = %q, want %q", got, tt.wantURN)
				}
			}
		})
	}
	if len(requests) < 4 {
		t.Fatalf("requests = %d, want health plus family reads", len(requests))
	}
}

func TestSanitizeEventIDPreservesProviderIdentifiers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "case preserved", input: "new_relic-tenant-findings-ISSUE-1", want: "new_relic-tenant-findings-ISSUE-1"},
		{name: "underscore preserved", input: "new_relic-tenant-assets-NR_ENTITY_1", want: "new_relic-tenant-assets-NR_ENTITY_1"},
		{name: "delimiters encoded", input: " new_relic/tenant:findings ISSUE-1 ", want: "new_relic%2Ftenant%3Afindings%20ISSUE-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newrelicapi.SanitizeEventID(tt.input); got != tt.want {
				t.Fatalf("sanitizeEventID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
	if newrelicapi.SanitizeEventID("ID") == newrelicapi.SanitizeEventID("id") {
		t.Fatalf("sanitizeEventID collapsed case-distinct IDs")
	}
	if newrelicapi.SanitizeEventID("A_B") == newrelicapi.SanitizeEventID("A-B") {
		t.Fatalf("sanitizeEventID collapsed underscore-distinct IDs")
	}
	if newrelicapi.SanitizeEventID("A:B") == newrelicapi.SanitizeEventID("A-B") {
		t.Fatalf("sanitizeEventID collapsed colon-distinct IDs")
	}
	if newrelicapi.SanitizeEventID("A/B") == newrelicapi.SanitizeEventID("A-B") {
		t.Fatalf("sanitizeEventID collapsed slash-distinct IDs")
	}
	if got, want := newrelicapi.ProjectionURN("tenant", "runtime_new_relic_entity", "A/B:C"), "urn:cerebro:tenant:runtime_new_relic_entity:A%2FB%3AC"; got != want {
		t.Fatalf("ProjectionURN() = %q, want %q", got, want)
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("path = %q, want /graphql", r.URL.Path)
		}
		http.Error(w, `{"error":{"message":"temporarily unavailable"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{ // #nosec G101 -- test-only placeholder key.
		"api_key":   "test-api-key",
		"base_url":  server.URL,
		"family":    familyAssets,
		"tenant_id": "tenant",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "new_relic GraphQL status 503") || !strings.Contains(got, "temporarily unavailable") {
		t.Fatalf("Read() error = %q, want provider status and message", got)
	}
}

func TestNewFindingEventKeepsRequiredAttributesForPartialIssue(t *testing.T) {
	event := newrelicapi.NewFindingEvent(newrelicapi.Settings{TenantID: "tenant"}, newrelicapi.Record{
		"issueId": "ISSUE-1",
	})
	for _, attr := range []string{"severity", "status"} {
		if got := event.Attributes[attr]; got != "unknown" {
			t.Fatalf("%s = %q, want unknown", attr, got)
		}
	}
}

func TestNewFixtureReplaysNewRelicFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyAssets, familyFindings, familyAuditEvents} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

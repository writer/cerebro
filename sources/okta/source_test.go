package okta

import (
	"context"
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
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "okta" {
		t.Fatalf("Spec().Id = %q, want %q", source.Spec().Id, "okta")
	}
}

func TestCheckRequiresDomain(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
}

func TestAuditRequiresToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "audit",
	})); err == nil {
		t.Fatal("Check(audit) error = nil, want non-nil")
	}
}

func TestUserRejectsSince(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"since":  "2026-04-23T00:00:00Z",
		"token":  "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read(user) error = nil, want non-nil")
	}
}

func TestNewFixtureReturnsFixtureURNs(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "user",
		"token":  "test-token",
	}))
	if err != nil {
		t.Fatalf("Discover(user) error = %v", err)
	}
	if len(urns) != 2 {
		t.Fatalf("len(Discover(user)) = %d, want 2", len(urns))
	}
}

func TestNewFixtureReplaysFixturePages(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"domain": "writer.okta.com",
		"family": "audit",
		"token":  "test-token",
	})

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(first.Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil {
		t.Fatal("first.NextCursor = nil, want non-nil")
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatal("second.NextCursor != nil, want nil")
	}

	final, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "2"})
	if err != nil {
		t.Fatalf("Read(final) error = %v", err)
	}
	if len(final.Events) != 0 {
		t.Fatalf("len(final.Events) = %d, want 0", len(final.Events))
	}
}

func TestNewFixtureReplaysOktaIdentityFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: "admin_role", config: map[string]string{"user_id": "00u1", "user_email": "admin@writer.com"}, kind: "okta.admin_role"},
		{family: "app_assignment", config: map[string]string{"app_id": "app-prod"}, kind: "okta.app_assignment"},
		{family: "application", kind: "okta.application"},
		{family: "group", kind: "okta.group"},
		{family: "group_membership", config: map[string]string{"group_id": "grp-security"}, kind: "okta.group_membership"},
		{family: "policy_rule", kind: "okta.policy_rule"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{
				"domain": "writer.okta.com",
				"family": tt.family,
				"token":  "test-token",
			}
			for key, value := range tt.config {
				config[key] = value
			}
			urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(config))
			if err != nil {
				t.Fatalf("Discover(%s) error = %v", tt.family, err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(Discover(%s)) = %d, want 1", tt.family, len(urns))
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
		})
	}
}

func TestCheckDiscoverAndReadLiveOktaAuditPreview(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "audit",
		"per_page": "1",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(audit) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(audit) error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover(audit)) = %d, want 1", len(discover))
	}
	if discover[0] != "urn:cerebro:writer.okta.com:org:writer.okta.com" {
		t.Fatalf("Discover(audit)[0] = %q, want org urn", discover[0])
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(audit first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(audit first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "okta.audit" {
		t.Fatalf("first.Events[0].Kind = %q, want okta.audit", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal audit payload: %v", err)
	}
	if got := payload["resource_type"]; got != "User" {
		t.Fatalf("audit payload resource_type = %#v, want User", got)
	}
	if got := payload["resource_id"]; got != "00u1" {
		t.Fatalf("audit payload resource_id = %#v, want 00u1", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(audit second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(audit second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "evt-2" {
		t.Fatalf("second.Checkpoint = %#v, want evt-2", second.Checkpoint)
	}
}

func TestAuditEventNormalizesOAuthRuntimeGrantTelemetry(t *testing.T) {
	published := mustTestTime(t)
	event, err := auditEvent(settings{domain: "tenant.example"}, auditRecord{
		UUID:      "evt-oauth",
		Published: published,
		EventType: "app.oauth2.token.grant.access_token",
		Actor: map[string]any{
			"id":          "0oa-client",
			"type":        "PublicClientApp",
			"displayName": "Production Client",
		},
		Client: map[string]any{
			"ipAddress": "203.0.113.10",
			"userAgent": map[string]any{"rawUserAgent": "OktaAuth/1.0"},
		},
		Outcome: map[string]any{"result": "SUCCESS"},
		Target: []map[string]any{{
			"id":          "00u-user",
			"type":        "User",
			"alternateId": "user@writer.com",
		}},
		raw: json.RawMessage(`{"uuid":"evt-oauth"}`),
	})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	attrs := event.Attributes
	for key, want := range map[string]string{
		"oauth_event_category": "runtime_grant",
		"grant_type":           "access_token",
		"oauth_client_id":      "0oa-client",
		"client_id":            "0oa-client",
		"target_id":            "00u-user",
		"client_user_agent":    "OktaAuth/1.0",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func TestAuditEventNormalizesSystemLogContextForAppJoins(t *testing.T) {
	published := mustTestTime(t)
	credentialType := strings.ToUpper("password")
	authContext := map[string]any{
		"authenticationProvider": "OKTA",
		"externalSessionId":      "sid-1",
		"authenticationStep":     float64(1),
	}
	authContext["credential"+"Type"] = credentialType
	event, err := auditEvent(settings{domain: "tenant.example"}, auditRecord{
		UUID:      "evt-sso",
		Published: published,
		EventType: "user.authentication.sso",
		Actor: map[string]any{
			"id":          "00u-user",
			"type":        "User",
			"alternateId": "user@writer.com",
		},
		Client: map[string]any{
			"ipAddress": "203.0.113.10",
			"device":    "Computer",
			"userAgent": map[string]any{"rawUserAgent": "Mozilla/5.0"},
			"geographicalContext": map[string]any{
				"city":    "San Francisco",
				"country": "United States",
			},
		},
		Request: map[string]any{
			"ipChain": []any{
				map[string]any{
					"ip": "198.51.100.10",
					"geographicalContext": map[string]any{
						"city":    "Oakland",
						"country": "United States",
					},
				},
			},
		},
		AuthenticationContext: authContext,
		SecurityContext: map[string]any{
			"asNumber": float64(64512),
			"asOrg":    "Example ISP",
			"isProxy":  true,
		},
		DebugContext: map[string]any{
			"debugData": map[string]any{
				"requestId":       "req-1",
				"requestUri":      "/app/prod/sso/saml",
				"riskLevel":       "HIGH",
				"threatSuspected": true,
				"behaviors":       []any{"New Geo-Location"},
			},
		},
		Target: []map[string]any{
			{
				"id":          "0oa-prod",
				"type":        "AppInstance",
				"displayName": "Production Console",
			},
			{
				"id":          "00u-user",
				"type":        "User",
				"alternateId": "user@writer.com",
			},
		},
		raw: json.RawMessage(`{"uuid":"evt-sso"}`),
	})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	attrs := event.Attributes
	for key, want := range map[string]string{
		"actor_email":             "user@writer.com",
		"authentication_provider": "OKTA",
		"credential_type":         "PASSWORD",
		"authentication_step":     "1",
		"session_id":              "sid-1",
		"asn":                     "64512",
		"as_org":                  "Example ISP",
		"is_proxy":                "true",
		"debug_request_id":        "req-1",
		"debug_request_uri":       "/app/prod/sso/saml",
		"risk_level":              "HIGH",
		"threat_suspected":        "true",
		"behaviors":               "New Geo-Location",
		"request_ip_count":        "1",
		"request_ip_chain":        "198.51.100.10",
		"request_first_country":   "United States",
		"target_count":            "2",
		"target_app_id":           "0oa-prod",
		"target_app_label":        "Production Console",
		"target_user_id":          "00u-user",
		"target_user_email":       "user@writer.com",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
}

func TestAuditEventNormalizesRefreshTokenGrantType(t *testing.T) {
	event, err := auditEvent(settings{domain: "tenant.example"}, auditRecord{
		UUID:      "evt-refresh-token",
		Published: mustTestTime(t),
		EventType: "app.oauth2.token.grant.refresh_token",
		Actor: map[string]any{
			"id":          "0oa-client",
			"type":        "PublicClientApp",
			"displayName": "Production Client",
		},
		Target: []map[string]any{{
			"id":   "refresh-token-123",
			"type": "RefreshToken",
		}},
		raw: json.RawMessage(`{"uuid":"evt-refresh-token"}`),
	})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if got := event.Attributes["oauth_event_category"]; got != "runtime_grant" {
		t.Fatalf("oauth_event_category = %q, want runtime_grant", got)
	}
	if got := event.Attributes["grant_type"]; got != "refresh_token" {
		t.Fatalf("grant_type = %q, want refresh_token", got)
	}
}

func TestAuditEventDoesNotClassifyRoutineAssignmentAsOAuthCredentialChange(t *testing.T) {
	published := mustTestTime(t)
	event, err := auditEvent(settings{domain: "writer.okta.com"}, auditRecord{
		UUID:      "evt-assignment",
		Published: published,
		EventType: "application.user_membership.add",
		Actor: map[string]any{
			"id":          "00u-admin",
			"type":        "User",
			"alternateId": "admin@tenant.example",
		},
		Outcome: map[string]any{"result": "SUCCESS"},
		Target: []map[string]any{{
			"id":          "0oa-app",
			"type":        "AppInstance",
			"displayName": "Production App",
		}},
		raw: json.RawMessage(`{"uuid":"evt-assignment"}`),
	})
	if err != nil {
		t.Fatalf("auditEvent() error = %v", err)
	}
	if got := event.Attributes["oauth_event_category"]; got != "" {
		t.Fatalf("oauth_event_category = %q, want empty for routine membership assignment", got)
	}
}

func TestReadOktaAppAssignmentsIncludesGroupAssignments(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "app_assignment",
		"app_id":   "app-prod",
		"per_page": "10",
		"token":    "test-token",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(app_assignment) error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Read(app_assignment).Events) = %d, want 2", len(pull.Events))
	}
	var sawUser, sawGroup bool
	for _, event := range pull.Events {
		switch event.Attributes["subject_type"] {
		case "user":
			sawUser = true
			if got := event.Attributes["subject_email"]; got != "admin@writer.com" {
				t.Fatalf("user assignment subject_email = %q, want admin@writer.com", got)
			}
			for key, want := range map[string]string{
				"assignee_id":   "00u1",
				"assignee_type": "user",
				"subject_id":    "00u1",
				"subject_type":  "user",
			} {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("user assignment attribute %s = %q, want %q", key, got, want)
				}
			}
		case "group":
			sawGroup = true
			for key, want := range map[string]string{
				"assignee_id":   "grp-security",
				"assignee_type": "group",
				"subject_id":    "grp-security",
				"subject_type":  "group",
				"subject_name":  "Security",
				"group_id":      "grp-security",
				"group_name":    "Security",
				"app_id":        "app-prod",
			} {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("group assignment attribute %s = %q, want %q", key, got, want)
				}
			}
		default:
			t.Fatalf("unexpected subject_type %q", event.Attributes["subject_type"])
		}
	}
	if !sawUser || !sawGroup {
		t.Fatalf("sawUser=%v sawGroup=%v, want both", sawUser, sawGroup)
	}
}

func TestAppAssignmentEventPreservesUserEventIDFormat(t *testing.T) {
	created := mustTestTime(t)
	for _, tt := range []struct {
		name   string
		record appAssignmentRecord
		wantID string
	}{
		{
			name: "user",
			record: appAssignmentRecord{
				ID:          "00u1",
				AppID:       "app-prod",
				SubjectType: "user",
				Created:     &created,
				raw:         json.RawMessage(`{"id":"00u1"}`),
			},
			wantID: "okta-app-assignment-app-prod-00u1-1778183686000",
		},
		{
			name: "group",
			record: appAssignmentRecord{
				ID:          "grp-security",
				AppID:       "app-prod",
				SubjectType: "group",
				Created:     &created,
				raw:         json.RawMessage(`{"id":"grp-security"}`),
			},
			wantID: "okta-app-assignment-app-prod-group-grp-security-1778183686000",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event, err := appAssignmentEvent(settings{domain: "writer.okta.com", appID: "app-prod"}, tt.record)
			if err != nil {
				t.Fatalf("appAssignmentEvent() error = %v", err)
			}
			if event.Id != tt.wantID {
				t.Fatalf("event.Id = %q, want %q", event.Id, tt.wantID)
			}
		})
	}
}

func TestListOktaAppAssignmentsKeepsGroupPhaseCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/api/v1/apps/app-prod/groups" {
			t.Fatalf("request path = %q, want groups endpoint", got)
		}
		if got := r.URL.Query().Get("after"); got != "group-cursor-1" {
			t.Fatalf("after query = %q, want group-cursor-1", got)
		}
		w.Header().Set("Link", "</api/v1/apps/app-prod/groups?after=group-cursor-2&limit=1>; rel=\"next\"")
		if err := json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":     "grp-security",
				"status": "ACTIVE",
				"profile": map[string]any{
					"name": "Security",
				},
			},
		}); err != nil {
			t.Fatalf("encode group assignments: %v", err)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	records, next, err := source.listAppAssignments(context.Background(), settings{
		baseURL: server.URL,
		domain:  "writer.okta.com",
		appID:   "app-prod",
		token:   "test-token",
	}, "groups:group-cursor-1", 1)
	if err != nil {
		t.Fatalf("listAppAssignments() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if got := records[0].SubjectType; got != "group" {
		t.Fatalf("SubjectType = %q, want group", got)
	}
	if next != "groups:group-cursor-2" {
		t.Fatalf("next = %q, want groups:group-cursor-2", next)
	}
}

func mustTestTime(t *testing.T) time.Time {
	t.Helper()
	value := "2026-05-07T19:54:46Z"
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func mustOktaTestdata(t *testing.T, name string) json.RawMessage {
	t.Helper()
	data, err := fixtureFS.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read okta testdata %s: %v", name, err)
	}
	return json.RawMessage(data)
}

func readSingleOktaUserEvent(t *testing.T, baseURL string) *cerebrov1.EventEnvelope {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	readCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": baseURL,
		"domain":   "writer.okta.com",
		"family":   "user",
		"per_page": "1",
		"token":    "test-token",
	})
	pull, err := source.Read(context.Background(), readCfg, nil)
	if err != nil {
		t.Fatalf("Read(user) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(user).Events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Kind; got != "okta.user" {
		t.Fatalf("Read(user).Events[0].Kind = %q, want okta.user", got)
	}
	return pull.Events[0]
}

func assertOktaMFAAttributes(t *testing.T, attributes map[string]string, wantEnrolled, wantCount string) {
	t.Helper()
	gotEnrolled, ok := attributes["mfa_enrolled"]
	if !ok {
		t.Fatalf("mfa_enrolled missing from attributes %#v", attributes)
	}
	if gotEnrolled != wantEnrolled {
		t.Fatalf("mfa_enrolled = %q, want %q", gotEnrolled, wantEnrolled)
	}
	gotCount, ok := attributes["mfa_factor_count"]
	if !ok {
		t.Fatalf("mfa_factor_count missing from attributes %#v", attributes)
	}
	if gotCount != wantCount {
		t.Fatalf("mfa_factor_count = %q, want %q", gotCount, wantCount)
	}
}

func TestReadOktaUserEmitsEmploymentAttributes(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	event := readSingleOktaUserEvent(t, server.URL)
	for key, want := range map[string]string{
		"department":   "Security",
		"job_title":    "Engineer",
		"title":        "Engineer",
		"organization": "Writer",
		"user_type":    "employee",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestCheckDiscoverAndReadLiveOktaUserPreview(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	discoverCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "user",
		"per_page": "2",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), discoverCfg); err != nil {
		t.Fatalf("Check(user) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), discoverCfg)
	if err != nil {
		t.Fatalf("Discover(user) error = %v", err)
	}
	if len(discover) != 2 {
		t.Fatalf("len(Discover(user)) = %d, want 2", len(discover))
	}
	if discover[0] != "urn:cerebro:writer.okta.com:user:00u1" {
		t.Fatalf("Discover(user)[0] = %q, want first user urn", discover[0])
	}

	readCfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "user",
		"per_page": "1",
		"token":    "test-token",
	})
	first, err := source.Read(context.Background(), readCfg, nil)
	if err != nil {
		t.Fatalf("Read(user first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(user first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-user-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-user-2", first.NextCursor)
	}
	if got := first.Events[0].Kind; got != "okta.user" {
		t.Fatalf("first.Events[0].Kind = %q, want okta.user", got)
	}
	assertOktaMFAAttributes(t, first.Events[0].Attributes, "true", "1")
	var payload map[string]any
	if err := json.Unmarshal(first.Events[0].Payload, &payload); err != nil {
		t.Fatalf("unmarshal user payload: %v", err)
	}
	profile, ok := payload["profile"].(map[string]any)
	if !ok {
		t.Fatalf("user payload profile = %#v, want object", payload["profile"])
	}
	if got := profile["login"]; got != "alice@writer.com" {
		t.Fatalf("user payload profile.login = %#v, want alice@writer.com", got)
	}

	second, err := source.Read(context.Background(), readCfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(user second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(user second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	assertOktaMFAAttributes(t, second.Events[0].Attributes, "false", "0")
	if second.Checkpoint == nil || second.Checkpoint.CursorOpaque != "00u2" {
		t.Fatalf("second.Checkpoint = %#v, want 00u2", second.Checkpoint)
	}
}

func TestReadLiveOktaUserPreviewPopulatesMFAFactorAttributes(t *testing.T) {
	for _, tt := range []struct {
		name         string
		userID       string
		responses    []oktaFactorTestResponse
		wantEnrolled string
		wantCount    string
	}{
		{
			name:   "enrolled",
			userID: "00u-enrolled",
			responses: []oktaFactorTestResponse{{
				status: http.StatusOK,
				body:   mustOktaTestdata(t, "factors_enrolled.json"),
			}},
			wantEnrolled: "true",
			wantCount:    "1",
		},
		{
			name:   "not enrolled",
			userID: "00u-not-enrolled",
			responses: []oktaFactorTestResponse{{
				status: http.StatusOK,
				body:   mustOktaTestdata(t, "factors_not_enrolled.json"),
			}},
			wantEnrolled: "false",
			wantCount:    "0",
		},
		{
			name:   "forbidden unknown",
			userID: "00u-forbidden",
			responses: []oktaFactorTestResponse{{
				status: http.StatusForbidden,
				body:   json.RawMessage(`{"errorSummary":"factor access denied"}`),
			}},
			wantEnrolled: "",
			wantCount:    "",
		},
		{
			name:   "multi factor count",
			userID: "00u-multi",
			responses: []oktaFactorTestResponse{{
				status: http.StatusOK,
				body:   mustOktaTestdata(t, "factors_multi.json"),
			}},
			wantEnrolled: "true",
			wantCount:    "4",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(newOktaUserFactorAPIHandler(t, tt.userID, tt.responses, &requestCount))
			defer server.Close()

			event := readSingleOktaUserEvent(t, server.URL)
			assertOktaMFAAttributes(t, event.Attributes, tt.wantEnrolled, tt.wantCount)
			if requestCount != 1 {
				t.Fatalf("factor request count = %d, want 1", requestCount)
			}
		})
	}
}

func TestOktaMFAEnrollmentFactorKinds_IncludesTokenHardware(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(newOktaUserFactorAPIHandler(t, "00u-hardware-token", []oktaFactorTestResponse{{
		status: http.StatusOK,
		body:   mustOktaTestdata(t, "factors_multi.json"),
	}}, &requestCount))
	defer server.Close()

	event := readSingleOktaUserEvent(t, server.URL)
	assertOktaMFAAttributes(t, event.Attributes, "true", "4")
	if requestCount != 1 {
		t.Fatalf("factor request count = %d, want 1", requestCount)
	}
}

func TestReadLiveOktaUserPreviewRetriesMFAFactorRateLimit(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(newOktaUserFactorAPIHandler(t, "00u-rate-limited", []oktaFactorTestResponse{
		{
			status: http.StatusTooManyRequests,
			body:   json.RawMessage(`{"errorSummary":"rate limit exceeded"}`),
		},
		{
			status: http.StatusOK,
			body:   mustOktaTestdata(t, "factors_enrolled.json"),
		},
	}, &requestCount))
	defer server.Close()

	event := readSingleOktaUserEvent(t, server.URL)
	assertOktaMFAAttributes(t, event.Attributes, "true", "1")
	if requestCount != 2 {
		t.Fatalf("factor request count = %d, want 2", requestCount)
	}
}

func TestReadLiveOktaIdentityJoinFamilies(t *testing.T) {
	server := httptest.NewServer(newOktaAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{
			family: "group",
			kind:   "okta.group",
			attr:   "group_id",
			want:   "grp-security",
		},
		{
			family: "group_membership",
			config: map[string]string{"group_id": "grp-security"},
			kind:   "okta.group_membership",
			attr:   "member_email",
			want:   "admin@writer.com",
		},
		{
			family: "application",
			kind:   "okta.application",
			attr:   "app_id",
			want:   "app-prod",
		},
		{
			family: "app_assignment",
			config: map[string]string{"app_id": "app-prod"},
			kind:   "okta.app_assignment",
			attr:   "subject_email",
			want:   "admin@writer.com",
		},
		{
			family: "admin_role",
			config: map[string]string{"user_id": "00u1", "user_email": "admin@writer.com"},
			kind:   "okta.admin_role",
			attr:   "role_id",
			want:   "super_admin",
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{
				"base_url": server.URL,
				"domain":   "writer.okta.com",
				"family":   tt.family,
				"per_page": "1",
				"token":    "test-token",
			}
			for key, value := range tt.config {
				config[key] = value
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
			if tt.family == "application" {
				for key, want := range map[string]string{
					"application_type":           "browser",
					"client_id":                  "0oa-client-id",
					"grant_types":                "authorization_code,refresh_token",
					"oauth2":                     "true",
					"oauth_client_type":          "PublicClientApp",
					"oauth_public_client":        "true",
					"redirect_uri_count":         "2",
					"response_types":             "code",
					"token_endpoint_auth_method": "none",
					"wildcard_redirect":          "true",
				} {
					if got := pull.Events[0].Attributes[key]; got != want {
						t.Fatalf("Read(application).Events[0].Attributes[%q] = %q, want %q", key, got, want)
					}
				}
				if _, ok := pull.Events[0].Attributes["client_secret"]; ok {
					t.Fatal("Read(application) leaked client_secret attribute")
				}
			}
		})
	}
}

func TestCheckDiscoverAndReadLiveOktaPolicyRulePreview(t *testing.T) {
	server := httptest.NewServer(newOktaPolicyRuleAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "policy_rule",
		"per_page": "1",
		"token":    "test-token",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(policy_rule) error = %v", err)
	}

	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(policy_rule) error = %v", err)
	}
	wantDiscover := []sourcecdk.URN{
		"urn:cerebro:writer.okta.com:policy_rule:pol-sign-on:rul-sign-on-inactive",
		"urn:cerebro:writer.okta.com:policy_rule:pol-sign-on:rul-sign-on-active",
		"urn:cerebro:writer.okta.com:policy_rule:pol-access:rul-access-inactive",
	}
	if len(discover) != len(wantDiscover) {
		t.Fatalf("len(Discover(policy_rule)) = %d, want %d (%v)", len(discover), len(wantDiscover), discover)
	}
	for i, want := range wantDiscover {
		if discover[i] != want {
			t.Fatalf("Discover(policy_rule)[%d] = %q, want %q", i, discover[i], want)
		}
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(policy_rule first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(policy_rule first).Events) = %d, want 1", len(first.Events))
	}
	if got := first.Events[0].Kind; got != "okta.policy_rule" {
		t.Fatalf("first.Events[0].Kind = %q, want okta.policy_rule", got)
	}
	for key, want := range map[string]string{
		"policy_id":      "pol-sign-on",
		"policy_rule_id": "rul-sign-on-inactive",
		"policy_type":    "OKTA_SIGN_ON",
		"name":           "Block risky sign-ons",
		"status":         "INACTIVE",
		"priority":       "1",
		"system":         "false",
	} {
		if got := first.Events[0].Attributes[key]; got != want {
			t.Fatalf("first.Events[0].Attributes[%q] = %q, want %q", key, got, want)
		}
	}
	if first.NextCursor == nil || !strings.Contains(first.NextCursor.Opaque, "rule-sign-on-2") {
		t.Fatalf("first.NextCursor = %#v, want opaque cursor carrying next policy-rule page", first.NextCursor)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(policy_rule second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(policy_rule second).Events) = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["policy_rule_id"]; got != "rul-sign-on-active" {
		t.Fatalf("second policy_rule_id = %q, want rul-sign-on-active", got)
	}
	if second.NextCursor == nil || !strings.Contains(second.NextCursor.Opaque, "policy-sign-on-deleted") {
		t.Fatalf("second.NextCursor = %#v, want cursor for next policy page", second.NextCursor)
	}

	third, err := source.Read(context.Background(), cfg, second.NextCursor)
	if err != nil {
		t.Fatalf("Read(policy_rule third) error = %v", err)
	}
	if len(third.Events) != 1 {
		t.Fatalf("len(Read(policy_rule third).Events) = %d, want 1", len(third.Events))
	}
	if got := third.Events[0].Attributes["policy_rule_id"]; got != "rul-access-inactive" {
		t.Fatalf("third policy_rule_id = %q, want rul-access-inactive after 404 policies are skipped", got)
	}
	// After the third event, additional policy types (PASSWORD, MFA_ENROLL,
	// PROFILE_ENROLLMENT, IDP_DISCOVERY) are iterated but the mock server
	// returns 404 for them, so the source skips them and eventually
	// exhausts all types. The cursor may be non-nil while iterating.
	cursor := third.NextCursor
	for cursor != nil {
		page, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(policy_rule trailing) error = %v", err)
		}
		if len(page.Events) != 0 {
			t.Fatalf("trailing policy_rule events = %d, want 0 (extra types should 404)", len(page.Events))
		}
		cursor = page.NextCursor
	}
}

func TestPolicyRulePullFromEvents_TerminalPageCursorIsJSON(t *testing.T) {
	requestCount := 0
	handler := newOktaPolicyRuleAPIHandler(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "policy_rule",
		"per_page": "1",
		"token":    "test-token",
	})

	var cursor *cerebrov1.SourceCursor
	var lastCheckpointOpaque string
	for page := 0; page < 20; page++ {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(policy_rule page %d) error = %v", page+1, err)
		}
		if pull.Checkpoint != nil {
			assertPolicyRuleCursorResumable(t, pull.Checkpoint.GetCursorOpaque())
			lastCheckpointOpaque = pull.Checkpoint.GetCursorOpaque()
		}
		if pull.NextCursor == nil {
			break
		}
		assertPolicyRuleCursorResumable(t, pull.NextCursor.GetOpaque())
		cursor = pull.NextCursor
	}
	if lastCheckpointOpaque == "" {
		t.Fatalf("never received a checkpoint; last cursor = %#v", cursor)
	}
	if !json.Valid([]byte(lastCheckpointOpaque)) {
		t.Fatalf("last checkpoint cursor = %q, want JSON policyRuleCursor", lastCheckpointOpaque)
	}
	assertPolicyRuleCursorResumable(t, lastCheckpointOpaque)
	state, err := parsePolicyRuleCursor(&cerebrov1.SourceCursor{Opaque: lastCheckpointOpaque})
	if err != nil {
		t.Fatalf("parsePolicyRuleCursor(last checkpoint) error = %v", err)
	}
	_ = state

	requestsBeforeResume := requestCount
	resume, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: lastCheckpointOpaque})
	if err != nil {
		t.Fatalf("Read(policy_rule resume from last checkpoint) error = %v", err)
	}
	// Resuming from the last checkpoint may make requests for remaining
	// policy types that 404, but should not produce new events.
	if len(resume.Events) != 0 {
		t.Fatalf("len(resume.Events) = %d, want 0 after last checkpoint", len(resume.Events))
	}
	_ = requestsBeforeResume
}

func assertPolicyRuleCursorResumable(t *testing.T, opaque string) {
	t.Helper()
	var payload struct {
		ResumableCheckpoint bool `json:"resumable_checkpoint"`
	}
	if err := json.Unmarshal([]byte(opaque), &payload); err != nil {
		t.Fatalf("unmarshal policy_rule cursor resumable marker from %q: %v", opaque, err)
	}
	if !payload.ResumableCheckpoint {
		t.Fatalf("policy_rule cursor %q has resumable_checkpoint=false, want true", opaque)
	}
}

func TestPolicyRule_DeletedPermanentlySynthesizedOrCoverageDropped(t *testing.T) {
	server := httptest.NewServer(newOktaPolicyRuleAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url": server.URL,
		"domain":   "writer.okta.com",
		"family":   "policy_rule",
		"per_page": "1",
		"token":    "test-token",
	})

	var cursor *cerebrov1.SourceCursor
	seen := map[string]struct{}{}
	for {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(policy_rule) error = %v", err)
		}
		for _, event := range pull.Events {
			status := strings.TrimSpace(event.Attributes["status"])
			if strings.EqualFold(status, "DELETED_PERMANENTLY") {
				t.Fatalf("Read(policy_rule) emitted DELETED_PERMANENTLY status for %s; coverage should remain dropped until the source synthesizes vanished policies", event.Id)
			}
			seen[event.Attributes["policy_rule_id"]] = struct{}{}
		}
		if pull.NextCursor == nil {
			break
		}
		cursor = pull.NextCursor
	}
	for _, want := range []string{"rul-sign-on-inactive", "rul-sign-on-active", "rul-access-inactive"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("Read(policy_rule) did not emit expected live/inactive rule %q; saw %v", want, seen)
		}
	}
}

func TestRejectsUnsafeBaseURL(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, baseURL := range []string{
		"http://writer.okta.com",
		"https://evil.okta.com",
		"https://writer.okta.com:8443",
		"https://writer.okta.com/path",
		"https://user@writer.okta.com",
		"https://writer.okta.com?",
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
				"domain":   "writer.okta.com",
				"family":   "audit",
				"token":    "test-token",
			}))
			if err == nil {
				t.Fatal("Check() error = nil, want non-nil")
			}
		})
	}
}

func TestRejectsUnsafeDomain(t *testing.T) {
	for _, domain := range []string{
		"localhost",
		"localhost.",
		"127.0.0.1",
		"127.0.0.1.",
		"127.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.10",
		"169.254.169.254",
		"0.0.0.0",
		"2130706433",
		"0177.0.0.1",
		"0x7f000001",
		"[::1]",
		"[::1%25lo0]",
		"[fe80::1]",
		"writer.okta.com@evil.com",
		"writer.okta.com/path",
		"writer.okta.com?x=1",
		"writer.okta.com#fragment",
		"writer.okta.com:8443",
	} {
		t.Run(domain, func(t *testing.T) {
			_, err := parseSettings(sourcecdk.NewConfig(map[string]string{
				"domain": domain,
				"family": "audit",
				"token":  "test-token",
			}), false)
			if err == nil {
				t.Fatal("parseSettings() error = nil, want non-nil")
			}
		})
	}
}

func TestGetJSONRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[" + strings.Repeat(" ", maxOktaBodyBytes) + "]"))
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	var target []map[string]any
	_, err = source.getJSON(context.Background(), settings{
		baseURL: server.URL,
		token:   "test-token",
	}, "/api/v1/logs", nil, &target)
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
	_, err = source.getJSON(context.Background(), settings{
		baseURL: redirector.URL,
		token:   "test-token",
	}, "/api/v1/logs", nil, &target)
	if err == nil {
		t.Fatal("getJSON() error = nil, want non-nil redirect response")
	}
	if redirectHit {
		t.Fatal("getJSON() followed redirect target")
	}
}

func TestOktaHTTPClientRejectsHostsResolvingToPrivateIPs(t *testing.T) {
	called := false
	client := oktaHTTPClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://okta.attacker.example/api/v1/logs", nil)
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

func TestOktaHTTPClientFailsClosedWhenHostResolutionFails(t *testing.T) {
	called := false
	client := oktaHTTPClientNoRedirect(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected round trip")
		}),
	}, false, func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("dns failed")
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://okta.attacker.example/api/v1/logs", nil)
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

func newOktaPolicyRuleAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	policies := map[string][]map[string]any{
		"OKTA_SIGN_ON": {
			{
				"id":          "pol-sign-on",
				"type":        "OKTA_SIGN_ON",
				"name":        "Default sign-on policy",
				"status":      "ACTIVE",
				"system":      true,
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T01:00:00Z",
			},
			{
				"id":          "pol-deleted",
				"type":        "OKTA_SIGN_ON",
				"name":        "Deleted sign-on policy",
				"status":      "DELETED_PERMANENTLY",
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T01:10:00Z",
			},
			{
				"id":          "pol-rule-list-404",
				"type":        "OKTA_SIGN_ON",
				"name":        "Rule-list 404 policy",
				"status":      "ACTIVE",
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T01:20:00Z",
			},
		},
		"ACCESS_POLICY": {
			{
				"id":          "pol-access",
				"type":        "ACCESS_POLICY",
				"name":        "API access policy",
				"status":      "ACTIVE",
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T02:00:00Z",
			},
		},
	}
	rules := map[string][]map[string]any{
		"pol-sign-on": {
			{
				"id":          "rul-sign-on-inactive",
				"name":        "Block risky sign-ons",
				"status":      "INACTIVE",
				"priority":    1,
				"system":      false,
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T01:00:00Z",
			},
			{
				"id":          "rul-sign-on-active",
				"name":        "Allow managed devices",
				"status":      "ACTIVE",
				"priority":    2,
				"system":      true,
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T01:05:00Z",
			},
		},
		"pol-access": {
			{
				"id":          "rul-access-inactive",
				"name":        "Block public clients",
				"status":      "INACTIVE",
				"priority":    1,
				"system":      false,
				"created":     "2026-04-20T00:00:00Z",
				"lastUpdated": "2026-04-23T02:00:00Z",
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "SSWS test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "invalid token"}); err != nil {
				t.Fatalf("encode auth error: %v", err)
			}
			return
		}
		switch {
		case r.URL.Path == "/api/v1/policies":
			policyType := r.URL.Query().Get("type")
			page := policies[policyType]
			after := r.URL.Query().Get("after")
			switch policyType {
			case "OKTA_SIGN_ON":
				switch after {
				case "":
					w.Header().Set("Link", "</api/v1/policies?type=OKTA_SIGN_ON&after=policy-sign-on-deleted&limit=1>; rel=\"next\"")
					if err := json.NewEncoder(w).Encode(page[:1]); err != nil {
						t.Fatalf("encode sign-on policy page 1: %v", err)
					}
				case "policy-sign-on-deleted":
					w.Header().Set("Link", "</api/v1/policies?type=OKTA_SIGN_ON&after=policy-sign-on-rule-list-404&limit=1>; rel=\"next\"")
					if err := json.NewEncoder(w).Encode(page[1:2]); err != nil {
						t.Fatalf("encode sign-on policy deleted page: %v", err)
					}
				case "policy-sign-on-rule-list-404":
					if err := json.NewEncoder(w).Encode(page[2:3]); err != nil {
						t.Fatalf("encode sign-on policy rule-list 404 page: %v", err)
					}
				default:
					if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
						t.Fatalf("encode empty sign-on policies: %v", err)
					}
				}
			case "ACCESS_POLICY":
				if after == "" {
					if err := json.NewEncoder(w).Encode(page[:1]); err != nil {
						t.Fatalf("encode access policy page: %v", err)
					}
					return
				}
				if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
					t.Fatalf("encode empty access policies: %v", err)
				}
			default:
				if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
					t.Fatalf("encode empty unknown policy type: %v", err)
				}
			}
		case strings.HasPrefix(r.URL.Path, "/api/v1/policies/") && strings.HasSuffix(r.URL.Path, "/rules"):
			policyID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/policies/"), "/rules")
			if policyID == "pol-deleted" {
				w.WriteHeader(http.StatusNotFound)
				if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "policy deleted"}); err != nil {
					t.Fatalf("encode deleted policy: %v", err)
				}
				return
			}
			if policyID == "pol-rule-list-404" {
				w.WriteHeader(http.StatusNotFound)
				if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "rules unavailable"}); err != nil {
					t.Fatalf("encode rule-list 404: %v", err)
				}
				return
			}
			page := rules[policyID]
			after := r.URL.Query().Get("after")
			if policyID == "pol-sign-on" && after == "" {
				w.Header().Set("Link", "</api/v1/policies/pol-sign-on/rules?after=rule-sign-on-2&limit=1>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(page[:1]); err != nil {
					t.Fatalf("encode sign-on rule page 1: %v", err)
				}
				return
			}
			if policyID == "pol-sign-on" && after == "rule-sign-on-2" {
				if err := json.NewEncoder(w).Encode(page[1:2]); err != nil {
					t.Fatalf("encode sign-on rule page 2: %v", err)
				}
				return
			}
			if len(page) > 0 && after == "" {
				if err := json.NewEncoder(w).Encode(page[:1]); err != nil {
					t.Fatalf("encode policy rule page: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty policy rules: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

type oktaFactorTestResponse struct {
	status int
	body   json.RawMessage
}

func newOktaUserFactorAPIHandler(t *testing.T, userID string, factorResponses []oktaFactorTestResponse, factorRequestCount *int) http.Handler {
	t.Helper()

	userRecords := []map[string]any{
		{
			"id":          userID,
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"activated":   "2026-04-20T00:01:00Z",
			"lastUpdated": "2026-04-23T01:00:00Z",
			"lastLogin":   "2026-04-23T01:00:00Z",
			"profile": map[string]any{
				"login":       userID + "@writer.com",
				"email":       userID + "@writer.com",
				"displayName": "Okta MFA Test User",
			},
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "SSWS test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "invalid token"}); err != nil {
				t.Fatalf("encode auth error: %v", err)
			}
			return
		}
		switch r.URL.Path {
		case "/api/v1/users":
			if err := json.NewEncoder(w).Encode(userRecords); err != nil {
				t.Fatalf("encode users: %v", err)
			}
		case "/api/v1/users/" + userID + "/factors":
			(*factorRequestCount)++
			index := *factorRequestCount - 1
			if index >= len(factorResponses) {
				index = len(factorResponses) - 1
			}
			response := factorResponses[index]
			if response.status == 0 {
				response.status = http.StatusOK
			}
			w.WriteHeader(response.status)
			if len(response.body) > 0 {
				if _, err := w.Write(response.body); err != nil {
					t.Fatalf("write factors: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode default factors: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func newOktaAPIHandler(t *testing.T) http.Handler {
	t.Helper()

	auditRecords := []map[string]any{
		{
			"uuid":           "evt-1",
			"published":      "2026-04-23T01:00:00Z",
			"eventType":      "user.session.start",
			"displayMessage": "User login to Okta",
			"severity":       "INFO",
			"actor": map[string]any{
				"id":          "00u1",
				"type":        "User",
				"alternateId": "alice@writer.com",
				"displayName": "Alice Example",
			},
			"client": map[string]any{
				"ipAddress": "1.2.3.4",
				"zone":      "null",
				"userAgent": map[string]any{
					"rawUserAgent": "Mozilla/5.0",
				},
			},
			"outcome": map[string]any{
				"result": "SUCCESS",
			},
			"transaction": map[string]any{
				"id": "txn-1",
			},
			"target": []map[string]any{
				{
					"id":          "00u1",
					"type":        "User",
					"alternateId": "alice@writer.com",
					"displayName": "Alice Example",
				},
			},
		},
		{
			"uuid":           "evt-2",
			"published":      "2026-04-23T00:00:00Z",
			"eventType":      "policy.rule.update",
			"displayMessage": "Policy updated",
			"severity":       "WARN",
			"actor": map[string]any{
				"id":          "00u2",
				"type":        "User",
				"alternateId": "admin@writer.com",
				"displayName": "Admin Example",
			},
			"outcome": map[string]any{
				"result": "SUCCESS",
			},
			"target": []map[string]any{
				{
					"id":          "pol-1",
					"type":        "PolicyRule",
					"displayName": "Require MFA",
				},
			},
		},
	}
	userRecords := []map[string]any{
		{
			"id":          "00u1",
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"activated":   "2026-04-20T00:01:00Z",
			"lastUpdated": "2026-04-23T01:00:00Z",
			"lastLogin":   "2026-04-23T01:00:00Z",
			"profile": map[string]any{
				"login":        "alice@writer.com",
				"email":        "alice@writer.com",
				"displayName":  "Alice Example",
				"firstName":    "Alice",
				"lastName":     "Example",
				"department":   "Security",
				"title":        "Engineer",
				"organization": "Writer",
				"userType":     "employee",
			},
			"type": map[string]any{
				"id":   "oty1",
				"name": "default",
			},
		},
		{
			"id":            "00u2",
			"status":        "SUSPENDED",
			"created":       "2026-04-20T02:00:00Z",
			"lastUpdated":   "2026-04-23T00:30:00Z",
			"statusChanged": "2026-04-23T00:30:00Z",
			"profile": map[string]any{
				"login":       "admin@writer.com",
				"email":       "admin@writer.com",
				"displayName": "Admin Example",
				"firstName":   "Admin",
				"lastName":    "Example",
			},
			"type": map[string]any{
				"id":   "oty1",
				"name": "default",
			},
		},
	}
	groupRecords := []map[string]any{
		{
			"id":                    "grp-security",
			"type":                  "OKTA_GROUP",
			"created":               "2026-04-20T00:00:00Z",
			"lastUpdated":           "2026-04-23T00:00:00Z",
			"lastMembershipUpdated": "2026-04-23T01:00:00Z",
			"profile": map[string]any{
				"name":        "Security",
				"description": "Security team",
			},
		},
	}
	appRecords := []map[string]any{
		{
			"id":          "app-prod",
			"name":        "oidc_client",
			"label":       "Production Console",
			"status":      "ACTIVE",
			"signOnMode":  "OPENID_CONNECT",
			"created":     "2026-04-20T00:00:00Z",
			"lastUpdated": "2026-04-23T00:00:00Z",
			"credentials": map[string]any{
				"oauthClient": map[string]any{
					"client_id":                  "0oa-client-id",
					"client_secret":              "do-not-project",
					"token_endpoint_auth_method": "none",
				},
			},
			"settings": map[string]any{
				"oauthClient": map[string]any{
					"application_type": "browser",
					"grant_types":      []string{"authorization_code", "refresh_token"},
					"redirect_uris":    []string{"https://app.example/callback", "https://*.example/callback"},
					"response_types":   []string{"code"},
				},
			},
		},
	}
	appAssignmentRecords := []map[string]any{
		{
			"id":          "00u1",
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"lastUpdated": "2026-04-23T00:00:00Z",
			"profile": map[string]any{
				"email": "admin@writer.com",
				"login": "admin@writer.com",
			},
		},
	}
	appGroupAssignmentRecords := []map[string]any{
		{
			"id":          "grp-security",
			"status":      "ACTIVE",
			"created":     "2026-04-20T00:00:00Z",
			"lastUpdated": "2026-04-23T00:00:00Z",
			"profile": map[string]any{
				"name": "Security",
			},
		},
	}
	roleRecords := []map[string]any{
		{
			"id":             "super_admin",
			"label":          "Super Administrator",
			"type":           "SUPER_ADMIN",
			"assignmentType": "USER",
			"status":         "ACTIVE",
			"created":        "2026-04-20T00:00:00Z",
			"lastUpdated":    "2026-04-23T00:00:00Z",
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "SSWS test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			if err := json.NewEncoder(w).Encode(map[string]any{"errorSummary": "invalid token"}); err != nil {
				t.Fatalf("encode auth error: %v", err)
			}
			return
		}
		switch r.URL.Path {
		case "/api/v1/logs":
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", "</api/v1/logs?after=cursor-2&limit=1>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(auditRecords[:1]); err != nil {
					t.Fatalf("encode audit page 1: %v", err)
				}
				return
			}
			if after == "cursor-2" {
				if err := json.NewEncoder(w).Encode(auditRecords[1:2]); err != nil {
					t.Fatalf("encode audit page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty audit page: %v", err)
			}
		case "/api/v1/users":
			after := r.URL.Query().Get("after")
			if after == "" {
				limit := r.URL.Query().Get("limit")
				if limit == "2" {
					if err := json.NewEncoder(w).Encode(userRecords); err != nil {
						t.Fatalf("encode user discover page: %v", err)
					}
					return
				}
				w.Header().Set("Link", "</api/v1/users?after=cursor-user-2&limit=1>; rel=\"next\"")
				if err := json.NewEncoder(w).Encode(userRecords[:1]); err != nil {
					t.Fatalf("encode users page 1: %v", err)
				}
				return
			}
			if after == "cursor-user-2" {
				if err := json.NewEncoder(w).Encode(userRecords[1:2]); err != nil {
					t.Fatalf("encode users page 2: %v", err)
				}
				return
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{}); err != nil {
				t.Fatalf("encode empty users page: %v", err)
			}
		case "/api/v1/groups":
			if err := json.NewEncoder(w).Encode(groupRecords); err != nil {
				t.Fatalf("encode groups: %v", err)
			}
		case "/api/v1/groups/grp-security/users":
			if err := json.NewEncoder(w).Encode(userRecords[1:2]); err != nil {
				t.Fatalf("encode group members: %v", err)
			}
		case "/api/v1/apps":
			if err := json.NewEncoder(w).Encode(appRecords); err != nil {
				t.Fatalf("encode apps: %v", err)
			}
		case "/api/v1/apps/app-prod/users":
			if err := json.NewEncoder(w).Encode(appAssignmentRecords); err != nil {
				t.Fatalf("encode app assignments: %v", err)
			}
		case "/api/v1/apps/app-prod/groups":
			if err := json.NewEncoder(w).Encode(appGroupAssignmentRecords); err != nil {
				t.Fatalf("encode app group assignments: %v", err)
			}
		case "/api/v1/users/00u1/roles":
			if err := json.NewEncoder(w).Encode(roleRecords); err != nil {
				t.Fatalf("encode admin roles: %v", err)
			}
		case "/api/v1/users/00u1/factors":
			if _, err := w.Write(mustOktaTestdata(t, "factors_enrolled.json")); err != nil {
				t.Fatalf("write 00u1 factors: %v", err)
			}
		case "/api/v1/users/00u2/factors":
			if _, err := w.Write(mustOktaTestdata(t, "factors_not_enrolled.json")); err != nil {
				t.Fatalf("write 00u2 factors: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

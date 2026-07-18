package okta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		configKey   string
		idSegment   int
		captureTime bool
	}{
		{family: familyAdminRole, fixtureCase: "list_admin_roles", configKey: "user_id", idSegment: 3},
		{family: familyAppAssign, fixtureCase: "list_app_assignments", configKey: "app_id", idSegment: 3},
		{family: familyApplication, fixtureCase: "list_applications"},
		{family: "api_token", fixtureCase: "list_api_tokens"},
		{family: "authorization_server", fixtureCase: "list_authorization_servers"},
		{family: familyAuthenticator, fixtureCase: "list_authenticators"},
		{family: "brand", fixtureCase: "list_brands", captureTime: true},
		{family: "device_assurance", fixtureCase: "list_device_assurance", captureTime: true},
		{family: "event_hook", fixtureCase: "list_event_hooks"},
		{family: familyGroup, fixtureCase: "list_groups"},
		{family: familyGroupMember, fixtureCase: "list_group_members", configKey: "group_id", idSegment: 3},
		{family: familyIDP, fixtureCase: "list_identity_providers"},
		{family: "inline_hook", fixtureCase: "list_inline_hooks"},
		{family: "log_stream", fixtureCase: "list_log_streams"},
		{family: familyNetworkZone, fixtureCase: "list_network_zones"},
		{family: familyThreatInsight, fixtureCase: "get_threat_insight"},
		{family: familyTrustedOrigin, fixtureCase: "list_trusted_origins"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedOktaBundle(t, test.family, test.fixtureCase)
			requestPath := capturedOktaRequestPath(t, bundle)
			server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != requestPath {
					return false
				}
				writeCapturedOktaResponse(w, bundle)
				return true
			})
			defer server.Close()

			source := capturedOktaSource(t)
			config := map[string]string{}
			if test.configKey != "" {
				config[test.configKey] = capturedOktaPathSegment(t, requestPath, test.idSegment)
			}
			cfg := capturedOktaConfig(server.URL, test.family, config)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			wantKind := "okta." + test.family
			if len(pull.Events) == 0 || pull.Events[0].Kind != wantKind {
				t.Fatalf("Read() events = %#v, want kind %q", pull.Events, wantKind)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, test.captureTime); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedOktaFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run(familyUser, testCapturedOktaUser)
	t.Run(familyPolicyRule, testCapturedOktaPolicyRule)
}

func testCapturedOktaUser(t *testing.T) {
	userBundle := capturedOktaBundle(t, familyUser, "list_users")
	factorBundle := capturedOktaBundle(t, familyUser, "list_user_factors")
	userPath := capturedOktaRequestPath(t, userBundle)
	factorPath := capturedOktaRequestPath(t, factorBundle)
	server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case userPath:
			writeCapturedOktaResponse(w, userBundle)
			return true
		case factorPath:
			writeCapturedOktaResponse(w, factorBundle)
			return true
		default:
			return false
		}
	})
	defer server.Close()

	source := capturedOktaSource(t)
	cfg := capturedOktaConfig(server.URL, familyUser, nil)
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "okta.user" {
		t.Fatalf("Read() events = %#v, want one okta.user", pull.Events)
	}
	if got := pull.Events[0].Attributes["mfa_factor_count"]; got != "2" {
		t.Fatalf("mfa_factor_count = %q, want 2", got)
	}
	if got := pull.Events[0].Attributes["mfa_phishing_resistant"]; got != "true" {
		t.Fatalf("mfa_phishing_resistant = %q, want true", got)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(userBundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyUser, pull.Events, urns, updateCapturedOktaFixtures()); err != nil {
		t.Fatal(err)
	}
}

func testCapturedOktaPolicyRule(t *testing.T) {
	policyBundle := capturedOktaBundle(t, familyPolicyRule, "list_policies")
	ruleBundle := capturedOktaBundle(t, familyPolicyRule, "list_policy_rules")
	policyPath := capturedOktaRequestPath(t, policyBundle)
	rulePath := capturedOktaRequestPath(t, ruleBundle)
	policyID := capturedOktaPathSegment(t, rulePath, 3)
	server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case policyPath:
			writeCapturedOktaResponse(w, policyBundle)
			return true
		case rulePath:
			writeCapturedOktaResponse(w, ruleBundle)
			return true
		default:
			return false
		}
	})
	defer server.Close()

	source := capturedOktaSource(t)
	cfg := capturedOktaConfig(server.URL, familyPolicyRule, map[string]string{"per_page": "1"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	cursor := &cerebrov1.SourceCursor{Opaque: fmt.Sprintf(`{"policy_type_index":0,"policy":{"id":%q,"type":"OKTA_SIGN_ON","status":"ACTIVE"}}`, policyID)}
	pull, err := source.Read(context.Background(), cfg, cursor)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "okta.policy_rule" {
		t.Fatalf("Read() events = %#v, want one okta.policy_rule", pull.Events)
	}
	urn, err := sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:writer.okta.com:policy_rule:%s:%s", policyID, pull.Events[0].Attributes["policy_rule_id"]))
	if err != nil {
		t.Fatalf("ParseURN() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(ruleBundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyPolicyRule, pull.Events, []sourcecdk.URN{urn}, updateCapturedOktaFixtures()); err != nil {
		t.Fatal(err)
	}
}

func capturedOktaBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", "okta", family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedOktaRequestPath(t *testing.T, bundle sourcefixture.Bundle) string {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed.Path
}

func capturedOktaPathSegment(t *testing.T, requestPath string, index int) string {
	t.Helper()
	segments := strings.Split(strings.Trim(requestPath, "/"), "/")
	if index < 0 || index >= len(segments) {
		t.Fatalf("request path %q has no segment %d", requestPath, index)
	}
	return segments[index]
}

func capturedOktaSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	return source
}

func capturedOktaConfig(baseURL, family string, extra map[string]string) sourcecdk.Config {
	values := map[string]string{
		"base_url": baseURL,
		"domain":   "writer.okta.com",
		"family":   family,
		"per_page": "2",
		"token":    "test-token",
	}
	for name, value := range extra {
		values[name] = value
	}
	return sourcecdk.NewConfig(values)
}

func capturedOktaServer(t *testing.T, handler func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "SSWS test-token" {
			t.Fatalf("Authorization = %q, want replay token", got)
		}
		if handler(w, r) {
			return
		}
		t.Fatalf("unexpected Okta replay request %s %s", r.Method, r.URL.RequestURI())
	}))
}

func writeCapturedOktaResponse(w http.ResponseWriter, bundle sourcefixture.Bundle) {
	w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
	for name, value := range bundle.Manifest.Response.Headers {
		w.Header().Set(name, value)
	}
	w.WriteHeader(bundle.Manifest.Response.Status)
	_, _ = w.Write(bundle.Payload)
}

func updateCapturedOktaFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}

package okta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		requestPath string
		config      map[string]string
		captureTime bool
	}{
		{family: familyAdminRole, fixtureCase: "list_admin_roles", requestPath: "/api/v1/users/00usfex7wP9lvobJ84x6/roles", config: map[string]string{"user_id": "00usfex7wP9lvobJ84x6"}},
		{family: familyAppAssign, fixtureCase: "list_app_assignments", requestPath: "/api/v1/apps/0oasf86d7hw9MMcnd4x6/users", config: map[string]string{"app_id": "0oasf86d7hw9MMcnd4x6"}},
		{family: familyApplication, fixtureCase: "list_applications", requestPath: "/api/v1/apps"},
		{family: "api_token", fixtureCase: "list_api_tokens", requestPath: "/api/v1/api-tokens"},
		{family: "authorization_server", fixtureCase: "list_authorization_servers", requestPath: "/api/v1/authorizationServers"},
		{family: familyAuthenticator, fixtureCase: "list_authenticators", requestPath: "/api/v1/authenticators"},
		{family: "brand", fixtureCase: "list_brands", requestPath: "/api/v1/brands", captureTime: true},
		{family: "device_assurance", fixtureCase: "list_device_assurance", requestPath: "/api/v1/device-assurances", captureTime: true},
		{family: "event_hook", fixtureCase: "list_event_hooks", requestPath: "/api/v1/eventHooks"},
		{family: familyGroup, fixtureCase: "list_groups", requestPath: "/api/v1/groups"},
		{family: familyGroupMember, fixtureCase: "list_group_members", requestPath: "/api/v1/groups/00gsf7bj3rH2d9PvL4x6/users", config: map[string]string{"group_id": "00gsf7bj3rH2d9PvL4x6"}},
		{family: familyIDP, fixtureCase: "list_identity_providers", requestPath: "/api/v1/idps"},
		{family: "inline_hook", fixtureCase: "list_inline_hooks", requestPath: "/api/v1/inlineHooks"},
		{family: "log_stream", fixtureCase: "list_log_streams", requestPath: "/api/v1/logStreams"},
		{family: familyNetworkZone, fixtureCase: "list_network_zones", requestPath: "/api/v1/zones"},
		{family: familyThreatInsight, fixtureCase: "get_threat_insight", requestPath: "/api/v1/threats/configuration"},
		{family: familyTrustedOrigin, fixtureCase: "list_trusted_origins", requestPath: "/api/v1/trustedOrigins"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedOktaBundle(t, test.family, test.fixtureCase)
			server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != test.requestPath {
					return false
				}
				writeCapturedOktaResponse(w, bundle)
				return true
			})
			defer server.Close()

			source := capturedOktaSource(t)
			cfg := capturedOktaConfig(server.URL, test.family, test.config)
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
	server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/users":
			writeCapturedOktaResponse(w, userBundle)
			return true
		case "/api/v1/users/00uFAKEFASTPASS000001/factors":
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
	const policyID = "00psfar1lATHw2WXj4x6"
	server := capturedOktaServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/policies":
			writeCapturedOktaResponse(w, policyBundle)
			return true
		case "/api/v1/policies/" + policyID + "/rules":
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

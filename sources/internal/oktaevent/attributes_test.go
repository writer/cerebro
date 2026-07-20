package oktaevent

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAppAssignmentAttributes(t *testing.T) {
	got := AppAssignmentAttributes("example.okta.com", "app_assignment", "0oaapp1", "00usub1", "USER", "ACTIVE")
	want := map[string]string{
		"domain":         "example.okta.com",
		"family":         "app_assignment",
		"app_id":         "0oaapp1",
		"subject_id":     "00usub1",
		"subject_type":   "USER",
		"assignee_id":    "00usub1",
		"assignee_type":  "USER",
		"principal_type": "USER",
		"status":         "ACTIVE",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AppAssignmentAttributes() = %#v, want %#v", got, want)
	}
}

func TestAddSystemLogAttributes(t *testing.T) {
	attributes := map[string]string{}
	AddSystemLogAttributes(attributes, SystemLogContext{
		AuthenticationContext: map[string]any{
			"authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
			"credentialProvider":     "OKTA_CREDENTIAL_PROVIDER",
			"credentialType":         "PASSWORD",
			"authenticationStep":     float64(1),
			"interface":              "Okta Verify",
			"externalSessionId":      "ext-session",
			"rootSessionId":          "root-session",
		},
		Transaction: map[string]any{"id": "txn-1"},
		SecurityContext: map[string]any{
			"asNumber": float64(64512),
			"asOrg":    "example-org",
			"isp":      "example-isp",
			"domain":   "example.net",
			"isProxy":  false,
		},
		DebugContext: map[string]any{
			"debugData": map[string]any{
				"requestId":         "req-1",
				"requestUri":        "/api/v1/authn",
				"requestApiTokenId": "token-1",
				"riskLevel":         "LOW",
				"threatSuspected":   "false",
				"behaviors":         []any{"New Geo-Location", "New Device"},
			},
		},
		Request: map[string]any{
			"ipChain": []any{
				map[string]any{
					"ip":                  "203.0.113.1",
					"geographicalContext": map[string]any{"city": "SF", "state": "CA", "country": "US"},
				},
				map[string]any{"ipAddress": "203.0.113.2"},
			},
		},
	})

	want := map[string]string{
		"authentication_provider":  "OKTA_AUTHENTICATION_PROVIDER",
		"credential_provider":      "OKTA_CREDENTIAL_PROVIDER",
		"credential_type":          "PASSWORD",
		"authentication_step":      "1",
		"authentication_interface": "Okta Verify",
		"session_id":               "ext-session",
		"external_session_id":      "ext-session",
		"root_session_id":          "root-session",
		"asn":                      "64512",
		"as_org":                   "example-org",
		"isp":                      "example-isp",
		"security_domain":          "example.net",
		"is_proxy":                 "false",
		"debug_request_id":         "req-1",
		"debug_request_uri":        "/api/v1/authn",
		"request_api_token_id":     "token-1",
		"risk_level":               "LOW",
		"risk":                     "LOW",
		"threat_suspected":         "false",
		"behaviors":                "New Geo-Location,New Device",
		"request_ip_count":         "2",
		"request_ip_chain":         "203.0.113.1,203.0.113.2",
		"request_first_ip":         "203.0.113.1",
		"request_first_city":       "SF",
		"request_first_state":      "CA",
		"request_first_country":    "US",
	}
	if !reflect.DeepEqual(attributes, want) {
		t.Errorf("AddSystemLogAttributes() = %#v, want %#v", attributes, want)
	}
}

func TestAddSystemLogAttributesSessionFallsBackToTransaction(t *testing.T) {
	attributes := map[string]string{}
	AddSystemLogAttributes(attributes, SystemLogContext{
		AuthenticationContext: map[string]any{},
		Transaction:           map[string]any{"id": "txn-only"},
	})
	if attributes["session_id"] != "txn-only" {
		t.Errorf("session_id = %q, want txn-only", attributes["session_id"])
	}
	if _, ok := attributes["external_session_id"]; ok {
		t.Errorf("external_session_id should be absent, got %q", attributes["external_session_id"])
	}
}

func TestAddSystemLogAttributesClientIPChainFallback(t *testing.T) {
	attributes := map[string]string{}
	AddSystemLogAttributes(attributes, SystemLogContext{
		Client: map[string]any{
			"ipChain": []any{map[string]any{"ip": "198.51.100.5"}},
		},
	})
	if attributes["request_ip_count"] != "1" {
		t.Errorf("request_ip_count = %q, want 1", attributes["request_ip_count"])
	}
	if attributes["request_first_ip"] != "198.51.100.5" {
		t.Errorf("request_first_ip = %q, want 198.51.100.5", attributes["request_first_ip"])
	}
}

func TestAddSystemLogAttributesEmptyContext(t *testing.T) {
	attributes := map[string]string{}
	AddSystemLogAttributes(attributes, SystemLogContext{})
	if len(attributes) != 0 {
		t.Errorf("expected no attributes for empty context, got %#v", attributes)
	}
}

func TestAddTargetAttributes(t *testing.T) {
	attributes := map[string]string{}
	AddTargetAttributes(attributes, []Identity{
		{ID: "0oaapp1", Type: "AppInstance", AlternateID: "app-alt", DisplayName: "My App"},
		{ID: "00uuser1", Type: "User", AlternateID: "user@example.com", DisplayName: "Jane"},
	})
	want := map[string]string{
		"target_count":            "2",
		"target_ids":              "0oaapp1,00uuser1",
		"target_types":            "AppInstance,User",
		"target_alternate_ids":    "app-alt,user@example.com",
		"target_display_names":    "My App,Jane",
		"target_app_id":           "0oaapp1",
		"target_app_label":        "My App",
		"target_app_alternate_id": "app-alt",
		"target_user_id":          "00uuser1",
		"target_user_email":       "user@example.com",
	}
	if !reflect.DeepEqual(attributes, want) {
		t.Errorf("AddTargetAttributes() = %#v, want %#v", attributes, want)
	}
}

func TestAddTargetAttributesEmpty(t *testing.T) {
	attributes := map[string]string{}
	AddTargetAttributes(attributes, nil)
	if len(attributes) != 0 {
		t.Errorf("expected no attributes for empty targets, got %#v", attributes)
	}
}

func TestOAuthEventCategory(t *testing.T) {
	cases := []struct {
		eventType string
		want      string
	}{
		{"app.oauth2.authorize.code", "runtime_grant"},
		{"app.oauth2.as.authorize.code", "runtime_grant"},
		{"app.oauth2.token.grant.access_token", "runtime_grant"},
		{"app.oauth2.as.token.grant.refresh_token", "runtime_grant"},
		{"system.api_token.create", "credential_change"},
		{"application.client_secret.rotate", "credential_change"},
		{"app.oauth2.client.create", "credential_change"},
		{"application.user_membership.add", ""},
		{"user.session.start", ""},
		{"  APP.OAUTH2.AUTHORIZE.CODE  ", "runtime_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			if got := OAuthEventCategory(tc.eventType); got != tc.want {
				t.Errorf("OAuthEventCategory(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

func TestOAuthGrantType(t *testing.T) {
	cases := []struct {
		eventType string
		want      string
	}{
		{"app.oauth2.authorize.code", "authorization_code"},
		{"app.oauth2.token.grant.access_token", "access_token"},
		{"app.oauth2.token.grant.refresh_token", "refresh_token"},
		{"app.oauth2.token.grant.id_token", "id_token"},
		{"user.session.start", ""},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			if got := OAuthGrantType(tc.eventType); got != tc.want {
				t.Errorf("OAuthGrantType(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

func TestOAuthClientIdentity(t *testing.T) {
	client := Identity{ID: "0oaclient", Type: "PublicClientApp"}
	t.Run("actor is client", func(t *testing.T) {
		got := OAuthClientIdentity(client, nil)
		if got != client {
			t.Errorf("OAuthClientIdentity() = %#v, want %#v", got, client)
		}
	})
	t.Run("client found in targets", func(t *testing.T) {
		actor := Identity{ID: "00uuser", Type: "User"}
		got := OAuthClientIdentity(actor, []Identity{{ID: "00uother", Type: "User"}, client})
		if got != client {
			t.Errorf("OAuthClientIdentity() = %#v, want %#v", got, client)
		}
	})
	t.Run("no client returns empty", func(t *testing.T) {
		actor := Identity{ID: "00uuser", Type: "User"}
		got := OAuthClientIdentity(actor, []Identity{{ID: "00uother", Type: "User"}})
		if got != (Identity{}) {
			t.Errorf("OAuthClientIdentity() = %#v, want empty", got)
		}
	})
}

func TestAnyString(t *testing.T) {
	values := map[string]any{
		"str":     "  hello ",
		"boolT":   true,
		"boolF":   false,
		"int":     float64(42),
		"float":   1.5,
		"num":     json.Number("123"),
		"nilval":  nil,
		"unknown": []any{1, 2},
	}
	cases := []struct {
		key  string
		want string
	}{
		{"str", "hello"},
		{"boolT", "true"},
		{"boolF", "false"},
		{"int", "42"},
		{"float", "1.5"},
		{"num", "123"},
		{"nilval", ""},
		{"missing", ""},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := anyString(values, tc.key); got != tc.want {
				t.Errorf("anyString(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestStringMapAndSlice(t *testing.T) {
	values := map[string]any{
		"str":      "  value ",
		"nonstr":   42,
		"slice":    []any{"a", "  b ", "", 3},
		"badslice": "notaslice",
	}
	if got := stringMap(values, "str"); got != "value" {
		t.Errorf("stringMap(str) = %q, want value", got)
	}
	if got := stringMap(values, "nonstr"); got != "" {
		t.Errorf("stringMap(nonstr) = %q, want empty", got)
	}
	if got := stringMap(values, "missing"); got != "" {
		t.Errorf("stringMap(missing) = %q, want empty", got)
	}
	if got := stringSliceMap(values, "slice"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("stringSliceMap(slice) = %#v, want [a b]", got)
	}
	if got := stringSliceMap(values, "badslice"); got != nil {
		t.Errorf("stringSliceMap(badslice) = %#v, want nil", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "found", "later"); got != "found" {
		t.Errorf("firstNonEmpty() = %q, want found", got)
	}
	if got := firstNonEmpty("", "   "); got != "" {
		t.Errorf("firstNonEmpty() = %q, want empty", got)
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("app.oauth2.client_secret.rotate", "client_secret", "api_token") {
		t.Error("containsAny() = false, want true")
	}
	if containsAny("user.session.start", "oauth", "token") {
		t.Error("containsAny() = true, want false")
	}
}

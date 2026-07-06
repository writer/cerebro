package apigee

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		requests[r.URL.RequestURI()]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/organizations/acme":
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "organizations/acme", "projectId": "gcp-project"})
		case "/v1/organizations":
			_ = json.NewEncoder(w).Encode(map[string]any{"organizations": []map[string]string{{"organization": "acme", "projectId": "gcp-project", "location": "us-central1"}}})
		case "/v1/organizations/acme/apis":
			if r.URL.Query().Get("includeRevisions") != "true" || r.URL.Query().Get("includeMetaData") != "true" {
				t.Fatalf("api proxy query = %q", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proxies": []map[string]any{{"name": "orders", "revision": []string{"1", "2"}, "apiProxyType": "PROGRAMMABLE"}}})
		case "/v1/organizations/acme/deployments":
			_ = json.NewEncoder(w).Encode(map[string]any{"deployments": []map[string]string{{"environment": "prod", "apiProxy": "orders", "revision": "2", "state": "READY", "basePath": "/orders"}}})
		case "/v1/organizations/acme/developers":
			if r.URL.Query().Get("count") != "100" {
				t.Fatalf("developers query = %q", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"developer": []map[string]string{{"email": "dev@fixture.invalid", "developerId": "dev-1", "userName": "dev-user", "status": "active"}}})
		case "/v1/organizations/acme/apps":
			if r.URL.Query().Get("expand") != "true" || r.URL.Query().Get("pageSize") != "100" {
				t.Fatalf("apps query = %q", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"app": []map[string]string{{"appId": "app-1", "name": "orders-app", "status": "approved"}}})
		default:
			t.Fatalf("unexpected path = %q", r.URL.RequestURI())
		}
	}))
	defer server.Close()

	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "organization": "acme", "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	for _, tc := range []struct {
		family string
		kind   string
	}{
		{family: familyOrganizations, kind: "apigee.organizations"},
		{family: familyAPIProxies, kind: "apigee.api_proxies"},
		{family: familyDeployments, kind: "apigee.deployments"},
		{family: familyDevelopers, kind: "apigee.developers"},
		{family: familyApps, kind: "apigee.apps"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			familyCfg := sourcecdk.NewConfig(withFamily(cfgValues, tc.family))
			pull, err := source.Read(context.Background(), familyCfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tc.kind {
				t.Fatalf("kind = %q", event.Kind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
		})
	}
	for _, path := range []string{
		"/v1/organizations/acme",
		"/v1/organizations",
		"/v1/organizations/acme/apis?includeMetaData=true&includeRevisions=true",
		"/v1/organizations/acme/deployments",
		"/v1/organizations/acme/developers?count=100",
		"/v1/organizations/acme/apps?expand=true&pageSize=100",
	} {
		if requests[path] == 0 {
			t.Fatalf("request %s was not observed; got %#v", path, requests)
		}
	}
}

func withFamily(values map[string]string, family string) map[string]string {
	clone := map[string]string{}
	for key, value := range values {
		clone[key] = value
	}
	clone["family"] = family
	return clone
}

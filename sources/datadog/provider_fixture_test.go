package datadog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedFamilies(t *testing.T) {
	tests := []struct {
		family      string
		fixtureCase string
		requestPath string
		wantKind    string
	}{
		{family: familyUsers, fixtureCase: "list_users", requestPath: "/api/v2/users", wantKind: "datadog.users"},
		{family: familyRoles, fixtureCase: "list_roles", requestPath: "/api/v2/roles", wantKind: "datadog.roles"},
		{family: familyTeams, fixtureCase: "list_teams", requestPath: "/api/v2/team", wantKind: "datadog.teams"},
		{family: familyMonitors, fixtureCase: "list_monitors", requestPath: "/api/v1/monitor", wantKind: "datadog.monitors"},
		{family: familySLOs, fixtureCase: "list_slos", requestPath: "/api/v1/slo", wantKind: "datadog.slos"},
		{family: familyDashboards, fixtureCase: "list_dashboards", requestPath: "/api/v1/dashboard", wantKind: "datadog.dashboards"},
		{family: familyIncidents, fixtureCase: "list_incidents", requestPath: "/api/v2/incidents", wantKind: "datadog.incidents"},
		{family: familyAudit, fixtureCase: "list_audit_events", requestPath: "/api/v2/audit/events", wantKind: "datadog.audit_events"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, test.fixtureCase)
			if err != nil {
				t.Fatalf("FindBundle(%s) error = %v", test.family, err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.requestPath {
					t.Fatalf("request path = %q, want %q", r.URL.Path, test.requestPath)
				}
				if r.Header.Get("DD-API-KEY") != "api-key" || r.Header.Get("DD-APPLICATION-KEY") != "app-key" {
					t.Fatal("Datadog replay request is missing configured authentication headers")
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			cfg := datadogTestConfig(server.URL, test.family)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) == 0 || pull.Events[0].Kind != test.wantKind {
				t.Fatalf("Read() events = %#v, want kind %q", pull.Events, test.wantKind)
			}
			assertDatadogEventContracts(t, source, pull.Events...)
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

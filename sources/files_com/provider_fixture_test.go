package files_com

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedFilesFamilies(t *testing.T) {
	tests := []struct {
		family         string
		fixtureCase    string
		minimumRecords int
	}{
		{family: familyLogin, fixtureCase: "list_logins", minimumRecords: 1},
		{family: familyUser, fixtureCase: "list_users", minimumRecords: 1},
	}

	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle := capturedFilesBundle(t, test.family, test.fixtureCase)
			server := capturedFilesServer(t, map[string]sourcefixture.Bundle{"": bundle})
			defer server.Close()

			source := capturedFilesSource(t)
			cfg := capturedFilesConfig(server.URL, test.family, nil)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimumRecords {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimumRecords)
			}
			for _, event := range pull.Events {
				if event.Kind != "files_com."+test.family {
					t.Fatalf("event kind = %q, want files_com.%s", event.Kind, test.family)
				}
				if strings.TrimSpace(event.Attributes["resource_id"]) == "" {
					t.Fatalf("resource_id is empty for event %q", event.Id)
				}
			}
			if test.family == familyLogin {
				if got := pull.Events[0].Attributes["event_type"]; got != "login" {
					t.Fatalf("event_type = %q, want login", got)
				}
				if strings.TrimSpace(pull.Events[0].Attributes["actor_id"]) == "" {
					t.Fatalf("actor_id is empty: %#v", pull.Events[0].Attributes)
				}
			} else if !strings.HasSuffix(pull.Events[0].Attributes["email"], "@example.test") {
				t.Fatalf("email = %q, want sanitized example address", pull.Events[0].Attributes["email"])
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != len(pull.Events) {
				t.Fatalf("Discover() URNs = %d, want %d read records", len(urns), len(pull.Events))
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, updateCapturedFilesFixtures()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceReplaysCapturedFilesLoginRange(t *testing.T) {
	bundle := capturedFilesBundle(t, familyLogin, "list_logins_range")
	captured := capturedFilesRequestURL(t, bundle)
	server := capturedFilesServer(t, map[string]sourcefixture.Bundle{"range": bundle})
	defer server.Close()

	source := capturedFilesSource(t)
	cfg := capturedFilesConfig(server.URL, familyLogin, map[string]string{
		"end_at":   captured.Query().Get("end_at"),
		"start_at": captured.Query().Get("start_at"),
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Attributes["observed_at"] != "2023-01-28T19:41:43-05:00" {
		t.Fatalf("Read() events = %#v, want captured range record", pull.Events)
	}
}

func capturedFilesBundle(t *testing.T, family, fixtureCase string) sourcefixture.Bundle {
	t.Helper()
	bundle, err := sourcefixture.FindBundle("../..", sourceID, family, fixtureCase)
	if err != nil {
		t.Fatalf("FindBundle(%s/%s) error = %v", family, fixtureCase, err)
	}
	return bundle
}

func capturedFilesRequestURL(t *testing.T, bundle sourcefixture.Bundle) *url.URL {
	t.Helper()
	parsed, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatalf("parse captured request URL: %v", err)
	}
	return parsed
}

func capturedFilesSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func capturedFilesConfig(baseURL, family string, extra map[string]string) sourcecdk.Config {
	values := map[string]string{
		"api_key":   "replay-token",
		"base_url":  baseURL + "/api/rest/v1",
		"family":    family,
		"tenant_id": "tenant",
	}
	for key, value := range extra {
		values[key] = value
	}
	return sourcecdk.NewConfig(values)
}

func capturedFilesServer(t *testing.T, cases map[string]sourcefixture.Bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-FilesAPI-Key"); got != "replay-token" {
			t.Fatalf("X-FilesAPI-Key = %q, want replay token", got)
		}
		caseName := ""
		if strings.TrimSpace(r.URL.Query().Get("start_at")) != "" {
			caseName = "range"
		}
		bundle, ok := cases[caseName]
		if !ok {
			t.Fatalf("unexpected Files.com replay query %s", r.URL.RawQuery)
		}
		captured := capturedFilesRequestURL(t, bundle)
		if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Files.com replay request %s %s; want %s", r.Method, r.URL.RequestURI(), captured.RequestURI())
		}
		for key, values := range captured.Query() {
			if got := r.URL.Query()[key]; strings.Join(got, "\x00") != strings.Join(values, "\x00") {
				t.Fatalf("query %q = %#v, want captured %#v", key, got, values)
			}
		}
		writeCapturedFilesResponse(w, bundle)
	}))
}

func writeCapturedFilesResponse(w http.ResponseWriter, bundle sourcefixture.Bundle) {
	w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
	for key, value := range bundle.Manifest.Response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(bundle.Manifest.Response.Status)
	_, _ = w.Write(bundle.Payload)
}

func updateCapturedFilesFixtures() bool {
	return strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
}

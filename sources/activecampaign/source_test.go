package activecampaign

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Token") != "test-token" {
			t.Fatalf("Api-Token = %q", r.Header.Get("Api-Token"))
		}
		if r.URL.RequestURI() == "/api/3/users/me" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/3/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"users": []map[string]string{{"id": "1", "username": "jdoe", "firstName": "John", "lastName": "Doe", "email": "jdoe@example.test"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "activecampaign.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["email"]; got != "jdoe@example.test" {
		t.Fatalf("email attribute = %q", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadFamiliesUseDocumentedV3Paths(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	responses := map[string]map[string]any{
		"/api/3/accounts": {
			"accounts": []map[string]string{{"id": "1", "name": "First Example Account", "updatedTimestamp": "2019-04-29T07:51:31-05:00"}},
		},
		"/api/3/automations": {
			"automations": []map[string]string{{"id": "2", "name": "Test SMS Send", "mdate": "2018-09-18T10:54:30-05:00"}},
		},
		"/api/3/campaigns": {
			"campaigns": []map[string]string{{"id": "11", "name": "FirstCampaign", "mdate": "2023-03-23T15:03:10-05:00"}},
		},
		"/api/3/contacts": {
			"contacts": []map[string]string{{"id": "68", "email": "janedoe@example.test", "firstName": "Jane", "udate": "2017-01-25T23:58:14-06:00"}},
		},
		"/api/3/users": {
			"users": []map[string]string{{"id": "1", "username": "jdoe", "email": "jdoe@example.test"}},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Api-Token") != "test-token" {
			t.Fatalf("Api-Token = %q", r.Header.Get("Api-Token"))
		}
		payload, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()

	for family, wantKind := range map[string]string{
		"accounts":    "activecampaign.accounts",
		"automations": "activecampaign.automations",
		"campaigns":   "activecampaign.campaigns",
		"contacts":    "activecampaign.contacts",
		"users":       "activecampaign.users",
	} {
		t.Run(family, func(t *testing.T) {
			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": family, "token": "test-token"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != wantKind {
				t.Fatalf("kind = %q, want %q", got, wantKind)
			}
		})
	}
}

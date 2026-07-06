package aircall

import (
	"context"
	"encoding/base64"
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
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("api-id:api-token"))
		if r.Header.Get("Authorization") != wantAuth {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/ping" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("per_page"); got == "" {
			t.Fatalf("per_page is empty")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]any{"count": 1, "total": 1, "current_page": 1, "per_page": 50, "next_page_link": nil, "previous_page_link": nil},
			"users": []map[string]any{{
				"id":                  456,
				"direct_link":         "https://api.aircall.io/v1/users/456",
				"name":                "John Doe",
				"email":               "john.doe@aircall.test",
				"available":           true,
				"availability_status": "available",
				"created_at":          "2019-12-29T10:03:18.000Z",
				"time_zone":           "America/New_York",
				"language":            "en-US",
				"extension":           "001",
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "username": "api-id", "password": "api-token", "per_page": "50"}
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
	if event.Kind != "aircall.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["email"]; got != "john.doe@aircall.test" {
		t.Fatalf("email attribute = %q", got)
	}
}

func TestReadDocumentedFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	responses := map[string]map[string]any{
		"/users": {
			"users": []map[string]any{{"id": 456, "name": "John Doe", "email": "john.doe@aircall.test", "availability_status": "available", "created_at": "2019-12-29T10:03:18.000Z"}},
		},
		"/teams": {
			"teams": []map[string]any{{"id": 678, "name": "Global Sales", "created_at": "2020-03-10T08:31:43.000Z"}},
		},
		"/calls": {
			"calls": []map[string]any{{"id": 812, "sid": "CA1234567890", "direction": "outbound", "status": "done", "started_at": 1584998199, "user": map[string]any{"id": 456, "name": "John Doe", "email": "john.doe@aircall.test"}}},
		},
		"/contacts": {
			"contacts": []map[string]any{{"id": 710, "first_name": "Vicente", "last_name": "Abad", "company_name": "TeleWorm", "created_at": 1400691054, "updated_at": 1444336506}},
		},
		"/numbers": {
			"numbers": []map[string]any{{"id": 1234, "name": "French Office", "digits": "+33176111111", "country": "FR", "created_at": "2020-01-02T11:41:01.000Z"}},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("api-id:api-token"))
		if r.Header.Get("Authorization") != wantAuth {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		body["meta"] = map[string]any{"count": 1, "total": 1, "current_page": 1, "per_page": 50, "next_page_link": nil, "previous_page_link": nil}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	for _, family := range []string{familyUsers, familyTeams, familyCalls, familyContacts, familyNumbers} {
		cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": family, "username": "api-id", "password": "api-token", "per_page": "50"})
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read(%s) error = %v", family, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%s) events = %d, want 1", family, len(pull.Events))
		}
		if wantKind := "aircall." + family; pull.Events[0].Kind != wantKind {
			t.Fatalf("Read(%s) kind = %q, want %q", family, pull.Events[0].Kind, wantKind)
		}
	}
}

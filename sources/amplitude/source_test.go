package amplitude

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
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/scim/1/Users" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("itemsPerPage"); got == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			"startIndex":   1,
			"itemsPerPage": 100,
			"totalResults": 1,
			"Resources": []map[string]any{{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "datamonster@amplitude.com",
				"userName": "datamonster@amplitude.com",
				"name": map[string]any{
					"givenName":  "Data",
					"familyName": "Monster",
				},
				"active": true,
				"emails": []map[string]any{{"value": "datamonster@amplitude.com", "primary": true}},
				"meta":   map[string]any{"resourceType": "User", "created": "2022-02-03T20:40:22.000Z"},
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "per_page": "100"}
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
	if event.Kind != "amplitude.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["email"]; got != "datamonster@amplitude.com" {
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
		"/scim/1/Users": {
			"Resources": []map[string]any{{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
				"id":       "datamonster@amplitude.com",
				"userName": "datamonster@amplitude.com",
				"name":     map[string]any{"givenName": "Data", "familyName": "Monster"},
				"active":   true,
				"emails":   []map[string]any{{"value": "datamonster@amplitude.com", "primary": true}},
				"meta":     map[string]any{"resourceType": "User", "created": "2022-02-03T20:40:22.000Z"},
			}},
		},
		"/scim/1/Groups": {
			"Resources": []map[string]any{{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
				"id":          "632",
				"displayName": "Datamonster Party",
				"members": []map[string]any{{
					"value":   "datamonster@amplitude.com",
					"display": "Data Monster",
				}},
				"meta": map[string]any{"resourceType": "Group", "created": "2022-02-03T20:40:22.000Z", "lastModified": "2022-02-03T21:25:25.000Z"},
			}},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		body, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		body["schemas"] = []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}
		body["startIndex"] = 1
		body["itemsPerPage"] = 100
		body["totalResults"] = 1
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	for _, family := range []string{familyUsers, familyGroups} {
		cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": family, "token": "test-token", "per_page": "100"})
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read(%s) error = %v", family, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%s) events = %d, want 1", family, len(pull.Events))
		}
		if wantKind := "amplitude." + family; pull.Events[0].Kind != wantKind {
			t.Fatalf("Read(%s) kind = %q, want %q", family, pull.Events[0].Kind, wantKind)
		}
	}
}

func TestSCIMStartIndexPaginationAdvancesByPageSize(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	var startIndexes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startIndexes = append(startIndexes, r.URL.Query().Get("startIndex"))
		w.Header().Set("Content-Type", "application/json")
		start := 1
		id := "first@example.com"
		if r.URL.Query().Get("startIndex") == "101" {
			start = 101
			id = "second@example.com"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			"startIndex":   start,
			"itemsPerPage": 100,
			"totalResults": 200,
			"Resources": []map[string]any{{
				"id":       id,
				"userName": id,
				"active":   true,
				"emails":   []map[string]any{{"value": id, "primary": true}},
				"meta":     map[string]any{"resourceType": "User"},
			}},
		})
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyUsers, "token": "test-token", "per_page": "100"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("first Read() error = %v", err)
	}
	if pull.NextCursor == nil || pull.NextCursor.GetOpaque() != "101" {
		t.Fatalf("first NextCursor = %q, want 101", pull.NextCursor)
	}
	pull, err = source.Read(context.Background(), cfg, pull.NextCursor)
	if err != nil {
		t.Fatalf("second Read() error = %v", err)
	}
	if got := strings.Join(startIndexes, ","); got != "1,101" {
		t.Fatalf("startIndex requests = %q, want 1,101", got)
	}
	if pull.Events[0].Attributes["email"] != "second@example.com" {
		t.Fatalf("second page email = %q", pull.Events[0].Attributes["email"])
	}
}

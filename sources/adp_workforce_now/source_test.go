package adp_workforce_now

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/hr/v2/workers/meta" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/hr/v2/workers" {
			if r.URL.Path == "/core/v1/event-notification-messages" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"events": []map[string]any{{
						"actor": map[string]string{"associateOID": "G557KMGC6KCSVZRD"},
						"data": map[string]any{
							"eventContext": map[string]any{
								"worker": map[string]string{"associateOID": "G3GMA28TB2SVJ2TF"},
							},
						},
						"eventID":         "event-1",
						"eventNameCode":   map[string]string{"codeValue": "worker.hire"},
						"eventStatusCode": map[string]string{"effectiveDateTime": "2026-07-01T12:00:00Z"},
					}},
				})
				return
			}
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"workers": []map[string]any{{
				"associateOID": "G3GMA28TB2SVJ2TF",
				"businessCommunication": map[string]any{
					"emails": []map[string]string{{"emailUri": "jordan.worker@example.test"}},
				},
				"person": map[string]any{
					"legalName": map[string]string{"formattedName": "Jordan Worker"},
				},
				"workAssignments": []map[string]any{{
					"jobTitle": "HR Analyst",
					"homeOrganizationalUnits": []map[string]any{{
						"nameCode": map[string]string{"shortName": "People Operations"},
					}},
				}},
				"workerDates": map[string]string{
					"originalHireDate": "2022-01-15",
				},
				"workerStatus": map[string]any{
					"statusCode": map[string]string{"codeValue": "Active"},
				},
			}},
		})
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
	if event.Kind != "adp_workforce_now.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	eventCfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": "event_notifications", "token": "test-token"})
	eventPull, err := source.Read(context.Background(), eventCfg, nil)
	if err != nil {
		t.Fatalf("Read(event_notifications) error = %v", err)
	}
	if len(eventPull.Events) != 1 {
		t.Fatalf("event notification events = %d, want 1", len(eventPull.Events))
	}
	if eventPull.Events[0].Kind != "adp_workforce_now.event_notifications" {
		t.Fatalf("event notification kind = %q", eventPull.Events[0].Kind)
	}
}

func TestReadUsersAdvancesSkipByPageSizeAfterFullPage(t *testing.T) {
	requests := make([]*http.Request, 0, 2)
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.URL.Path != "/hr/v2/workers" {
			t.Fatalf("path = %q, want /hr/v2/workers", r.URL.Path)
		}
		if got := r.URL.Query().Get("$top"); got != "100" {
			t.Fatalf("$top query = %q, want 100", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("$skip") {
		case "0":
			workers := make([]map[string]any, 0, 100)
			for i := range 100 {
				workers = append(workers, map[string]any{
					"associateOID": "worker-full-page-" + strconv.Itoa(i),
					"person":       map[string]any{"legalName": map[string]string{"formattedName": "Full Page Worker"}},
					"businessCommunication": map[string]any{
						"emails": []map[string]string{{"emailUri": "full.page.worker@example.test"}},
					},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workers": workers})
		case "100":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workers": []map[string]any{{
					"associateOID": "worker-after-full-page",
					"person":       map[string]any{"legalName": map[string]string{"formattedName": "Next Page Worker"}},
				}},
			})
		default:
			t.Fatalf("unexpected $skip query = %q", r.URL.Query().Get("$skip"))
		}
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyUsers, "token": "test-token", "per_page": "100"})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor == nil || first.NextCursor.GetOpaque() != "100" {
		t.Fatalf("first NextCursor = %#v, want 100", first.NextCursor)
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if got := requests[0].URL.Query().Get("$skip"); got != "0" {
		t.Fatalf("first $skip query = %q, want 0", got)
	}
	if got := requests[1].URL.Query().Get("$skip"); got != "100" {
		t.Fatalf("second $skip query = %q, want 100", got)
	}
	if got := requests[1].URL.Query().Get("$skip"); got == "1" {
		t.Fatalf("second $skip query = %q, want page-size offset", got)
	}
}

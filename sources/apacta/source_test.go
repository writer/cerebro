package apacta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadDocumentedFamilies(t *testing.T) {
	tests := []struct {
		name       string
		family     string
		wantPath   string
		wantKind   string
		responseID string
		response   map[string]any
	}{
		{
			name:       "activity",
			family:     familyActivity,
			wantPath:   "/activities",
			wantKind:   "apacta.activity",
			responseID: "activity-1",
			response: map[string]any{
				"id": "activity-1", "company_id": "company-1", "hex_code": "336699", "name": "Installation", "erp_id": "erp-activity-1", "modified": "2026-06-01T00:00:00Z",
			},
		},
		{
			name:       "city",
			family:     familyCity,
			wantPath:   "/cities",
			wantKind:   "apacta.city",
			responseID: "city-1",
			response: map[string]any{
				"id": "city-1", "zip_code": 1000, "name": "Copenhagen", "modified": "2026-06-01T00:00:00Z",
			},
		},
		{
			name:       "contact person",
			family:     familyContactPerson,
			wantPath:   "/contacts/contact-1/contact_persons",
			wantKind:   "apacta.contact_person",
			responseID: "contact-person-1",
			response: map[string]any{
				"id": "contact-person-1", "contact_id": "contact-1", "name": "Alex Contact", "email": "alex@example.test", "title": "Manager", "modified": "2026-06-01T00:00:00Z",
			},
		},
		{
			name:       "project user",
			family:     familyProjectsUser,
			wantPath:   "/projects/project-1/users",
			wantKind:   "apacta.projects_user",
			responseID: "project-user-1",
			response: map[string]any{
				"id": "project-user-1", "email": "project.user@example.test", "full_name": "Project User", "is_active": true, "modified": "2026-06-01T00:00:00Z",
			},
		},
		{
			name:       "user",
			family:     familyUser,
			wantPath:   "/users",
			wantKind:   "apacta.user",
			responseID: "user-1",
			response: map[string]any{
				"id": "user-1", "email": "user@example.test", "first_name": "Casey", "last_name": "User", "full_name": "Casey User", "is_active": true, "modified": "2026-06-01T00:00:00Z",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()

			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Fatalf("Authorization = %q, want Bearer test-token", got)
				}
				wantPath := tt.wantPath
				if requests == 1 {
					wantPath = defaultHealthPath
				}
				if r.URL.Path != wantPath {
					t.Fatalf("path = %q, want %q", r.URL.Path, wantPath)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": []map[string]any{tt.response}})
			}))
			defer server.Close()

			cfgValues := map[string]string{
				"tenant_id": "tenant", "base_url": server.URL, "family": tt.family,
				"api_token": "test-token", "contact_id": "contact-1", "project_id": "project-1",
			}
			cfg := sourcecdk.NewConfig(cfgValues)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if requests < 2 {
				t.Fatalf("requests = %d, want at least health and read requests", requests)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.wantKind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if got := event.Attributes["id"]; got != tt.responseID {
				t.Fatalf("attribute id = %q, want %q", got, tt.responseID)
			}
		})
	}
}

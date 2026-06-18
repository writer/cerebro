package pagerduty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != "pagerduty" {
		t.Fatalf("Spec().Id = %q, want pagerduty", got)
	}
}

func TestReadPagerDutyResponderTopologyKinds(t *testing.T) {
	for _, tt := range []struct {
		name     string
		family   string
		kind     string
		path     string
		response map[string]any
		want     map[string]string
	}{
		{
			name:   "user",
			family: "user",
			kind:   "pagerduty.user",
			path:   "/users",
			response: map[string]any{"users": []map[string]any{{
				"id": "PU1", "name": "Alice Responder", "email": "alice@writer.com",
				"role": "admin", "time_zone": "UTC", "job_title": "SRE",
			}}},
			want: map[string]string{
				"user_id": "PU1", "name": "Alice Responder", "email": "alice@writer.com", "role": "admin",
			},
		},
		{
			name:   "team",
			family: "team",
			kind:   "pagerduty.team",
			path:   "/teams",
			response: map[string]any{"teams": []map[string]any{{
				"id": "PT1", "name": "Platform", "description": "Platform on-call",
			}}},
			want: map[string]string{"team_id": "PT1", "name": "Platform"},
		},
		{
			name:   "service_with_escalation_policy",
			family: "service",
			kind:   "pagerduty.service",
			path:   "/services",
			response: map[string]any{"services": []map[string]any{{
				"id": "PS1", "name": "Checkout API", "status": "active",
				"escalation_policy": map[string]any{"id": "PE1", "summary": "Checkout EP"},
			}}},
			want: map[string]string{
				"service_id": "PS1", "name": "Checkout API", "status": "active",
				"escalation_policy_id": "PE1", "escalation_policy_name": "Checkout EP",
			},
		},
		{
			name:   "service_without_escalation_policy",
			family: "service",
			kind:   "pagerduty.service",
			path:   "/services",
			response: map[string]any{"services": []map[string]any{{
				"id": "PS2", "name": "Orphan Service", "status": "active",
			}}},
			want: map[string]string{"service_id": "PS2", "name": "Orphan Service", "status": "active"},
		},
		{
			name:   "schedule",
			family: "schedule",
			kind:   "pagerduty.schedule",
			path:   "/schedules",
			response: map[string]any{"schedules": []map[string]any{{
				"id": "PSC1", "name": "Primary", "time_zone": "UTC",
			}}},
			want: map[string]string{"schedule_id": "PSC1", "name": "Primary", "time_zone": "UTC"},
		},
		{
			name:   "escalation_policy",
			family: "escalation_policy",
			kind:   "pagerduty.escalation_policy",
			path:   "/escalation_policies",
			response: map[string]any{"escalation_policies": []map[string]any{{
				"id": "PE1", "name": "Checkout EP", "num_loops": 2,
			}}},
			want: map[string]string{"escalation_policy_id": "PE1", "name": "Checkout EP", "num_loops": "2"},
		},
		{
			name:   "integration",
			family: "integration",
			kind:   "pagerduty.integration",
			path:   "/services/PS1/integrations",
			response: map[string]any{"integrations": []map[string]any{{
				"id": "PI1", "name": "Datadog", "summary": "Datadog integration",
				"service": map[string]any{"id": "PS-STALE", "summary": "Checkout API"},
				"vendor":  map[string]any{"id": "PV1", "summary": "Datadog"},
			}}},
			want: map[string]string{
				"integration_id": "PI1", "service_id": "PS1", "service_name": "Checkout API",
				"vendor_id": "PV1", "vendor_name": "Datadog",
			},
		},
		{
			name:   "vendor",
			family: "vendor",
			kind:   "pagerduty.vendor",
			path:   "/vendors",
			response: map[string]any{"vendors": []map[string]any{{
				"id": "PV1", "name": "Datadog", "website_url": "https://datadoghq.com",
			}}},
			want: map[string]string{"vendor_id": "PV1", "name": "Datadog", "website_url": "https://datadoghq.com"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "service_id": "PS1", "token": "pagerduty-token"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}

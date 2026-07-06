package aha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadUsers(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(ahaTestHandler(t, map[string]any{
		"/users": map[string]any{
			"users":      []map[string]any{{"id": "user-1", "name": "Grace Hopper", "email": "grace@example.test", "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-02T00:00:00Z"}},
			"pagination": map[string]any{"total_records": 1, "total_pages": 1, "current_page": 1},
		},
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "per_page": "100"})
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
	if event.Kind != "aha.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["user_id"]; got != "user-1" {
		t.Fatalf("user_id = %q, want user-1", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadProviderVerifiedFamilyPaths(t *testing.T) {
	tests := []struct {
		family    string
		path      string
		response  map[string]any
		wantKind  string
		extraConf map[string]string
	}{
		{
			family:   familyProducts,
			path:     "/products",
			wantKind: "aha.products",
			response: map[string]any{"products": []map[string]any{{"id": "product-1", "name": "Roadmaps", "reference_prefix": "APP", "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-02T00:00:00Z"}}, "pagination": pageOne()},
		},
		{
			family:   familyFeatures,
			path:     "/features",
			wantKind: "aha.features",
			response: map[string]any{"features": []map[string]any{{"id": "feature-1", "name": "Export roadmap", "reference_num": "APP-1", "product": map[string]any{"id": "product-1"}, "release": map[string]any{"id": "release-1"}, "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-02T00:00:00Z"}}, "pagination": pageOne()},
		},
		{
			family:    familyReleases,
			path:      "/products/PRODUCT-1/releases",
			wantKind:  "aha.releases",
			extraConf: map[string]string{"product_id": "PRODUCT-1"},
			response:  map[string]any{"releases": []map[string]any{{"id": "release-1", "name": "Q3 Launch", "reference_num": "APP-R-1", "product": map[string]any{"id": "PRODUCT-1"}, "release_date": "2026-09-30", "created_at": "2026-06-01T00:00:00Z", "updated_at": "2026-06-02T00:00:00Z"}}, "pagination": pageOne()},
		},
		{
			family:   familyAuditEvents,
			path:     "/audits",
			wantKind: "aha.audit_events",
			response: map[string]any{"audits": []map[string]any{{"id": "audit-1", "action": "update", "auditable_type": "Feature", "auditable_id": "feature-1", "created_at": "2026-06-02T00:00:00Z", "user": map[string]any{"id": "user-1", "name": "Grace Hopper", "email": "grace@example.test"}}}, "pagination": pageOne()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(ahaTestHandler(t, map[string]any{tt.path: tt.response}))
			defer server.Close()

			cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token", "per_page": "100"}
			for key, value := range tt.extraConf {
				cfgValues[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(cfgValues), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got, tt.wantKind)
			}
		})
	}
}

func ahaTestHandler(t *testing.T, responses map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path == "/me" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		response, ok := responses[r.URL.Path]
		if !ok {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}
}

func pageOne() map[string]any {
	return map[string]any{"total_records": 1, "total_pages": 1, "current_page": 1}
}

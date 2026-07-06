package anchore

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
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/system" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/apps/app-1/versions/version-1/assets" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"pagination": map[string]any{"item_count": 1, "next_cursor": ""},
			"items": []map[string]any{{
				"name":      "docker.io/library/nginx:latest",
				"type":      "container",
				"reference": "docker.io/library/nginx:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"system_metadata": map[string]string{
					"id":         "11111111-1111-4111-8111-111111111111",
					"created_at": "2026-06-01T00:00:00Z",
					"updated_at": "2026-06-02T00:00:00Z",
				},
			}},
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "username": "alice", "password": "secret", "enterprise_url": "test-enterprise_url", "app_id": "app-1", "version_id": "version-1"}
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
	if event.Kind != "anchore.assets" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestReadAnchoreRuntimeFamiliesUseDocumentedPaths(t *testing.T) {
	tests := []struct {
		family string
		path   string
		body   map[string]any
		kind   string
	}{
		{
			family: familyAssets,
			path:   "/apps/app-1/versions/version-1/assets",
			kind:   "anchore.assets",
			body: map[string]any{
				"pagination": map[string]any{"item_count": 1, "next_cursor": ""},
				"items": []map[string]any{{
					"name":      "docker.io/library/alpine:latest",
					"type":      "container",
					"reference": "docker.io/library/alpine:latest@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					"system_metadata": map[string]string{
						"id":         "22222222-2222-4222-8222-222222222222",
						"created_at": "2026-06-01T00:00:00Z",
						"updated_at": "2026-06-02T00:00:00Z",
					},
				}},
			},
		},
		{
			family: familyFindings,
			path:   "/apps/app-1/versions/version-1/policy/findings/all",
			kind:   "anchore.findings",
			body: map[string]any{
				"pagination": map[string]any{"item_count": 1, "next_cursor": ""},
				"items": []map[string]any{{
					"rule":            map[string]any{"id": "dockerfile-secrets", "gate": "dockerfile", "trigger": "instruction", "recommendation": "Remove embedded secrets."},
					"result":          map[string]any{"trigger_id": "policy-trigger-1", "action": "stop", "message": "Dockerfile contains a secret."},
					"assets_affected": 1,
				}},
			},
		},
		{
			family: familyVulnerabilities,
			path:   "/apps/app-1/versions/version-1/vulnerabilities",
			kind:   "anchore.vulnerabilities",
			body: map[string]any{
				"pagination": map[string]any{"item_count": 1, "next_cursor": ""},
				"items": []map[string]any{{
					"vulnerability_id": "CVE-2026-0001",
					"severity":         "high",
					"fix_state":        "not_fixed",
					"package_name":     "openssl",
					"package_version":  "3.0.0",
					"package_type":     "apk",
					"purl":             "pkg:apk/alpine/openssl@3.0.0",
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.body)
			}))
			defer server.Close()
			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "username": "alice", "password": "secret", "app_id": "app-1", "version_id": "version-1"})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
		})
	}
}

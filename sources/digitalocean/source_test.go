package digitalocean

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceReadsFamilies(t *testing.T) {
	fixtures := map[string]string{
		"/v2/droplets":  "testdata/read_droplets.json",
		"/v2/vpcs":      "testdata/read_vpcs.json",
		"/v2/firewalls": "testdata/read_firewalls.json",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		fixture, ok := fixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := os.ReadFile(filepath.FromSlash(fixture))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	cases := []struct {
		family string
		kind   string
	}{
		{familyDroplets, "digitalocean.droplets"},
		{familyVPCs, "digitalocean.vpcs"},
		{familyFirewalls, "digitalocean.firewalls"},
	}
	for _, tc := range cases {
		t.Run(tc.family, func(t *testing.T) {
			source, err := newSource(clientOptions{allowLoopback: true})
			if err != nil {
				t.Fatalf("newSource() error = %v", err)
			}
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"token":     "test-token",
				"family":    tc.family,
				"base_url":  server.URL + "/",
			})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) == 0 {
				t.Fatalf("Discover() returned no URNs")
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) == 0 {
				t.Fatalf("Read() returned no events")
			}
			for _, event := range pull.Events {
				if event.GetKind() != tc.kind {
					t.Fatalf("event kind = %q, want %q", event.GetKind(), tc.kind)
				}
				if strings.TrimSpace(event.GetId()) == "" {
					t.Fatalf("event id is empty")
				}
				if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
					t.Fatalf("ValidateEventEnvelope() error = %v", err)
				}
			}
		})
	}
}

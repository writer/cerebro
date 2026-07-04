package meraki

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
		if r.Header.Get(tokenHeader) != "test-token" {
			t.Fatalf("%s = %q", tokenHeader, r.Header.Get(tokenHeader))
		}
		if r.URL.Path != "/networks/network-1/events/eventTypes" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "networkid": "network-1", "api_key": "test-token"}
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
	if event.Kind != "meraki.eventtype" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestAccessPolicyMapsPolicyName(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tokenHeader) != "test-token" {
			t.Fatalf("%s = %q", tokenHeader, r.Header.Get(tokenHeader))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/networks/network-1/events/eventTypes":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "event-type-1"}})
		case "/networks/network-1/switch/accessPolicies":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "policy-1", "name": "Guest WiFi", "resource_urn": "urn:cerebro:tenant:policy:policy-1"}})
		default:
			t.Fatalf("path = %q", r.URL.Path)
		}
	}))
	defer server.Close()
	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyAccesspolicy, "networkid": "network-1", "api_key": "test-token"})
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
	if got := pull.Events[0].Attributes["policy_name"]; got != "Guest WiFi" {
		t.Fatalf("policy_name = %q, want Guest WiFi", got)
	}
	if got := pull.Events[0].Attributes["policy_type"]; got != "accesspolicy" {
		t.Fatalf("policy_type = %q, want accesspolicy", got)
	}
}

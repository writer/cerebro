package grc

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadVantaVendorPagesAsCanonicalGRCEvents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVendor)

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(discover))
	}
	if got := discover[0].String(); !strings.Contains(got, "grc_vendor:vanta:vendor-1") {
		t.Fatalf("Discover()[0] = %q, want vendor-1 grc urn", got)
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	event := first.Events[0]
	if event.Kind != "grc.vendor" {
		t.Fatalf("event.Kind = %q, want grc.vendor", event.Kind)
	}
	if event.SourceId != "grc" {
		t.Fatalf("event.SourceId = %q, want grc", event.SourceId)
	}
	if got := event.Attributes["provider"]; got != "vanta" {
		t.Fatalf("event provider = %q, want vanta", got)
	}
	if got := event.Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("event inherent_risk_level = %q, want HIGH", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal event payload: %v", err)
	}
	if got := payload["name"]; got != "Acme SaaS" {
		t.Fatalf("payload name = %#v, want Acme SaaS", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := second.Events[0].Attributes["vendor_id"]; got != "vendor-2" {
		t.Fatalf("second vendor_id = %q, want vendor-2", got)
	}
}

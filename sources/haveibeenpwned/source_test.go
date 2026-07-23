package haveibeenpwned

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedBreaches(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyBreaches, "adobe")
	if err != nil {
		t.Fatalf("FindBundle() error = %v", err)
	}
	const providerPath = "/breaches"
	if !strings.Contains(bundle.Manifest.Request.URL, providerPath+"?domain=adobe.com") {
		t.Fatalf("capture URL = %q, want Adobe breach filter", bundle.Manifest.Request.URL)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	sawDomainFilter := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty for public breach metadata", got)
		}
		if got := r.Header.Get("hibp-api-key"); got != "" {
			t.Fatalf("hibp-api-key = %q, want empty for public breach metadata", got)
		}
		if r.URL.Path != providerPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, providerPath)
		}
		if got := r.URL.Query().Get("domain"); got == "adobe.com" {
			sawDomainFilter = true
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "domain": "adobe.com", "family": familyBreaches, "health_path": providerPath}
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
	if !sawDomainFilter {
		t.Fatal("captured domain filter was not replayed")
	}
	event := pull.Events[0]
	if event.Kind != "haveibeenpwned.breaches" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["finding_id"] != "Adobe" || event.Attributes["resource_id"] != "adobe.com" {
		t.Fatalf("breach attributes = %#v", event.Attributes)
	}
	if event.Attributes["severity"] != "unknown" || event.Attributes["status"] != "observed" {
		t.Fatalf("breach classification = %#v", event.Attributes)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:haveibeenpwned_breaches:adobe.com" {
		t.Fatalf("resource_urn = %q", got)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyBreaches, pull.Events, urns, os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES") == "1"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("stabilized event id is empty: %#v", event)
	}
	if _, err := sourcefixture.NewCatalogSource(".", defaultFamily); err != nil {
		t.Fatalf("NewCatalogSource() error = %v", err)
	}
}

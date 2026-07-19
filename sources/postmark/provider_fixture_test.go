package postmark

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceReplaysCapturedPostmarkDomains(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyDomains, "list_domains")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Postmark-Account-Token") != "replay-token" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() || r.URL.Query().Get("count") != "2" || r.URL.Query().Get("offset") != "0" {
			t.Fatalf("unexpected Postmark replay request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatal(err)
	}
	source.allowLoopbackForTest()
	cfg := sourcecdk.NewConfig(map[string]string{"api_token": "replay-token", "base_url": server.URL, "family": familyDomains, "per_page": "2", "tenant_id": "tenant"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("Read() events = %d, want 2", len(pull.Events))
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	for index, event := range pull.Events {
		if index >= len(urns) || event.Attributes["resource_urn"] != urns[index].String() {
			t.Fatalf("domain resource_urn = %q, discover URN = %#v", event.Attributes["resource_urn"], urns)
		}
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
		t.Fatal(err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyDomains, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}

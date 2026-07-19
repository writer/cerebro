package contentful

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

func TestSourceReplaysCapturedContentfulDocuments(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyDocuments, "list_entries")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer replay-token" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected Contentful replay request %s %s", r.Method, r.URL.RequestURI())
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
	cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyDocuments, "space_id": "cfexampleapi", "tenant_id": "tenant", "token": "replay-token"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 10 {
		t.Fatalf("Read() events = %d, want 10", len(pull.Events))
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
		t.Fatal(err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyDocuments, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}

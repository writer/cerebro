package bamboohr

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

func TestSourceReplaysCapturedBambooHRUsers(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyUsers, "employee_directory")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := url.Parse(bundle.Manifest.Request.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic cmVwbGF5LXRva2VuOng=" || r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
			t.Fatalf("unexpected BambooHR replay request %s %s", r.Method, r.URL.RequestURI())
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
	cfg := sourcecdk.NewConfig(map[string]string{"api_key": "replay-token", "base_url": server.URL + "/api/gateway.php/hogwarts", "company": "hogwarts", "family": familyUsers, "tenant_id": "tenant"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || !strings.HasSuffix(pull.Events[0].Attributes["email"], "@example.test") {
		t.Fatalf("captured events = %#v", pull.Events)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
		t.Fatal(err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyUsers, pull.Events, urns, strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"); err != nil {
		t.Fatal(err)
	}
}

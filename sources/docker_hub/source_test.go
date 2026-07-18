package docker_hub

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

func TestSourceReplaysCapturedRepository(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyRepositories, "ubuntu_repository")
	if err != nil {
		t.Fatalf("FindBundle() error = %v", err)
	}
	const providerPath = "/v2/namespaces/library/repositories/ubuntu"
	if !strings.HasSuffix(bundle.Manifest.Request.URL, providerPath) {
		t.Fatalf("capture URL = %q, want suffix %q", bundle.Manifest.Request.URL, providerPath)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty for public repository endpoint", got)
		}
		if r.URL.Path != providerPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, providerPath)
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyRepositories, "health_path": defaultHealthPath, "namespace": "library", "repository": "ubuntu"}
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
	if event.Kind != "docker_hub.repositories" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.Attributes["resource_id"] != "library/ubuntu" || event.Attributes["resource_name"] != "ubuntu" {
		t.Fatalf("repository attributes = %#v", event.Attributes)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:docker_hub_repositories:library%2Fubuntu" {
		t.Fatalf("resource_urn = %q", got)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if err := sourcefixture.StabilizeEvents(bundle, pull.Events, false); err != nil {
		t.Fatalf("StabilizeEvents() error = %v", err)
	}
	if err := sourcefixture.CompareOrUpdateSourceOutputs(".", familyRepositories, pull.Events, urns, os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES") == "1"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("stabilized event id is empty: %#v", event)
	}
	if _, err := NewFixture(); err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
}

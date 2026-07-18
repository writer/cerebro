package huggingface

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

func TestSourceReplaysCapturedModels(t *testing.T) {
	bundle, err := sourcefixture.FindBundle("../..", sourceID, familyRepositories, "models")
	if err != nil {
		t.Fatalf("FindBundle() error = %v", err)
	}
	const providerPath = "/models"
	if !strings.Contains(bundle.Manifest.Request.URL, "/api/models?author=google-bert&limit=1") {
		t.Fatalf("capture URL = %q, want public model query", bundle.Manifest.Request.URL)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	sawCapturedQuery := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization = %q, want empty for public models endpoint", got)
		}
		if r.URL.Path != providerPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, providerPath)
		}
		if r.URL.Query().Get("author") == "google-bert" && r.URL.Query().Get("limit") == "1" {
			sawCapturedQuery = true
		}
		w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
		for name, value := range bundle.Manifest.Response.Headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(bundle.Manifest.Response.Status)
		_, _ = w.Write(bundle.Payload)
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyRepositories, "health_path": providerPath, "organization": "google-bert", "per_page": "1"}
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
	if event.Kind != "huggingface.repositories" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if !sawCapturedQuery {
		t.Fatal("captured author and limit query was not replayed")
	}
	if event.Attributes["resource_id"] != "google-bert/bert-base-chinese" || event.Attributes["resource_type"] != "model_repository" {
		t.Fatalf("model attributes = %#v", event.Attributes)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:huggingface_repositories:google-bert%2Fbert-base-chinese" {
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

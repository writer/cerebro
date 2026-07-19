package opendatasoft

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/test-source/aggregates" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Aggregate Fixture", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "auth_model": "api_key", "api_token": "test-token", "dataset_id": "test-dataset_id", "source": "test-source"}
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
	if event.Kind != "opendatasoft.aggregate" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReplaysCapturedOpenDataSoftFamilies(t *testing.T) {
	const publicDatasetID = "pole-emploi-rome-arborescence-principale"
	tests := []struct {
		family      string
		fixtureCase string
		minimum     int
		config      map[string]string
	}{
		{family: familyAggregate, fixtureCase: "catalog_aggregates", minimum: 1, config: map[string]string{"select": "count(*)"}},
		{family: familyPage, fixtureCase: "pages", minimum: 1},
		{family: familyDataset, fixtureCase: "catalog_datasets", minimum: 1},
		{family: familyFacet, fixtureCase: "catalog_facets", minimum: 1},
		{family: familyResource, fixtureCase: "catalog_root", minimum: 1},
		{family: familyResource2, fixtureCase: "api_root", minimum: 1},
		{family: familyMetadataTemplate, fixtureCase: "metadata_templates", minimum: 1},
		{family: familyDatasetsAggregate, fixtureCase: "dataset_aggregates", minimum: 1, config: map[string]string{"select": "count(*)"}},
		{family: familyAttachment, fixtureCase: "dataset_attachments", minimum: 1},
		{family: familyDatasetsFacet, fixtureCase: "dataset_facets", minimum: 1},
		{family: familyRecord, fixtureCase: "dataset_records", minimum: 1},
		{family: familyReuses, fixtureCase: "dataset_reuses"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, test.fixtureCase)
			if err != nil {
				t.Fatalf("FindBundle(%s/%s) error = %v", test.family, test.fixtureCase, err)
			}
			captured, err := url.Parse(bundle.Manifest.Request.URL)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "" {
					t.Fatalf("Authorization = %q, want empty for public OpenDataSoft endpoint", got)
				}
				if r.Method != http.MethodGet || r.URL.EscapedPath() != captured.EscapedPath() {
					t.Fatalf("unexpected OpenDataSoft replay request %s %s", r.Method, r.URL.RequestURI())
				}
				if !equalQuery(r.URL.Query(), captured.Query()) {
					t.Fatalf("query = %q, want %q", r.URL.Query().Encode(), captured.Query().Encode())
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
			values := map[string]string{
				"auth_model": "none",
				"base_url":   server.URL + "/api/v2",
				"dataset_id": publicDatasetID,
				"family":     test.family,
				"per_page":   "1",
				"source":     "catalog",
				"tenant_id":  "tenant",
			}
			for key, value := range test.config {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) < test.minimum {
				t.Fatalf("Read() events = %d, want at least %d", len(pull.Events), test.minimum)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			for _, event := range pull.Events {
				if event.Kind != "opendatasoft."+test.family || strings.TrimSpace(event.Id) == "" {
					t.Fatalf("captured event = %#v", event)
				}
			}
			update := strings.TrimSpace(os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES")) == "1"
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, update); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func equalQuery(left, right url.Values) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok || len(leftValues) != len(rightValues) {
			return false
		}
		for index, leftValue := range leftValues {
			if rightValues[index] != leftValue {
				return false
			}
		}
	}
	return true
}

package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/catalogruntime"
)

func TestCatalogRuntimeMatchesGoOracleFixtures(t *testing.T) {
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil {
		t.Fatalf("BuiltinEntry(%q) error = %v", sourceID, err)
	}
	if !ok {
		t.Fatalf("BuiltinEntry(%q) not found", sourceID)
	}
	for _, family := range openAIFamilies() {
		family := family
		t.Run(family.Name, func(t *testing.T) {
			expected := readOracleEvent(t, family.Name)
			payload, err := json.Marshal(expected.Payload)
			if err != nil {
				t.Fatal(err)
			}
			response := payload
			if !family.Singleton {
				response, err = json.Marshal(map[string]any{"data": []json.RawMessage{payload}, "has_more": false})
				if err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write(response)
			}))
			defer server.Close()

			manual, err := New()
			if err != nil {
				t.Fatal(err)
			}
			manual.inner.AllowLoopbackBaseURL = true
			compiled, err := catalogruntime.NewDefinitionWithValidationOptions(entry.Definition, catalogruntime.ValidationOptions{AllowLoopbackBaseURL: true})
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{
				"api_key":   "credential-reference-fixture", // #nosec G101 -- non-secret fixture reference.
				"token":     "credential-reference-fixture", // #nosec G101 -- non-secret fixture reference.
				"base_url":  server.URL,
				"family":    family.Name,
				"tenant_id": expected.TenantID,
			}
			for _, parameter := range family.PathParams {
				values[parameter] = expected.Attributes[parameter]
			}
			cfg := sourcecdk.NewConfig(values)
			goPull, err := manual.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("manual Read() error = %v", err)
			}
			rustPull, err := compiled.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("catalog Read() error = %v", err)
			}
			if len(goPull.Events) != 1 || len(rustPull.Events) != 1 {
				t.Fatalf("event counts = manual %d catalog %d, want 1 each", len(goPull.Events), len(rustPull.Events))
			}
			goEvent, catalogEvent := goPull.Events[0], rustPull.Events[0]
			if catalogEvent.Id != goEvent.Id || catalogEvent.Kind != goEvent.Kind || catalogEvent.SchemaRef != goEvent.SchemaRef || catalogEvent.SourceId != goEvent.SourceId || catalogEvent.TenantId != goEvent.TenantId {
				t.Fatalf("identity contract mismatch:\nmanual=%#v\ncatalog=%#v", goEvent, catalogEvent)
			}
			if string(catalogEvent.Payload) != string(goEvent.Payload) {
				t.Fatalf("payload mismatch:\nmanual=%s\ncatalog=%s", goEvent.Payload, catalogEvent.Payload)
			}
			for attribute, want := range goEvent.Attributes {
				if got := catalogEvent.Attributes[attribute]; got != want {
					t.Fatalf("catalog attribute %s = %q, want Go oracle %q", attribute, got, want)
				}
			}
		})
	}
}

type oracleEvent struct {
	TenantID   string            `json:"tenant_id"`
	Payload    json.RawMessage   `json:"payload"`
	Attributes map[string]string `json:"attributes"`
}

func readOracleEvent(t *testing.T, family string) oracleEvent {
	t.Helper()
	path := filepath.Join("testdata", "read_"+family+".json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []oracleEvent
	if err := json.Unmarshal(bytes, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("%s fixture has %d events, want 1", path, len(events))
	}
	return events[0]
}

package backstage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
)

func TestSourceSpec(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "backstage" {
		t.Fatalf("Spec().Id = %q, want backstage", source.Spec().Id)
	}
	if source.Spec().Name != "Backstage" {
		t.Fatalf("Spec().Name = %q, want Backstage", source.Spec().Name)
	}
}

func TestRuntimeFixturesSatisfyCatalogContracts(t *testing.T) {
	catalogBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	for _, family := range []string{familyComponent, familySystem} {
		if _, err := sourcecdk.LoadFixtureURNs(os.DirFS("."), "testdata/discover_"+family+".json"); err != nil {
			t.Fatalf("load %s discover fixture: %v", family, err)
		}
		if _, err := sourcecdk.LoadFixtureEventsWithContracts(os.DirFS("."), "testdata/read_"+family+".json", catalog.EventContracts); err != nil {
			t.Fatalf("load %s read fixture: %v", family, err)
		}
	}
}

func TestGenuineProviderResponsesReplayEveryRuntimeFamily(t *testing.T) {
	tests := []struct {
		family   string
		wantKind string
	}{
		{family: familyComponent, wantKind: "backstage.component"},
		{family: familySystem, wantKind: "backstage.system"},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			bundle, err := sourcefixture.FindBundle("../..", sourceID, test.family, "public_first_page")
			if err != nil {
				t.Fatalf("FindBundle() error = %v", err)
			}
			capturedURL, err := url.Parse(bundle.Manifest.Request.URL)
			if err != nil {
				t.Fatalf("parse captured URL: %v", err)
			}
			if capturedURL.Path != "/api/catalog/entities/by-query" {
				t.Fatalf("capture path = %q, want /api/catalog/entities/by-query", capturedURL.Path)
			}
			if got, want := capturedURL.Query().Get("filter"), "kind="+test.family; got != want {
				t.Fatalf("capture filter = %q, want %q", got, want)
			}
			if got := capturedURL.Query().Get("limit"); got != "1" {
				t.Fatalf("capture limit = %q, want 1", got)
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Fatalf("method = %q, want GET", r.Method)
				}
				if r.URL.Path != capturedURL.Path {
					t.Fatalf("path = %q, want %q", r.URL.Path, capturedURL.Path)
				}
				if got, want := r.URL.Query().Get("filter"), "kind="+test.family; got != want {
					t.Fatalf("filter = %q, want %q", got, want)
				}
				if got := r.URL.Query().Get("limit"); got != "100" {
					t.Fatalf("limit = %q, want 100", got)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
					t.Fatalf("Authorization = %q, want Bearer replay-token", got)
				}
				w.Header().Set("Content-Type", bundle.Manifest.Response.ContentType)
				for name, value := range bundle.Manifest.Response.Headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(bundle.Manifest.Response.Status)
				_, _ = w.Write(bundle.Payload)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			cfg := sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"token":     "replay-token",
				"family":    test.family,
			})
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != test.wantKind {
				t.Fatalf("event kind = %q, want %q", got, test.wantKind)
			}
			for _, attribute := range []string{"name", "kind"} {
				if strings.TrimSpace(pull.Events[0].Attributes[attribute]) == "" {
					t.Fatalf("required attribute %q missing", attribute)
				}
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if err := sourcefixture.StabilizeEvents(bundle, pull.Events, true); err != nil {
				t.Fatalf("StabilizeEvents() error = %v", err)
			}
			if err := sourcefixture.CompareOrUpdateSourceOutputs(".", test.family, pull.Events, urns, os.Getenv("CEREBRO_UPDATE_SOURCE_FIXTURES") == "1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadComponentFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/catalog/entities/by-query" {
			t.Fatalf("request path = %q, want /api/catalog/entities/by-query", r.URL.Path)
		}
		if got := r.URL.Query().Get("filter"); got != "kind=component" {
			t.Fatalf("filter query = %q, want kind=component", got)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit query = %q, want 100", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "" {
			t.Fatalf("per_page query = %q, want empty", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer backstage-token" {
			t.Fatalf("Authorization = %q, want Bearer backstage-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"kind": "Component",
				"metadata": map[string]any{
					"uid":         "component-1",
					"name":        "cerebro",
					"namespace":   "default",
					"description": "Security intelligence graph",
					"annotations": map[string]any{
						"cerebro.io/criticality":         "high",
						"cerebro.io/data-classification": "restricted",
					},
				},
				"spec": map[string]any{
					"type":      "service",
					"lifecycle": "production",
					"owner":     "group:platform/security",
					"system":    "security",
				},
				"repository": "WriterInternal/cerebro",
			}},
			"totalItems": 1,
			"pageInfo":   map[string]any{},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "backstage.component" {
		t.Fatalf("Kind = %q, want backstage.component", event.Kind)
	}
	if event.Attributes["name"] != "cerebro" || event.Attributes["owner"] != "group:platform/security" {
		t.Fatalf("attrs = %#v, want Backstage component attributes", event.Attributes)
	}
	if event.Attributes["repository"] != "WriterInternal/cerebro" {
		t.Fatalf("repository = %q, want WriterInternal/cerebro", event.Attributes["repository"])
	}
	if event.Attributes["criticality"] != "high" || event.Attributes["data_class"] != "restricted" {
		t.Fatalf("annotation attrs = %#v, want Backstage annotation attributes", event.Attributes)
	}
}

func TestReadSystemFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/catalog/entities/by-query" {
			t.Fatalf("request path = %q, want /api/catalog/entities/by-query", r.URL.Path)
		}
		if got := r.URL.Query().Get("filter"); got != "kind=system" {
			t.Fatalf("filter query = %q, want kind=system", got)
		}
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit query = %q, want 100", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer backstage-token" {
			t.Fatalf("Authorization = %q, want Bearer backstage-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{
				"kind": "System",
				"metadata": map[string]any{
					"uid":         "system-1",
					"name":        "security-platform",
					"namespace":   "default",
					"description": "Security services",
				},
				"spec": map[string]any{
					"type":   "product",
					"owner":  "group:platform/security",
					"domain": "security",
				},
			}},
			"totalItems": 1,
			"pageInfo":   map[string]any{},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "system",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "backstage.system" {
		t.Fatalf("Kind = %q, want backstage.system", event.Kind)
	}
	if event.Attributes["name"] != "security-platform" || event.Attributes["owner"] != "group:platform/security" {
		t.Fatalf("attrs = %#v, want Backstage system attributes", event.Attributes)
	}
	if event.Attributes["domain"] != "security" {
		t.Fatalf("domain = %q, want security", event.Attributes["domain"])
	}
}

func TestReadComponentFamilyEmitsOwnershipContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"kind": "Component",
				"metadata": map[string]any{
					"uid":       "component-9",
					"name":      "payments",
					"namespace": "default",
					"annotations": map[string]any{
						"cerebro.io/criticality": "tier0",
					},
				},
				"spec": map[string]any{
					"type":      "service",
					"lifecycle": "production",
					"owner":     "group:platform/payments",
					"system":    "commerce",
				},
			},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	for _, required := range []string{"name", "kind"} {
		if strings.TrimSpace(event.Attributes[required]) == "" {
			t.Fatalf("required attribute %q missing, attrs = %#v", required, event.Attributes)
		}
	}
	if event.Attributes["owner"] != "group:platform/payments" {
		t.Fatalf("owner = %q, want group:platform/payments", event.Attributes["owner"])
	}
	if event.Attributes["criticality"] != "tier0" {
		t.Fatalf("criticality = %q, want tier0", event.Attributes["criticality"])
	}
	if event.Attributes["system"] != "commerce" {
		t.Fatalf("system = %q, want commerce", event.Attributes["system"])
	}
}

func TestReadComponentFamilyRejectsRecordWithoutIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"kind": "Component",
				"spec": map[string]any{"type": "service"},
			},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want rejection of component record without stable identity")
	}
}

func TestReadComponentFamilyUsesStableRecordTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"kind":       "Component",
					"updated_at": "2026-05-01T12:00:00Z",
					"metadata": map[string]any{
						"uid":        "component-1",
						"name":       "cerebro",
						"etag":       "etag-value",
						"generation": 7,
					},
				},
			},
			"pageInfo": map[string]any{"nextCursor": "page-2"},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "backstage-token",
		"family":    "component",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	want := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if got := pull.Events[0].OccurredAt.AsTime(); !got.Equal(want) {
		t.Fatalf("OccurredAt = %s, want %s", got, want)
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
}

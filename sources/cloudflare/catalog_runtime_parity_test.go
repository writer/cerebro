package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcefixture"
	"github.com/writer/cerebro/sources/catalogruntime"
)

type cloudflareOracleEvent struct {
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind"`
	SchemaRef  string            `json:"schema_ref"`
	Payload    json.RawMessage   `json:"payload"`
	Attributes map[string]string `json:"attributes"`
}

func TestCatalogRuntimeMatchesAllCloudflareGoOracleFamilies(t *testing.T) {
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil {
		t.Fatalf("BuiltinEntry(cloudflare) error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(cloudflare) ok = false")
	}

	for _, family := range entry.Definition.ResourceFamilies {
		family := family
		t.Run(family.ID, func(t *testing.T) {
			oracle := readCloudflareOracleEvent(t, family.ID)
			response, err := json.Marshal(map[string]any{
				"success":     true,
				"errors":      []any{},
				"messages":    []any{},
				"result":      []json.RawMessage{oracle.Payload},
				"result_info": map[string]any{"page": 1, "per_page": 100, "total_pages": 1, "total_count": 1},
			})
			if err != nil {
				t.Fatalf("marshal provider response: %v", err)
			}
			serverFor := func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if got := r.Header.Get("Authorization"); got != "Bearer replay-token" {
						t.Fatalf("Authorization = %q, want applied outside provider definition", got)
					}
					w.Header().Set("Content-Type", "application/json")
					if family.Read != nil && family.Read.DetailPath != "" && strings.HasSuffix(r.URL.EscapedPath(), "/"+oracle.Attributes[idAttributeForParity(family.ID)]) {
						detail, err := json.Marshal(map[string]any{"success": true, "result": oracle.Payload})
						if err != nil {
							t.Fatalf("marshal detail response: %v", err)
						}
						_, _ = w.Write(detail)
						return
					}
					_, _ = w.Write(response)
				}))
			}

			goServer := serverFor()
			defer goServer.Close()
			goSource := capturedCloudflareSource(t)
			goPull, err := goSource.Read(context.Background(), cloudflareParityConfig(goServer.URL, family.ID, oracle.Attributes), nil)
			if err != nil {
				t.Fatalf("Go Read() error = %v", err)
			}

			rustServer := serverFor()
			defer rustServer.Close()

			definition := entry.Definition
			definition.Transport.BaseURL = rustServer.URL + "/client/v4"
			source, err := catalogruntime.NewDefinitionWithValidationOptions(definition, catalogruntime.ValidationOptions{AllowLoopbackBaseURL: true})
			if err != nil {
				t.Fatalf("NewDefinition() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cloudflareParityConfig(rustServer.URL, family.ID, oracle.Attributes), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 || len(goPull.Events) != 1 {
				t.Fatalf("events = %d, want one Go oracle event", len(pull.Events))
			}
			if pull.NextCursor != nil {
				t.Fatalf("terminal cursor = %#v, want nil", pull.NextCursor)
			}
			event := pull.Events[0]
			goEvent := goPull.Events[0]
			if event.TenantId != oracle.TenantID || event.SourceId != oracle.SourceID || event.Kind != oracle.Kind || event.SchemaRef != oracle.SchemaRef {
				t.Fatalf("event contract = tenant %q source %q kind %q schema %q, want %#v", event.TenantId, event.SourceId, event.Kind, event.SchemaRef, oracle)
			}
			var gotPayload any
			if err := json.Unmarshal(event.Payload, &gotPayload); err != nil {
				t.Fatalf("event payload: %v", err)
			}
			var goPayload any
			if err := json.Unmarshal(goEvent.Payload, &goPayload); err != nil {
				t.Fatalf("Go payload: %v", err)
			}
			if !reflect.DeepEqual(gotPayload, goPayload) {
				t.Fatalf("payload drift from Go: got %#v want %#v", gotPayload, goPayload)
			}
			for key, want := range goEvent.Attributes {
				if key == "observed_at" {
					continue
				}
				if got := event.Attributes[key]; got != want {
					t.Errorf("attribute %s = %q, want %q", key, got, want)
				}
			}
			for _, key := range []string{"tenant_id", "source_event_id", idAttributeForParity(family.ID)} {
				if strings.TrimSpace(event.Attributes[key]) == "" {
					t.Errorf("required attribute %s is empty", key)
				}
			}
			if strings.Contains(string(event.Payload), "replay-token") {
				t.Fatal("credential value entered emitted payload")
			}
		})
	}
}

func TestCatalogRuntimeResumesCloudflareMemberPagesWithGoCursors(t *testing.T) {
	entry, ok, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil || !ok {
		t.Fatalf("BuiltinEntry(cloudflare) = ok %v error %v", ok, err)
	}
	pages := map[string]sourcefixture.Bundle{
		"1": capturedCloudflareBundle(t, "member", "list_members"),
		"2": capturedCloudflareBundle(t, "member", "list_members_page_2"),
		"3": capturedCloudflareBundle(t, "member", "list_members_page_3"),
	}
	requestPath := capturedCloudflareRequestPath(t, pages["1"])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != requestPath {
			t.Fatalf("path = %q, want %q", r.URL.EscapedPath(), requestPath)
		}
		page := r.URL.Query().Get("page")
		bundle, ok := pages[page]
		if !ok {
			t.Fatalf("page = %q, want 1, 2, or 3", page)
		}
		writeCapturedCloudflareResponse(w, bundle)
	}))
	defer server.Close()
	definition := entry.Definition
	definition.Transport.BaseURL = server.URL + "/client/v4"
	source, err := catalogruntime.NewDefinitionWithValidationOptions(definition, catalogruntime.ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	cfg := cloudflareParityConfig(server.URL, "member", map[string]string{
		"account_id": capturedCloudflarePathSegment(t, requestPath, 3),
	})
	var cursor *cerebrov1.SourceCursor
	for page := 1; page <= 3; page++ {
		pull, err := source.Read(context.Background(), cfg, cursor)
		if err != nil {
			t.Fatalf("Read(page %d) error = %v", page, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(page %d) events = %d, want 1", page, len(pull.Events))
		}
		if page < 3 {
			if got, want := pull.NextCursor.GetOpaque(), string(rune('1'+page)); got != want {
				t.Fatalf("Read(page %d) cursor = %q, want %q", page, got, want)
			}
		} else if pull.NextCursor != nil {
			t.Fatalf("Read(page 3) cursor = %#v, want terminal", pull.NextCursor)
		}
		cursor = pull.NextCursor
	}
}

func cloudflareParityConfig(baseURL, family string, attributes map[string]string) sourcecdk.Config {
	return capturedCloudflareConfig(baseURL, family, map[string]string{
		"account_id": firstNonEmptyForParity(attributes["account_id"], "account-1"),
		"zone_id":    firstNonEmptyForParity(attributes["zone_id"], "zone-1"),
		"per_page":   "100",
	})
}

func idAttributeForParity(familyID string) string {
	switch familyID {
	case "access_application", "zone_access_application":
		return "application_id"
	case "access_group", "zone_access_group":
		return "group_id"
	case "account":
		return "account_id"
	case "account_ruleset", "zone_ruleset":
		return "ruleset_id"
	case "audit_log":
		return "audit_id"
	case "member":
		return "member_id"
	case "gateway_rule":
		return "rule_id"
	case "load_balancer":
		return "load_balancer_id"
	case "load_balancer_pool":
		return "pool_id"
	case "role":
		return "role_id"
	case "worker_script":
		return "script_id"
	case "zone":
		return "zone_id"
	case "dns_record":
		return "record_id"
	default:
		return "id"
	}
}

func readCloudflareOracleEvent(t *testing.T, family string) cloudflareOracleEvent {
	t.Helper()
	payload, err := os.ReadFile("testdata/read_" + family + ".json") // #nosec G304 -- family is the closed checked-in catalog vocabulary.
	if err != nil {
		t.Fatalf("read Go oracle: %v", err)
	}
	var events []cloudflareOracleEvent
	if err := json.Unmarshal(payload, &events); err != nil {
		t.Fatalf("decode Go oracle: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("Go oracle has no events")
	}
	return events[0]
}

func firstNonEmptyForParity(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

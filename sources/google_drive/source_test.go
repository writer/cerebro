package google_drive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"gopkg.in/yaml.v3"
)

func TestCatalogDeclaresVerifiedGoogleDriveProviderAPI(t *testing.T) {
	payload, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var catalog struct {
		Description     string   `yaml:"description"`
		RuntimeFamilies []string `yaml:"runtime_families"`
		ProviderAPI     struct {
			Status     string   `yaml:"status"`
			Transport  string   `yaml:"transport"`
			Auth       string   `yaml:"auth"`
			BaseURL    string   `yaml:"base_url"`
			References []string `yaml:"references"`
			Families   []struct {
				ID     string `yaml:"id"`
				Method string `yaml:"method"`
				Path   string `yaml:"path"`
			} `yaml:"families"`
		} `yaml:"provider_api"`
	}
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}
	for _, text := range []string{"file metadata", "shared-drive metadata", "provider page token"} {
		if !strings.Contains(catalog.Description, text) {
			t.Fatalf("description = %q, want source-specific text %q", catalog.Description, text)
		}
	}
	assertStringSet(t, catalog.RuntimeFamilies, []string{familyFiles, familySharedDrives})
	if catalog.ProviderAPI.Status != "verified" || catalog.ProviderAPI.Transport != "rest" || catalog.ProviderAPI.Auth != "oauth_authorization_code" || catalog.ProviderAPI.BaseURL != defaultBaseURLTemplate {
		t.Fatalf("provider_api = %#v, want verified Drive REST OAuth API", catalog.ProviderAPI)
	}
	for _, ref := range []string{
		"https://raw.githubusercontent.com/googleapis/google-api-go-client/main/drive/v3/drive-api.json",
		"https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list",
		"https://developers.google.com/workspace/drive/api/reference/rest/v3/drives/list",
		"https://developers.google.com/workspace/drive/api/reference/rest/v3/changes/list",
	} {
		if !hasString(catalog.ProviderAPI.References, ref) {
			t.Fatalf("provider references = %v, want %s", catalog.ProviderAPI.References, ref)
		}
	}
	wantPaths := map[string]string{
		familyFiles:        "/files",
		familySharedDrives: "/drives",
		familyChanges:      "/changes",
	}
	gotPaths := map[string]string{}
	for _, family := range catalog.ProviderAPI.Families {
		if family.Method != http.MethodGet {
			t.Fatalf("provider family %s method = %q, want GET", family.ID, family.Method)
		}
		gotPaths[family.ID] = family.Path
	}
	for family, want := range wantPaths {
		if got := gotPaths[family]; got != want {
			t.Fatalf("provider path for %s = %q, want %q", family, got, want)
		}
	}
}

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/about?fields=user" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/files" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{{"id": "record-1", "resource_urn": "urn:cerebro:tenant:runtime_asset:record-1", "resource_type": "asset", "resource_id": "record-1", "name": "Record One", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
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
	if event.Kind != "google_drive.files" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestSourceReadsSharedDrives(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RequestURI() == "/about?fields=user" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/drives" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"drives": []map[string]string{{"id": "drive-1", "resource_urn": "urn:cerebro:tenant:runtime_shared_drive:drive-1", "resource_type": "shared_drive", "resource_id": "drive-1", "name": "Security", "updated_at": "2026-06-01T00:00:00Z"}}})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familySharedDrives, "token": "test-token"})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(shared_drives) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Kind; got != "google_drive.shared_drives" {
		t.Fatalf("kind = %q, want google_drive.shared_drives", got)
	}
}

func TestNewFixtureReplaysGoogleDriveFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyChanges, familyFiles, familySharedDrives} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family string
		kind   string
		want   string
	}{
		{family: familyChanges, kind: "google_drive.changes", want: "source-google_drive-changes-1"},
		{family: familyFiles, kind: "google_drive.files", want: "source-google_drive-files-1"},
		{family: familySharedDrives, kind: "google_drive.shared_drives", want: "source-google_drive-shared_drives-1"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if got := event.Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := event.Attributes["source_event_id"]; got != tt.want {
				t.Fatalf("source_event_id = %q, want %q", got, tt.want)
			}
		})
	}
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("strings = %v, want %v", got, want)
	}
	for _, value := range want {
		if !hasString(got, value) {
			t.Fatalf("strings = %v, want %q", got, value)
		}
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

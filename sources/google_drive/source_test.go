package google_drive

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func TestSourceCheckAndReadRuntimeFamilies(t *testing.T) {
	tests := []struct {
		family        string
		path          string
		responseKey   string
		record        map[string]any
		wantKind      string
		wantURN       string
		wantAttribute string
		wantValue     string
	}{
		{
			family:      familyFiles,
			path:        "/files",
			responseKey: "files",
			record: map[string]any{
				"kind":         "drive#file",
				"id":           "1AbCdEfGhIjKlMnOpQrStUvWxYz",
				"name":         "Risk Register",
				"mimeType":     "application/vnd.google-apps.spreadsheet",
				"modifiedTime": "2026-06-29T18:12:44Z",
				"createdTime":  "2026-06-20T09:10:00Z",
			},
			wantKind:      "google_drive.files",
			wantURN:       "urn:cerebro:tenant:google_drive_files:1AbCdEfGhIjKlMnOpQrStUvWxYz",
			wantAttribute: "resource_type",
			wantValue:     "application/vnd.google-apps.spreadsheet",
		},
		{
			family:      familySharedDrives,
			path:        "/drives",
			responseKey: "drives",
			record: map[string]any{
				"kind":        "drive#drive",
				"id":          "0AExampleSharedDrive",
				"name":        "Security Evidence",
				"createdTime": "2026-06-20T10:05:00Z",
				"restrictions": map[string]any{
					"driveMembersOnly": true,
					"domainUsersOnly":  true,
				},
			},
			wantKind:      "google_drive.shared_drives",
			wantURN:       "urn:cerebro:tenant:google_drive_shared_drives:0AExampleSharedDrive",
			wantAttribute: "resource_type",
			wantValue:     "shared_drive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
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
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				if got := r.URL.Query().Get("pageSize"); got == "" {
					t.Fatalf("pageSize query is empty")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"kind":          "drive#list",
					"nextPageToken": "page-2",
					tt.responseKey:  []map[string]any{tt.record},
				})
			}))
			defer server.Close()

			cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": tt.family, "token": "test-token", "per_page": "25"})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.wantKind)
			}
			if strings.TrimSpace(event.Id) == "" {
				t.Fatalf("event id is empty: %#v", event)
			}
			if got := event.Attributes["resource_urn"]; got != tt.wantURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantURN)
			}
			if got := event.Attributes[tt.wantAttribute]; got != tt.wantValue {
				t.Fatalf("%s = %q, want %q", tt.wantAttribute, got, tt.wantValue)
			}
			if got := sourcecdk.CursorToken(pull.NextCursor); got != "page-2" {
				t.Fatalf("NextCursor = %q, want page-2", got)
			}
		})
	}
}

func TestSourceReadsChangesWithProviderPageToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/changes" {
			t.Fatalf("path = %q, want /changes", r.URL.Path)
		}
		if got := r.URL.Query().Get("pageToken"); got != "start-token" {
			t.Fatalf("pageToken = %q, want start-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"kind":              "drive#changeList",
			"newStartPageToken": "new-start-token",
			"changes": []map[string]any{{
				"kind":       "drive#change",
				"fileId":     "1AbCdEfGhIjKlMnOpQrStUvWxYz",
				"time":       "2026-06-29T18:12:44Z",
				"type":       "file",
				"changeType": "file",
				"file": map[string]any{
					"kind":     "drive#file",
					"id":       "1AbCdEfGhIjKlMnOpQrStUvWxYz",
					"name":     "Risk Register",
					"mimeType": "application/vnd.google-apps.spreadsheet",
				},
			}},
		})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyChanges, "token": "test-token", "per_page": "25"})
	pull, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "start-token"})
	if err != nil {
		t.Fatalf("Read(changes) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Kind; got != "google_drive.changes" {
		t.Fatalf("kind = %q, want google_drive.changes", got)
	}
	if got := event.Attributes["event_type"]; got != "file" {
		t.Fatalf("event_type = %q, want file", got)
	}
	if got := event.Attributes["resource_id"]; got != "1AbCdEfGhIjKlMnOpQrStUvWxYz" {
		t.Fatalf("resource_id = %q, want file ID", got)
	}
}

func TestSourceCheckReportsProviderUnavailable(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": familyFiles, "token": "test-token"})
	err = source.Check(context.Background(), cfg)
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable failure")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Check() error = %v, want provider unavailable status", err)
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
		{family: familyChanges, kind: "google_drive.changes", want: "1AbCdEfGhIjKlMnOpQrStUvWxYz"},
		{family: familyFiles, kind: "google_drive.files", want: "1AbCdEfGhIjKlMnOpQrStUvWxYz"},
		{family: familySharedDrives, kind: "google_drive.shared_drives", want: "0AExampleSharedDrive"},
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

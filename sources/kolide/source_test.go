package kolide

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceSpec(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "kolide" {
		t.Fatalf("Spec().Id = %q, want kolide", source.Spec().Id)
	}
	if source.Spec().Name != "Kolide" {
		t.Fatalf("Spec().Name = %q, want Kolide", source.Spec().Name)
	}
}

func TestSourceSpecNilSafe(t *testing.T) {
	var source *Source
	if got := source.Spec(); got != nil {
		t.Fatalf("nil Source Spec() = %#v, want nil", got)
	}
	if got := (&Source{}).Spec(); got != nil {
		t.Fatalf("zero Source Spec() = %#v, want nil", got)
	}
}

func TestDefaultBaseURLUsesCurrentAPI(t *testing.T) {
	if strings.Contains(defaultBaseURL, "/api/v0") {
		t.Fatalf("defaultBaseURL = %q, want non-deprecated Kolide API", defaultBaseURL)
	}
	if defaultBaseURL != "https://api.kolide.com" {
		t.Fatalf("defaultBaseURL = %q, want current Kolide API origin", defaultBaseURL)
	}
}

func TestSourceCheckAndReadFamilies(t *testing.T) {
	tests := []struct {
		family string
		path   string
		kind   string
		record map[string]any
		attrs  map[string]string
	}{
		{
			family: familyDevice,
			path:   "/devices",
			kind:   "kolide.device",
			record: map[string]any{
				"id":                    "device_01",
				"name":                  "ENG-MBA-01",
				"registered_at":         "2026-05-01T12:00:00Z",
				"last_authenticated_at": "2026-05-29T17:05:00Z",
				"last_seen_at":          "2026-05-30T08:30:00Z",
				"registered_owner_info": map[string]any{
					"identifier": "person_01",
					"location":   "https://api.kolide.com/people/person_01",
				},
				"operating_system": "macOS 15.5",
				"hardware_model":   "MacBook Pro",
				"serial":           "C02KOLIDE001",
				"hardware_uuid":    "E7C0B9B1-8E76-4D24-A423-589A2B035C12",
				"auth_state":       "Good",
				"auth_configuration": map[string]any{
					"device_id":           "device_01",
					"authentication_mode": "only_registered_owner",
				},
				"device_type": "Mac",
				"form_factor": "Computer",
			},
			attrs: map[string]string{
				"device_id":           "device_01",
				"device_name":         "ENG-MBA-01",
				"serial_number":       "C02KOLIDE001",
				"os":                  "macOS 15.5",
				"auth_state":          "Good",
				"authentication_mode": "only_registered_owner",
				"registered_at":       "2026-05-01T12:00:00Z",
			},
		},
		{
			family: familyCheck,
			path:   "/checks",
			kind:   "kolide.check",
			record: map[string]any{
				"id":                        "check_01",
				"name":                      "Disk encryption is enabled",
				"slug":                      "disk-encryption-enabled",
				"compatible_platforms":      []any{"darwin"},
				"description":               "Requires FileVault on macOS devices.",
				"issue_title":               "Enable disk encryption",
				"fix_instructions_template": "Turn on FileVault.",
				"rationale_template":        "Disk encryption protects local data.",
				"blocks_auth_configuration": map[string]any{
					"blocking_enabled":  true,
					"grace_period_days": 3,
				},
				"percent_passing": 96,
				"kolide_provided": true,
				"type":            "osquery",
			},
			attrs: map[string]string{
				"check_id":         "check_01",
				"slug":             "disk-encryption-enabled",
				"title":            "Enable disk encryption",
				"remediation":      "Turn on FileVault.",
				"blocking_enabled": "true",
				"percent_passing":  "96",
			},
		},
		{
			family: familyIssue,
			path:   "/issues",
			kind:   "kolide.issue",
			record: map[string]any{
				"id":                "issue_01",
				"issue_key":         "volume",
				"issue_value":       "Macintosh HD",
				"title":             "Disk encryption disabled",
				"value":             map[string]any{"encrypted": false},
				"exempted":          false,
				"resolved_at":       nil,
				"detected_at":       "2026-05-20T14:00:00Z",
				"blocks_device_at":  "2026-05-27T14:00:00Z",
				"last_rechecked_at": "2026-05-21T09:15:00Z",
				"device_information": map[string]any{
					"identifier": "device_01",
					"location":   "https://api.kolide.com/devices/device_01",
				},
				"check_information": map[string]any{
					"identifier": "check_01",
					"location":   "https://api.kolide.com/checks/check_01",
				},
			},
			attrs: map[string]string{
				"issue_id":         "issue_01",
				"issue_key":        "volume",
				"issue_value":      "Macintosh HD",
				"device_id":        "device_01",
				"check_id":         "check_01",
				"check_url":        "https://api.kolide.com/checks/check_01",
				"blocks_device_at": "2026-05-27T14:00:00Z",
			},
		},
		{
			family: familySoftware,
			path:   "/packages",
			kind:   "kolide.software",
			record: map[string]any{
				"id":       "package_01",
				"url":      "https://api.kolide.com/packages/package_01",
				"version":  "1.12.3",
				"built_at": "2026-05-15T18:45:00Z",
			},
			attrs: map[string]string{
				"software_id":       "package_01",
				"package_id":        "package_01",
				"package_name":      "package_01",
				"installed_version": "1.12.3",
				"download_url":      "https://api.kolide.com/packages/package_01",
				"built_at":          "2026-05-15T18:45:00Z",
			},
		},
		{
			family: familyUserDevice,
			path:   "/devices",
			kind:   "kolide.user_device",
			record: map[string]any{
				"id":                    "device_02",
				"name":                  "ENG-WIN-02",
				"registered_at":         "2026-05-04T10:00:00Z",
				"last_authenticated_at": "2026-05-28T11:20:00Z",
				"last_seen_at":          "2026-05-28T11:45:00Z",
				"registered_owner_info": map[string]any{
					"identifier": "person_02",
					"location":   "https://api.kolide.com/people/person_02",
				},
				"serial":        "PF4KOLIDE002",
				"hardware_uuid": "B6124D09-BD62-4638-B228-184F7C6C8D99",
				"device_type":   "Windows",
			},
			attrs: map[string]string{
				"device_id":   "device_02",
				"device_name": "ENG-WIN-02",
				"owner_id":    "person_02",
				"owner_url":   "https://api.kolide.com/people/person_02",
			},
		},
		{
			family: familyVulnerability,
			path:   "/issues",
			kind:   "kolide.vulnerability",
			record: map[string]any{
				"id":                "issue_vuln_01",
				"issue_key":         "cve",
				"issue_value":       "CVE-2026-0001",
				"title":             "OpenSSL package has a vulnerable version",
				"detected_at":       "2026-05-25T10:00:00Z",
				"last_rechecked_at": "2026-05-25T12:00:00Z",
				"device_information": map[string]any{
					"identifier": "device_01",
					"location":   "https://api.kolide.com/devices/device_01",
				},
				"check_information": map[string]any{
					"identifier": "check_vulnerability_01",
					"location":   "https://api.kolide.com/checks/check_vulnerability_01",
				},
				"value": map[string]any{
					"cve_id":            "CVE-2026-0001",
					"package_name":      "openssl",
					"installed_version": "3.0.1",
					"fixed_version":     "3.0.2",
					"severity":          "high",
					"remediation":       "Update OpenSSL to 3.0.2 or later.",
				},
			},
			attrs: map[string]string{
				"vulnerability_id":  "issue_vuln_01",
				"cve_id":            "CVE-2026-0001",
				"device_id":         "device_01",
				"package_name":      "openssl",
				"installed_version": "3.0.1",
				"fixed_version":     "3.0.2",
				"severity":          "high",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.URL.Path != tt.path {
					t.Errorf("request path = %q, want %s", r.URL.Path, tt.path)
					http.Error(w, "unexpected path", http.StatusInternalServerError)
					return
				}
				if got := r.URL.Query().Get("per_page"); got == "" {
					t.Errorf("per_page query is empty")
					http.Error(w, "missing per_page", http.StatusInternalServerError)
					return
				}
				if got := r.URL.Query().Get("limit"); got != "" {
					t.Errorf("limit query = %q, want Kolide per_page only", got)
					http.Error(w, "unexpected limit", http.StatusInternalServerError)
					return
				}
				if got := r.Header.Get("Authorization"); got != "Bearer kolide-token" {
					t.Errorf("Authorization = %q, want Bearer kolide-token", got)
					http.Error(w, "unexpected auth", http.StatusInternalServerError)
					return
				}
				if got := r.Header.Get("X-Kolide-Api-Version"); got != defaultAPIVersion {
					t.Errorf("X-Kolide-Api-Version = %q, want %s", got, defaultAPIVersion)
					http.Error(w, "unexpected api version", http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data":       []map[string]any{tt.record},
					"pagination": map[string]any{"current_cursor": "", "next_cursor": "", "count": 1},
				})
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
				"token":     "kolide-token",
				"family":    tt.family,
				"per_page":  "100",
			})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			urns, err := source.Discover(context.Background(), cfg)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(urns) != 1 {
				t.Fatalf("len(URNs) = %d, want 1", len(urns))
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %s", event.Kind, tt.kind)
			}
			for key, want := range tt.attrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("%s attribute %q = %q, want %q", tt.family, key, got, want)
				}
			}
			if tt.family == familyDevice && event.Attributes["status"] != "" {
				t.Fatalf("device status = %q, want empty when provider only returns auth_state", event.Attributes["status"])
			}
			if tt.family == familyDevice && event.Attributes["compliance_status"] != "" {
				t.Fatalf("device compliance_status = %q, want empty when provider only returns auth_state", event.Attributes["compliance_status"])
			}
			if requests != 3 {
				t.Fatalf("requests = %d, want Check, Discover, and Read", requests)
			}
		})
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "This feature has been disabled by your organization",
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"token":     "kolide-token",
		"family":    familyDevice,
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider unavailable error")
	}
	var statusErr interface {
		StatusCode() int
	}
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("Read() error = %v, want provider status 401", err)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyCheck,
		familyDevice,
		familyIssue,
		familySoftware,
		familyUserDevice,
		familyVulnerability,
	} {
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
}

func TestReadDeviceFamilyFromFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/device.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/devices" {
			t.Errorf("request path = %q, want /devices", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(fixture)
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
		"token":     "kolide-token",
		"family":    "device",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kolide.device" {
		t.Fatalf("Kind = %q, want kolide.device", event.Kind)
	}
	if event.Attributes["device_name"] != "ENG-MBA-01" || event.Attributes["serial_number"] != "C02KOLIDE001" {
		t.Fatalf("attrs = %#v, want fixture device name/serial", event.Attributes)
	}
	if got := event.Attributes["registered_at"]; got != "2026-05-01T12:00:00Z" {
		t.Fatalf("registered_at = %q, want fixture timestamp", got)
	}
	if got := event.Attributes["registered"]; got != "" {
		t.Fatalf("registered = %q, want empty when provider omits boolean registration state", got)
	}
}

func TestReadDeviceFamilyEmitsHostPostureAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/devices" {
			t.Errorf("request path = %q, want /devices", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":            "device-1",
				"name":          "mba-1",
				"serial_number": "SERIAL1",
				"failure_count": 3,
				"registered":    true,
				"registered_at": "2026-05-01T12:00:00Z",
				"resolved_at":   nil,
			}},
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
		"token":     "kolide-token",
		"family":    "device",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["device_id"] != "device-1" {
		t.Fatalf("device_id = %q, want device-1", attrs["device_id"])
	}
	if attrs["failure_count"] != "3" {
		t.Fatalf("failure_count = %q, want 3", attrs["failure_count"])
	}
	if attrs["registered"] != "true" {
		t.Fatalf("registered = %q, want true", attrs["registered"])
	}
	if attrs["registered_at"] != "2026-05-01T12:00:00Z" {
		t.Fatalf("registered_at = %q, want 2026-05-01T12:00:00Z", attrs["registered_at"])
	}
}

func TestReadDeviceFamilyPrefersOSNameOverStructuredOS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/devices" {
			t.Errorf("request path = %q, want /devices", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id": "device-1",
				"os": map[string]any{
					"name":    "macOS",
					"version": "15.5",
				},
			}},
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
		"token":     "kolide-token",
		"family":    "device",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := pull.Events[0].Attributes["os"]; got != "macOS" {
		t.Fatalf("os = %q, want os.name scalar", got)
	}
	if got := pull.Events[0].Attributes["os_version"]; got != "15.5" {
		t.Fatalf("os_version = %q, want os.version", got)
	}
}

func TestReadDeviceFamiliesPreserveUpdatedAtOccurredAtPrecedence(t *testing.T) {
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: familyDevice, kind: "kolide.device"},
		{family: familyUserDevice, kind: "kolide.user_device"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/devices" {
					t.Errorf("request path = %q, want /devices", r.URL.Path)
					http.Error(w, "unexpected path", http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": []map[string]any{{
						"id":                    "device-1",
						"updated_at":            "2026-05-01T12:00:00Z",
						"last_seen_at":          "2026-05-30T08:30:00Z",
						"last_authenticated_at": "2026-05-29T17:05:00Z",
						"registered_at":         "2026-05-01T12:00:00Z",
					}},
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
				"token":     "kolide-token",
				"family":    tt.family,
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Kind = %q, want %s", got, tt.kind)
			}
			want := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			if got := pull.Events[0].OccurredAt.AsTime(); !got.Equal(want) {
				t.Fatalf("OccurredAt = %s, want updated_at %s", got, want)
			}
		})
	}
}

func TestReadSoftwareFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/packages" {
			t.Errorf("request path = %q, want /packages", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer kolide-token" {
			t.Errorf("Authorization = %q, want Bearer kolide-token", got)
			http.Error(w, "unexpected auth", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":         "software-1",
					"device_id":  "device-1",
					"name":       "openssl",
					"version":    "3.0.1",
					"purl":       "pkg:generic/openssl@3.0.1",
					"updated_at": "2026-05-01T12:00:00Z",
					"user": map[string]any{
						"email": "alice@example.com",
					},
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
		"token":     "kolide-token",
		"family":    "software",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kolide.software" {
		t.Fatalf("Kind = %q, want kolide.software", event.Kind)
	}
	if event.Attributes["device_id"] != "device-1" {
		t.Fatalf("device_id = %q, want device-1", event.Attributes["device_id"])
	}
	if event.Attributes["package_name"] != "openssl" || event.Attributes["installed_version"] != "3.0.1" {
		t.Fatalf("attrs = %#v, want package name/version", event.Attributes)
	}
	if event.Attributes["source_product"] != "kolide" {
		t.Fatalf("source_product = %q, want kolide", event.Attributes["source_product"])
	}
}

func TestReadSoftwareFamilyKeepsSamePackageOnDifferentDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/packages" {
			t.Errorf("request path = %q, want /packages", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"device_id": "device-1",
					"name":      "openssl",
					"version":   "3.0.1",
				},
				{
					"device_id": "device-2",
					"name":      "openssl",
					"version":   "3.0.1",
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
		"token":     "kolide-token",
		"family":    "software",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want both device package rows", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs are equal %q, want per-row identities", pull.Events[0].Id)
	}
	if pull.Events[0].Attributes["external_id"] == pull.Events[1].Attributes["external_id"] {
		t.Fatalf("external_id values are equal %q, want per-row fallback identities", pull.Events[0].Attributes["external_id"])
	}
}

func TestReadVulnerabilityFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issues" {
			t.Errorf("request path = %q, want /issues", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":                "finding-1",
					"cve_id":            "CVE-2026-0001",
					"severity":          "high",
					"device_id":         "device-1",
					"package_name":      "openssl",
					"installed_version": "3.0.1",
					"fixed_version":     "3.0.2",
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
		"token":     "kolide-token",
		"family":    "vulnerability",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kolide.vulnerability" {
		t.Fatalf("Kind = %q, want kolide.vulnerability", pull.Events[0].Kind)
	}
	if attrs["cve_id"] != "CVE-2026-0001" || attrs["package_name"] != "openssl" || attrs["fixed_version"] != "3.0.2" {
		t.Fatalf("attrs = %#v, want CVE/package/remediation attributes", attrs)
	}
}

func TestReadVulnerabilityFamilyFiltersComplianceIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issues" {
			t.Errorf("request path = %q, want /issues", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":          "issue-compliance-1",
					"issue_key":   "volume",
					"issue_value": "Macintosh HD",
					"title":       "Disk encryption disabled",
					"value":       map[string]any{"encrypted": false},
				},
				{
					"id":          "issue-vuln-1",
					"issue_key":   "cve",
					"issue_value": "CVE-2026-0001",
					"title":       "OpenSSL package has a vulnerable version",
					"value": map[string]any{
						"cve_id":            "CVE-2026-0001",
						"package_name":      "openssl",
						"installed_version": "3.0.1",
						"fixed_version":     "3.0.2",
						"severity":          "high",
					},
				},
				{
					"id":          "issue-vuln-2",
					"issue_key":   "advisory",
					"issue_value": "KOLIDE-2026-0002",
					"title":       "Vendor advisory affects installed package",
					"value": map[string]any{
						"advisory_id":       "KOLIDE-2026-0002",
						"package_name":      "kolide-agent",
						"installed_version": "1.2.3",
						"fixed_version":     "1.2.4",
						"severity":          "medium",
					},
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
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL,
		"token":     "kolide-token",
		"family":    "vulnerability",
	})
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 2 ||
		urns[0].String() != "urn:cerebro:writer:kolide_vulnerability:issue-vuln-1" ||
		urns[1].String() != "urn:cerebro:writer:kolide_vulnerability:issue-vuln-2" {
		t.Fatalf("URNs = %#v, want only vulnerability issue URNs", urns)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want only vulnerability issues", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["vulnerability_id"] != "issue-vuln-1" || attrs["cve_id"] != "CVE-2026-0001" {
		t.Fatalf("attrs = %#v, want vulnerability issue attributes", attrs)
	}
	if attrs["package_name"] != "openssl" || attrs["fixed_version"] != "3.0.2" {
		t.Fatalf("attrs = %#v, want package fix details from vulnerability value", attrs)
	}
	attrs = pull.Events[1].Attributes
	if attrs["vulnerability_id"] != "issue-vuln-2" || attrs["advisory_id"] != "KOLIDE-2026-0002" {
		t.Fatalf("attrs = %#v, want advisory vulnerability attributes", attrs)
	}
	if attrs["package_name"] != "kolide-agent" || attrs["fixed_version"] != "1.2.4" {
		t.Fatalf("attrs = %#v, want advisory package fix details", attrs)
	}
}

func TestReadIssueFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issues" {
			t.Errorf("request path = %q, want /issues", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":                 "issue-1",
					"title":              "Disk encryption disabled",
					"issue_key":          "volume",
					"issue_value":        "Macintosh HD",
					"resolved_at":        nil,
					"detected_at":        "2026-05-01T12:00:00Z",
					"last_rechecked_at":  "2026-05-01T13:00:00Z",
					"blocks_device_at":   "2026-05-02T12:00:00Z",
					"exempted":           false,
					"device_information": map[string]any{"identifier": "device-1", "name": "Writer MacBook", "hostname": "writer-mbp.local", "serial_number": "SERIAL1", "location": "https://api.kolide.com/devices/device-1"},
					"check_information":  map[string]any{"identifier": "check-1", "location": "https://api.kolide.com/checks/check-1"},
					"value":              map[string]any{"encrypted": false},
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
		"token":     "kolide-token",
		"family":    "issue",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kolide.issue" {
		t.Fatalf("Kind = %q, want kolide.issue", pull.Events[0].Kind)
	}
	for key, want := range map[string]string{
		"issue_id":         "issue-1",
		"device_id":        "device-1",
		"device_name":      "Writer MacBook",
		"hostname":         "writer-mbp.local",
		"serial_number":    "SERIAL1",
		"check_id":         "check-1",
		"title":            "Disk encryption disabled",
		"exempted":         "false",
		"blocks_device_at": "2026-05-02T12:00:00Z",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("issue attribute %q = %q, want %q", key, got, want)
		}
	}
	if attrs["resolved_at"] != "" {
		t.Fatalf("resolved_at = %q, want omitted for open issue", attrs["resolved_at"])
	}
}

func TestReadIssueFamilyDoesNotUseBlockDeadlineAsOccurredAt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issues" {
			t.Errorf("request path = %q, want /issues", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":                 "issue-1",
				"title":              "Disk encryption disabled",
				"blocks_device_at":   "2099-05-02T12:00:00Z",
				"device_information": map[string]any{"identifier": "device-1"},
				"check_information":  map[string]any{"identifier": "check-1"},
			}},
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
		"token":     "kolide-token",
		"family":    "issue",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	if pull.Events[0].Attributes["blocks_device_at"] != "2099-05-02T12:00:00Z" {
		t.Fatalf("blocks_device_at attribute = %q, want preserved deadline", pull.Events[0].Attributes["blocks_device_at"])
	}
	deadline := time.Date(2099, 5, 2, 12, 0, 0, 0, time.UTC)
	if pull.Events[0].OccurredAt == nil {
		t.Fatal("OccurredAt is nil, want source runtime fallback timestamp")
	}
	if got := pull.Events[0].OccurredAt.AsTime(); !got.Before(deadline) {
		t.Fatalf("OccurredAt = %s, want ingest fallback before block deadline %s", got, deadline)
	}
}

func TestReadCheckFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checks" {
			t.Errorf("request path = %q, want /checks", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":        "check-1",
					"slug":      "disk-encrypted",
					"title":     "Disk encryption enabled",
					"status":    "passing",
					"device_id": "device-1",
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
		"token":     "kolide-token",
		"family":    "check",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kolide.check" {
		t.Fatalf("Kind = %q, want kolide.check", pull.Events[0].Kind)
	}
	if attrs["check_id"] != "check-1" || attrs["title"] != "Disk encryption enabled" {
		t.Fatalf("attrs = %#v, want check attributes", attrs)
	}
}

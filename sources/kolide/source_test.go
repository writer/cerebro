package kolide

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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

func TestDefaultBaseURLUsesCurrentAPI(t *testing.T) {
	if strings.Contains(defaultBaseURL, "/api/v0") {
		t.Fatalf("defaultBaseURL = %q, want non-deprecated Kolide API", defaultBaseURL)
	}
	if defaultBaseURL != "https://api.kolide.com" {
		t.Fatalf("defaultBaseURL = %q, want current Kolide API origin", defaultBaseURL)
	}
}

func TestReadDeviceFamilyFromFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/device.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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
	if event.Attributes["hostname"] != "mba-1.writer.test" || event.Attributes["owner_email"] != "alice@writer.com" {
		t.Fatalf("attrs = %#v, want fixture hostname/owner", event.Attributes)
	}
}

func TestReadDeviceFamilyEmitsHostPostureAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":            "device-1",
				"name":          "mba-1",
				"serial_number": "SERIAL1",
				"failure_count": 3,
				"registered":    true,
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
		"base_url":  server.URL + "/api/v1",
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
}

func TestReadDeviceFamilyPrefersOSNameOverStructuredOS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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

func TestReadSoftwareFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/packages" {
			t.Fatalf("request path = %q, want /api/v1/packages", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer kolide-token" {
			t.Fatalf("Authorization = %q, want Bearer kolide-token", got)
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
		"base_url":  server.URL + "/api/v1",
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
		if r.URL.Path != "/api/v1/packages" {
			t.Fatalf("request path = %q, want /api/v1/packages", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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
		if r.URL.Path != "/api/v1/issues" {
			t.Fatalf("request path = %q, want /api/v1/issues", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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

func TestReadIssueFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/issues" {
			t.Fatalf("request path = %q, want /api/v1/issues", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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

func TestReadCheckFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/checks" {
			t.Fatalf("request path = %q, want /api/v1/checks", r.URL.Path)
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
		"base_url":  server.URL + "/api/v1",
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

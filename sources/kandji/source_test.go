package kandji

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceSpec(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "kandji" {
		t.Fatalf("Spec().Id = %q, want kandji", source.Spec().Id)
	}
	if source.Spec().Name != "Kandji / Iru" {
		t.Fatalf("Spec().Name = %q, want Kandji / Iru", source.Spec().Name)
	}
}

func TestReadDeviceFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer kandji-token" {
			t.Fatalf("Authorization = %q, want Bearer kandji-token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"device_id":     "device-1",
					"device_name":   "MacBook Pro",
					"serial_number": "SERIAL1",
					"platform":      "macOS",
					"os_version":    "15.0",
					"last_check_in": "2026-05-01T12:00:00Z",
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
		"token":     "kandji-token",
		"family":    "device",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "kandji.device" {
		t.Fatalf("Kind = %q, want kandji.device", event.Kind)
	}
	if event.Attributes["device_id"] != "device-1" {
		t.Fatalf("device_id = %q, want device-1", event.Attributes["device_id"])
	}
	if event.Attributes["owner_email"] != "alice@example.com" {
		t.Fatalf("owner_email = %q, want alice@example.com", event.Attributes["owner_email"])
	}
	if event.Attributes["source_product"] != "kandji" {
		t.Fatalf("source_product = %q, want kandji", event.Attributes["source_product"])
	}
}

func TestReadDeviceFamilyEmitsPostureAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices" {
			t.Fatalf("request path = %q, want /api/v1/devices", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"device_id":         "device-9",
					"device_name":       "MacBook Air",
					"serial_number":     "SERIAL9",
					"platform":          "macOS",
					"mdm_enabled":       true,
					"filevault_enabled": false,
					"is_missing":        false,
					"compliance_status": "non_compliant",
					"mdm_status":        "enrolled",
					"last_check_in":     "2026-05-01T12:00:00Z",
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
		"token":     "kandji-token",
		"family":    "device",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kandji.device" {
		t.Fatalf("Kind = %q, want kandji.device", pull.Events[0].Kind)
	}
	if attrs["device_id"] != "device-9" {
		t.Fatalf("device_id = %q, want device-9 (stable asset identity)", attrs["device_id"])
	}
	for key, want := range map[string]string{
		"mdm_enabled":       "true",
		"filevault_enabled": "false",
		"is_missing":        "false",
		"compliance_status": "non_compliant",
		"status":            "enrolled",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("posture attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestReadApplicationFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/prism/apps" {
			t.Fatalf("request path = %q, want /api/v1/prism/apps", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":            "app-1",
					"device_id":     "device-1",
					"name":          "Safari",
					"bundle_id":     "com.apple.Safari",
					"version":       "18.0",
					"publisher":     "Apple",
					"last_seen_at":  "2026-05-01T12:00:00Z",
					"serial_number": "SERIAL1",
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
		"token":     "kandji-token",
		"family":    "application",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kandji.application" {
		t.Fatalf("Kind = %q, want kandji.application", pull.Events[0].Kind)
	}
	if attrs["application_name"] != "Safari" || attrs["bundle_identifier"] != "com.apple.Safari" || attrs["installed_version"] != "18.0" {
		t.Fatalf("attrs = %#v, want app inventory attributes", attrs)
	}
}

func TestReadVulnerabilityFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/vulnerability-management/detections" {
			t.Fatalf("request path = %q, want /api/v1/vulnerability-management/detections", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"id":                "finding-1",
					"cve_id":            "CVE-2026-0001",
					"severity":          "high",
					"device_id":         "device-1",
					"installed_version": "1.0.0",
					"fixed_version":     "1.0.1",
					"app": map[string]any{
						"name": "Safari",
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
		"token":     "kandji-token",
		"family":    "vulnerability",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if pull.Events[0].Kind != "kandji.vulnerability" {
		t.Fatalf("Kind = %q, want kandji.vulnerability", pull.Events[0].Kind)
	}
	if attrs["cve_id"] != "CVE-2026-0001" || attrs["application_name"] != "Safari" {
		t.Fatalf("attrs = %#v, want CVE/application attributes", attrs)
	}
}

func TestReadVulnerabilityFamilyKeepsSameCVEOnDifferentDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/vulnerability-management/detections" {
			t.Fatalf("request path = %q, want /api/v1/vulnerability-management/detections", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"cve_id":            "CVE-2026-0001",
					"device_id":         "device-1",
					"installed_version": "1.0.0",
					"app": map[string]any{
						"name": "Safari",
					},
				},
				{
					"cve_id":            "CVE-2026-0001",
					"device_id":         "device-2",
					"installed_version": "1.0.0",
					"app": map[string]any{
						"name": "Safari",
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
		"token":     "kandji-token",
		"family":    "vulnerability",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want both device vulnerability rows", len(pull.Events))
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("event IDs are equal %q, want per-row identities", pull.Events[0].Id)
	}
	if pull.Events[0].Attributes["external_id"] == pull.Events[1].Attributes["external_id"] {
		t.Fatalf("external_id values are equal %q, want per-row fallback identities", pull.Events[0].Attributes["external_id"])
	}
}

package kandji

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		switch r.URL.Path {
		case "/api/v1/devices":
			if got := r.Header.Get("Authorization"); got != "Bearer kandji-token" {
				t.Errorf("Authorization = %q, want Bearer kandji-token", got)
				http.Error(w, "unexpected auth", http.StatusInternalServerError)
				return
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
		case "/api/v1/devices/device-1/details":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"general": map[string]any{"device_id": "device-1"},
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
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
	for key, want := range map[string]string{
		"resource_id":   "device-1",
		"resource_name": "MacBook Pro",
		"resource_type": "device",
		"resource_urn":  "urn:cerebro:writer:kandji_device:device-1",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadDeviceFamilyEmitsPostureAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/devices":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{
						"device_id":         "device-9",
						"device_name":       "MacBook Air",
						"serial_number":     "SERIAL9",
						"platform":          "macOS",
						"is_missing":        false,
						"compliance_status": "non_compliant",
						"mdm_status":        "enrolled",
						"last_check_in":     "2026-05-01T12:00:00Z",
					},
				},
			})
		case "/api/v1/devices/device-9/details":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"general": map[string]any{
					"device_id":      "device-9",
					"device_name":    "MacBook Air",
					"blueprint_name": "Engineering Macs",
					"assigned_user":  map[string]any{"email": "alice@example.com"},
				},
				"mdm":       map[string]any{"mdm_enabled": "True"},
				"filevault": map[string]any{"filevault_enabled": false},
				"kandji_agent": map[string]any{
					"is_agent_installed":     true,
					"last_check_in_datetime": "2026-05-01T12:10:00Z",
				},
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
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
		"mdm_enabled":       "True",
		"filevault_enabled": "false",
		"is_missing":        "false",
		"compliance_status": "non_compliant",
		"status":            "enrolled",
		"blueprint_name":    "Engineering Macs",
		"owner_email":       "alice@example.com",
		"agent_installed":   "true",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("posture attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestReadApplicationFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/prism/apps" {
			t.Errorf("request path = %q, want /api/v1/prism/apps", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"device_id":          "device-1",
					"device__name":       "MacBook Pro",
					"device__family":     "Mac",
					"device__user_email": "alice@example.com",
					"name":               "Safari",
					"bundle_id":          "com.apple.Safari",
					"version":            "18.0",
					"developer_name":     "Apple",
					"last_collected_at":  "2026-05-01T12:00:00Z",
					"serial_number":      "SERIAL1",
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
	if attrs["device_name"] != "MacBook Pro" || attrs["platform"] != "Mac" || attrs["owner_email"] != "alice@example.com" {
		t.Fatalf("attrs = %#v, want Prism device/user attributes", attrs)
	}
	if attrs["external_id"] != "device-1/com.apple.Safari" {
		t.Fatalf("external_id = %q, want device-scoped bundle id", attrs["external_id"])
	}
	for key, want := range map[string]string{
		"resource_id":   "device-1/com.apple.Safari",
		"resource_name": "Safari",
		"resource_type": "application",
		"resource_urn":  "urn:cerebro:writer:kandji_application:device-1/com.apple.Safari",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestReadApplicationFamilyKeepsSameBundleOnDifferentDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/prism/apps" {
			t.Errorf("request path = %q, want /api/v1/prism/apps", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"device_id": "device-1", "bundle_id": "com.apple.Safari", "name": "Safari", "version": "18.0"},
				{"device_id": "device-2", "bundle_id": "com.apple.Safari", "name": "Safari", "version": "18.0"},
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
		"base_url":  server.URL + "/api/v1",
		"token":     "kandji-token",
		"family":    "application",
	})
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 2 {
		t.Fatalf("len(URNs) = %d, want both per-device app installations", len(urns))
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(Events) = %d, want both per-device app installations", len(pull.Events))
	}
	got := map[string]bool{}
	for _, event := range pull.Events {
		got[event.Attributes["external_id"]] = true
	}
	for _, want := range []string{"device-1/com.apple.Safari", "device-2/com.apple.Safari"} {
		if !got[want] {
			t.Fatalf("external IDs = %#v, missing %q", got, want)
		}
	}
}

func TestReadVulnerabilityFamily(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/vulnerability-management/detections" {
			t.Errorf("request path = %q, want /api/v1/vulnerability-management/detections", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"device_id":             "device-1",
					"device_name":           "MacBook Pro",
					"device_serial_number":  "SERIAL1",
					"name":                  "Safari",
					"version":               "18.0",
					"bundle_id":             "com.apple.Safari",
					"cve_id":                "CVE-2026-0001",
					"cve_description":       "WebKit memory safety issue",
					"cvss_score":            8.1,
					"cvss_severity":         "High",
					"first_detection_date":  "2026-05-01",
					"latest_detection_date": "2026-05-02",
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
	if attrs["severity"] != "High" || attrs["description"] != "WebKit memory safety issue" || attrs["serial_number"] != "SERIAL1" {
		t.Fatalf("attrs = %#v, want Kandji vulnerability detection attributes", attrs)
	}
	if attrs["external_id"] != "device-1/CVE-2026-0001/Safari/18.0" {
		t.Fatalf("external_id = %q, want device-scoped CVE detection id", attrs["external_id"])
	}
	for key, want := range map[string]string{
		"resource_id":   "device-1/CVE-2026-0001/Safari/18.0",
		"resource_name": "CVE-2026-0001",
		"resource_type": "vulnerability",
		"resource_urn":  "urn:cerebro:writer:kandji_vulnerability:device-1/CVE-2026-0001/Safari/18.0",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyApplication, familyDevice, familyVulnerability} {
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
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: familyApplication, kind: "kandji.application", wantResourceURN: "urn:cerebro:tenant:kandji_application:aa79459d-8566-4655-b09a-8f5c6bcf8b43/com.agilebits.onepassword7"},
		{family: familyDevice, kind: "kandji.device", wantResourceURN: "urn:cerebro:tenant:kandji_device:03f81208-2b6a-4a77-81f5-cf1633bcfb95"},
		{family: familyVulnerability, kind: "kandji.vulnerability", wantResourceURN: "urn:cerebro:tenant:kandji_vulnerability:abcd/CVE-2024-12345/Acrobat%20Reader/1.0.0"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
			if got := pull.Events[0].Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("Read(%s).resource_urn = %q, want %q", tt.family, got, tt.wantResourceURN)
			}
		})
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"service unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "writer",
		"base_url":  server.URL + "/api/v1",
		"token":     "kandji-token",
		"family":    familyApplication,
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "kandji API returned 503") {
		t.Fatalf("Read() error = %q, want 503 provider error", got)
	}
}

func TestReadVulnerabilityFamilyKeepsSameCVEOnDifferentDevices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/vulnerability-management/detections" {
			t.Errorf("request path = %q, want /api/v1/vulnerability-management/detections", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
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
	got := map[string]bool{}
	for _, event := range pull.Events {
		got[event.Attributes["external_id"]] = true
	}
	for _, want := range []string{"device-1/CVE-2026-0001/Safari/1.0.0", "device-2/CVE-2026-0001/Safari/1.0.0"} {
		if !got[want] {
			t.Fatalf("external IDs = %#v, missing %q", got, want)
		}
	}
}

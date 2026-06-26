package grc

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestReadGRCMonitoredComputerNormalizesPostureFields(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyMonitoredComputer)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(monitored_computer) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(monitored_computer).Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "grc.monitored_computer" {
		t.Fatalf("event kind = %q, want grc.monitored_computer", event.Kind)
	}
	attrs := event.Attributes
	for key, want := range map[string]string{
		"computer_id":             "computer-1",
		"device_id":               "computer-1",
		"device_uuid":             "udid-1",
		"serial_number":           "serial-1",
		"integration_id":          "kandji",
		"screenlock_status":       "OK",
		"disk_encryption_status":  "OK",
		"password_manager_status": "NEEDS_ATTENTION",
		"antivirus_status":        "OK",
		"os":                      "MACOS",
		"os_version":              "15.5",
		"owner_id":                "person-1",
		"owner_email":             "designer@example.com",
		"compliance_status":       "needs_attention",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestReadGRCMonitoredComputerLeavesComplianceUnsetWithoutPosture(t *testing.T) {
	attrs := attributesFor(settings{provider: "grc", tenantID: "writer"}, familyMonitoredComputer, grcRecord{
		ID: "serial-1",
		Values: map[string]any{
			"serialNumber": "serial-1",
		},
	})
	if got := attrs["compliance_status"]; got != "" {
		t.Fatalf("compliance_status = %q, want unset", got)
	}
}

func TestMonitoredComputerComplianceStatusPrioritizesFailures(t *testing.T) {
	if got := monitoredComputerComplianceStatus(map[string]string{
		"screenlock_status":       "NOT_APPLICABLE",
		"password_manager_status": "FAIL",
	}); got != "needs_attention" {
		t.Fatalf("monitoredComputerComplianceStatus() = %q, want needs_attention", got)
	}
	if got := monitoredComputerComplianceStatus(map[string]string{
		"screenlock_status":       "OK",
		"password_manager_status": "NOT_APPLICABLE",
	}); got != "ok" {
		t.Fatalf("monitoredComputerComplianceStatus() = %q, want ok", got)
	}
}

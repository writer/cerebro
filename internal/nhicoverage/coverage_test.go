package nhicoverage

import (
	"testing"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

func TestFromSourceCoverageBuildsNHILanesAndExcludesRemediation(t *testing.T) {
	report := sourcecoverage.Report{
		Version:     "source-coverage/v1",
		GeneratedAt: "2026-06-15T12:00:00Z",
		TenantID:    "writer",
		Records: []sourcecoverage.Record{
			{
				SourceID:                 "openai",
				TenantID:                 "writer",
				DimensionID:              "service_accounts",
				DimensionType:            "entity_family",
				Title:                    "Service accounts",
				State:                    sourcecoverage.StateHealthy,
				SupportLevel:             "supported",
				HighValue:                true,
				SupportedRuntimeFamilies: []string{"service_account"},
			},
			{
				SourceID:      "openai",
				TenantID:      "writer",
				DimensionID:   "tokens_and_keys",
				DimensionType: "entity_family",
				Title:         "API keys",
				State:         sourcecoverage.StateUnconfigured,
				SupportLevel:  "supported",
				HighValue:     true,
				BlindSpot:     true,
				Warning:       "API keys coverage is unconfigured for tenant writer",
			},
			{
				SourceID:      "gcp",
				TenantID:      "writer",
				DimensionID:   "workload_identity_pool",
				DimensionType: "relationship",
				Title:         "Workload identity pools",
				State:         sourcecoverage.StatePartial,
				SupportLevel:  "partial",
				HighValue:     true,
				BlindSpot:     true,
			},
			{
				SourceID:      "kubernetes",
				TenantID:      "writer",
				DimensionID:   "rbac_bindings",
				DimensionType: "app_entitlement",
				Title:         "RBAC bindings",
				State:         sourcecoverage.StateFailed,
				SupportLevel:  "supported",
				HighValue:     true,
				BlindSpot:     true,
			},
			{
				SourceID:                 "azure",
				TenantID:                 "writer",
				DimensionID:              "credential",
				DimensionType:            "entity_family",
				Title:                    "Azure application and service principal credentials",
				State:                    sourcecoverage.StateHealthy,
				SupportLevel:             "supported",
				HighValue:                true,
				SupportedRuntimeFamilies: []string{"credential"},
			},
			{
				SourceID:      "okta",
				TenantID:      "writer",
				DimensionID:   "users",
				DimensionType: "entity_family",
				Title:         "Users",
				State:         sourcecoverage.StateHealthy,
				SupportLevel:  "supported",
				HighValue:     true,
			},
			{
				SourceID:                 "duo",
				TenantID:                 "writer",
				DimensionID:              "mfa_devices",
				DimensionType:            "entity_family",
				Title:                    "MFA phones, hardware tokens, and WebAuthn credentials",
				State:                    sourcecoverage.StateHealthy,
				SupportLevel:             "supported",
				HighValue:                true,
				SupportedRuntimeFamilies: []string{"token", "web_authn_credential"},
			},
			{
				SourceID:      "okta",
				TenantID:      "writer",
				DimensionID:   "remediation",
				DimensionType: "remediation_state",
				Title:         "Remediation lifecycle",
				State:         sourcecoverage.StateUnsupported,
				SupportLevel:  "unsupported",
				HighValue:     true,
				BlindSpot:     true,
			},
		},
	}

	nhi := FromSourceCoverage(report)

	if nhi.Version != Version || nhi.GeneratedAt != report.GeneratedAt || nhi.TenantID != report.TenantID {
		t.Fatalf("report identity = %#v", nhi)
	}
	if nhi.Totals.Dimensions != 5 || nhi.Totals.HighValueDimensions != 5 || nhi.Totals.BlindSpots != 3 {
		t.Fatalf("totals = %#v", nhi.Totals)
	}
	if nhi.Gate.Status != "fail" || nhi.Gate.BlockingReason != "failed" {
		t.Fatalf("gate = %#v, want failed gate", nhi.Gate)
	}
	assertRecord(t, nhi.Records, "service_accounts", LaneInventory, "service_account")
	assertRecord(t, nhi.Records, "tokens_and_keys", LaneCredential, "api_key")
	assertRecord(t, nhi.Records, "workload_identity_pool", LaneTrust, "workload_identity")
	assertRecord(t, nhi.Records, "rbac_bindings", LaneEntitlement, "rbac")
	assertRecord(t, nhi.Records, "credential", LaneCredential, "service_principal")
	assertMissingRecord(t, nhi.Records, "users")
	assertMissingRecord(t, nhi.Records, "mfa_devices")
	assertMissingRecord(t, nhi.Records, "remediation")
	if len(nhi.BlindSpots) != 3 {
		t.Fatalf("blind spot count = %d, want 3: %#v", len(nhi.BlindSpots), nhi.BlindSpots)
	}
	if len(nhi.Summaries) != 5 {
		t.Fatalf("summaries = %#v, want one source/lane summary per included record", nhi.Summaries)
	}
	if len(nhi.LaneSummaries) != 4 {
		t.Fatalf("lane summaries = %#v, want four lanes", nhi.LaneSummaries)
	}
}

func TestRecordsFromCoverageClassifiesActivityAndExposure(t *testing.T) {
	records := RecordsFromCoverage([]sourcecoverage.Record{
		{
			SourceID:      "aws",
			DimensionID:   "access_key_audit_events",
			DimensionType: "audit_event",
			Title:         "Access key audit events",
			State:         sourcecoverage.StateHealthy,
		},
		{
			SourceID:      "aws",
			DimensionID:   "external_principal_trust",
			DimensionType: "relationship",
			Title:         "External principals",
			State:         sourcecoverage.StateUnconfigured,
			BlindSpot:     true,
		},
	})

	assertRecord(t, records, "access_key_audit_events", LaneActivity, "access_key")
	assertRecord(t, records, "external_principal_trust", LaneExposure, "external_principal")
}

func assertRecord(t *testing.T, records []Record, dimensionID string, lane string, subjectKind string) {
	t.Helper()
	for _, record := range records {
		if record.DimensionID != dimensionID {
			continue
		}
		if record.Lane != lane || record.SubjectKind != subjectKind {
			t.Fatalf("%s classification = lane:%q subject:%q, want lane:%q subject:%q", dimensionID, record.Lane, record.SubjectKind, lane, subjectKind)
		}
		return
	}
	t.Fatalf("missing NHI record %q in %#v", dimensionID, records)
}

func assertMissingRecord(t *testing.T, records []Record, dimensionID string) {
	t.Helper()
	for _, record := range records {
		if record.DimensionID == dimensionID {
			t.Fatalf("unexpected NHI record %q: %#v", dimensionID, record)
		}
	}
}
